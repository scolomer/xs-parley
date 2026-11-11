import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Audit } from "./audit.ts";
import { generateKemPair, generateParley, generateSignPair, signCert } from "./crypto.ts";
import { KEM_GRACE_MS, KemKeeper, PeerBook } from "./keys.ts";
import { Store } from "./store.ts";
import { FakeClock } from "./testkit.ts";

const dirs: string[] = [];
afterEach(() => {
	for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function tmpStore(): Store {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xsp-store-"));
	dirs.push(dir);
	return new Store(path.join(dir, "nested", "xs-parley"));
}

describe("Store", () => {
	test("creates 0700 directories and 0600 files atomically", () => {
		const store = tmpStore();
		const file = path.join(store.root, "parleys", `${"A".repeat(22)}.json`);
		store.writeParley({ v: 1, parley_id: "A".repeat(22), name: "x", relay: "r", members: {}, peers: {} });
		expect(fs.statSync(file).mode & 0o777).toBe(0o600);
		for (const d of [store.root, path.dirname(file)]) expect(fs.statSync(d).mode & 0o777).toBe(0o700);
		expect(fs.readdirSync(path.dirname(file)).filter(f => f.endsWith(".tmp"))).toEqual([]);
		expect(store.readParley("A".repeat(22))?.name).toBe("x");
	});

	test("rejects ids that could escape the directory", () => {
		const store = tmpStore();
		expect(() => store.parleyPath("../../etc/passwd")).toThrow();
		expect(() => store.identityPath("xs:../x")).toThrow();
		expect(() => store.auditPath("a/b")).toThrow();
	});
});

describe("Audit", () => {
	test("appends 0600 JSONL records with context, and tails them", () => {
		const store = tmpStore();
		const audit = new Audit(store, () => Date.parse("2026-01-02T03:04:05.678Z"));
		const id = "B".repeat(22);
		audit.log(id, { event: "sent", msg_id: "m1", text: "hello", session_id: "s", entry_id: "e" });
		audit.log(id, { event: "response_received", msg_id: "m2", reply_to: "m1", status: "ok", text: "world" });
		expect(fs.statSync(store.auditPath(id)).mode & 0o777).toBe(0o600);
		const lines = audit.tail(id, 10);
		expect(lines).toHaveLength(2);
		expect(lines[0]).toMatchObject({ ts: "2026-01-02T03:04:05.678Z", parley_id: id, event: "sent", text: "hello", session_id: "s" });
		expect(audit.tail(id, 1)[0]?.event).toBe("response_received");
	});

	test("rotates at the size limit and keeps 3 files", () => {
		const store = tmpStore();
		const audit = new Audit(store, Date.now, 300);
		const id = "C".repeat(22);
		for (let i = 0; i < 40; i++) audit.log(id, { event: "received", msg_id: `m${i}`, text: "x".repeat(60) });
		const file = store.auditPath(id);
		const names = fs.readdirSync(path.dirname(file)).sort();
		expect(names).toEqual([`${id}.jsonl`, `${id}.jsonl.1`, `${id}.jsonl.2`]);
		// The newest events survive, in order.
		const tail = audit.tail(id, 3);
		expect(tail.map(l => l.msg_id)).toEqual(["m37", "m38", "m39"]);
		expect(audit.tail(id, 1000).length).toBeLessThan(40);
	});
});

describe("KemKeeper", () => {
	test("rotation keeps the previous private key for 10 minutes, then wipes it", () => {
		const clock = new FakeClock();
		const keeper = new KemKeeper(() => clock.now());
		const first = keeper.privs()[0]!;
		const firstCopy = new Uint8Array(first);
		const firstPub = keeper.pub;
		keeper.rotate();
		expect(keeper.pub).not.toEqual(firstPub);
		expect(keeper.privs()).toHaveLength(2);
		expect(keeper.privs()[1]).toEqual(firstCopy);
		clock.advance(KEM_GRACE_MS - 1);
		expect(keeper.privs()).toHaveLength(2);
		clock.advance(2);
		expect(keeper.privs()).toHaveLength(1);
		expect(first.every(b => b === 0)).toBe(true);
	});

	test("rotation is due after 24 h", () => {
		const clock = new FakeClock();
		const keeper = new KemKeeper(() => clock.now());
		expect(keeper.dueForRotation()).toBe(false);
		clock.advance(24 * 3600_000);
		expect(keeper.dueForRotation()).toBe(true);
		expect(keeper.untilRotation()).toBe(0);
		keeper.rotate();
		expect(keeper.dueForRotation()).toBe(false);
	});
});

describe("PeerBook", () => {
	const { ask } = generateParley("relay.test", "infra");
	const sign = generateSignPair();
	const cert = (issuedAt: number, alias = "peer") =>
		signCert(ask, { signPub: sign.pub, kemPub: generateKemPair().pub, alias, role: "", issuedAt: new Date(issuedAt) });

	test("a certificate replaces the cached one only if strictly more recent", () => {
		let changes = 0;
		const book = new PeerBook({}, () => changes++);
		const t = Date.parse("2026-05-05T10:00:00.000Z");
		const newer = cert(t + 1000, "new");
		const older = cert(t, "old");
		expect(book.accept(older)).toBe(true);
		expect(book.accept(newer)).toBe(true);
		expect(book.accept(older)).toBe(false);
		expect(book.accept(newer)).toBe(false);
		expect(changes).toBe(2);
		const fp = Object.keys(book.snapshot())[0]!;
		expect(book.known(fp)?.body.alias).toBe("new");
	});

	test("a certificate older than 25 h is not usable to encrypt and the member shows offline", () => {
		const book = new PeerBook({}, () => {});
		const t = Date.parse("2026-05-05T10:00:00.000Z");
		book.accept(cert(t));
		const fp = Object.keys(book.snapshot())[0]!;
		book.setOnline(fp, true);
		expect(book.usable(fp, t + 24 * 3600_000)).toBeDefined();
		expect(book.views("xs:self", t + 24 * 3600_000)[0]?.online).toBe(true);
		expect(book.usable(fp, t + 25 * 3600_000 + 1)).toBeUndefined();
		expect(book.views("xs:self", t + 25 * 3600_000 + 1)[0]?.online).toBe(false);
		expect(book.known(fp)).toBeDefined();
	});
});
