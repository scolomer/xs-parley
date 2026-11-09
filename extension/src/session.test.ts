import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import { executeCommand } from "./commands.ts";
import { b64uEncode, generateKemPair, INVITE_RE, inviteSecrets, sealInviteRequest } from "./crypto.ts";
import { XshellSession, UserError } from "./session.ts";
import {
	cleanup,
	FakeClock,
	FakeHost,
	FakeNetwork,
	FakeTransport,
	makeNode,
	makeShell,
	type Node,
	settle,
	TEST_ENDPOINT,
	waitFor,
} from "./testkit.ts";

const nodes: Node[] = [];
afterEach(() => cleanup(nodes.splice(0)));

function setup(): { clock: FakeClock; net: FakeNetwork } {
	return { clock: new FakeClock(), net: new FakeNetwork() };
}

describe("xshell names", () => {
	test("create refuses a name already used locally, and says how to join it when another session holds it", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		const { membership } = await a.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "ask" });
		await expect(a.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "ask" })).rejects.toThrow(
			`déjà pris sur cette machine par la xshell ${membership.xshellId} (à laquelle cette session appartient)`,
		);
		const other = new XshellSession({ store: a.store, audit: a.audit, transport: new FakeTransport(net), clock, host: new FakeHost() });
		try {
			await expect(other.createShell({ name: "infra", relay: "relay.test", role: "", policy: "ask" })).rejects.toThrow(
				"tenue par une autre session de cette machine) : /xshell join infra pour la rejoindre",
			);
		} finally {
			other.detachAll();
		}
		expect(a.store.listShells()).toHaveLength(1);
	});

	test("join refuses a name used by another xshell_id, accepts --name to rename", async () => {
		const { clock, net } = setup();
		const creator = makeNode(net, clock, "creator");
		const other = makeNode(net, clock, "other");
		nodes.push(creator, other);
		const first = await creator.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "auto" });
		const second = await other.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "auto" });
		expect(second.membership.xshellId).not.toBe(first.membership.xshellId);

		await expect(creator.session.joinShell({ key: second.keys.answer, role: "", policy: "ask" })).rejects.toThrow(/désigne déjà une autre xshell.*--name/);
		const renamed = await creator.session.joinShell({ key: second.keys.answer, name: "infra-bis", role: "", policy: "ask" });
		expect(renamed.membership.name).toBe("infra-bis");
		expect(renamed.membership.key.rank).toBe("S");
		expect(creator.session.byName("infra")?.xshellId).toBe(first.membership.xshellId);
	});

	test("invalid names and keys are user errors", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		await expect(a.session.createShell({ name: "bad name", relay: "relay.test", role: "", policy: "ask" })).rejects.toThrow(UserError);
		await expect(a.session.createShell({ name: "ok", relay: "relay.test", alias: "bad alias", role: "", policy: "ask" })).rejects.toThrow(UserError);
		await expect(a.session.joinShell({ key: "xs2:garbage", role: "", policy: "ask" })).rejects.toThrow(UserError);
	});
});

describe("create and join are atomic", () => {
	test("a create the relay refuses leaves neither membership nor file", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		a.transport.refuseConnections = "connexion au relai impossible";
		await expect(a.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "ask" })).rejects.toThrow(/unavailable — connexion au relai impossible/);
		expect(a.session.all()).toHaveLength(0);
		expect(a.store.listShells()).toHaveLength(0);
		expect(a.session.activeToolNames()).toEqual([]);
	});

	test("a join the relay refuses leaves the other local members' file untouched", async () => {
		const { clock, net } = setup();
		const creator = makeNode(net, clock, "creator");
		nodes.push(creator);
		const created = await creator.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "ask" });
		const id = created.membership.xshellId;
		const before = creator.store.readShell(id);
		// A second omp session on the same machine (same store), whose relay connection is refused.
		const transport = new FakeTransport(net);
		transport.refuseConnections = "refusé";
		const local = new XshellSession({ store: creator.store, audit: creator.audit, transport, clock, host: new FakeHost() });
		try {
			await expect(local.joinShell({ key: created.keys.answer, name: "infra", role: "", policy: "ask" })).rejects.toThrow(UserError);
			expect(local.all()).toHaveLength(0);
			expect(creator.store.readShell(id)).toEqual(before);
		} finally {
			local.detachAll();
		}
	});
});

describe("membership state", () => {
	test("files are private and hold what §7.5 lists; the identity key lives outside the session state", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		const out = await a.session.createShell({ name: "infra", relay: "relay.test", alias: "boss", role: "rôle\nsur deux lignes", policy: "auto" });
		const id = out.membership.xshellId;
		const fp = out.membership.fp;
		const shellFile = path.join(a.root, "shells", `${id}.json`);
		const keyFile = path.join(a.root, "keys", `${fp}.key`);
		expect(fs.statSync(shellFile).mode & 0o777).toBe(0o600);
		expect(fs.statSync(keyFile).mode & 0o777).toBe(0o600);
		expect(fs.statSync(path.join(a.root, "shells")).mode & 0o777).toBe(0o700);
		const file = a.store.readShell(id)!;
		expect(file.members[fp]).toMatchObject({ key: out.keys.ask, alias: "boss", policy: "auto" });
		expect(file.members[fp]!.role).not.toContain("\n");
		expect(file.members[fp]!.cert?.body.alias).toBe("boss");
		// The session entry never holds a secret.
		const state = JSON.stringify(a.host.states.at(-1));
		expect(state).toContain(id);
		expect(state).not.toContain(out.keys.ask);
		expect(state).not.toContain(out.keys.answer);
	});

	test("--notls is kept in the xshell file: the connection, now and after a resume, is plain ws://", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		const out = await a.session.createShell({ name: "lan", relay: "relay.test:8080", notls: true, role: "", policy: "ask" });
		expect(out.membership.endpoint).toBe("ws://relay.test:8080/ws");
		expect(a.transport.isUp("ws://relay.test:8080/ws")).toBe(true);
		expect(a.store.readShell(out.membership.xshellId)?.notls).toBe(true);
		expect(out.keys.ask).toStartWith("xs2:relay.test:8080:");

		const state = a.host.states.at(-1)!;
		a.session.detachAll();
		const resumed = new XshellSession({ store: a.store, audit: a.audit, transport: new FakeTransport(net), clock, host: new FakeHost() });
		try {
			resumed.restore(state);
			expect(resumed.get(out.membership.xshellId)?.endpoint).toBe("ws://relay.test:8080/ws");
		} finally {
			resumed.detachAll();
		}
	});

	test("resume rejoins from the session state without any key exchange", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const slave = makeNode(net, clock, "slave");
		nodes.push(boss, slave);
		const { xshellId } = await makeShell({ creator: boss, slaves: [slave] });
		const bossFp = boss.session.get(xshellId)!.fp;
		const state = boss.host.states.at(-1)!;
		boss.session.detachAll();
		await settle();
		expect(net.group(xshellId).has(bossFp)).toBe(false);

		const host = new FakeHost();
		const resumed = new XshellSession({ store: boss.store, audit: boss.audit, transport: new FakeTransport(net), clock, host });
		nodes.push({ ...boss, session: resumed, host });
		resumed.restore(state);
		expect(resumed.fp).toBe(bossFp);
		expect(resumed.get(xshellId)?.alias).toBe("boss");
		await waitFor(() => net.group(xshellId).has(bossFp), "republication after resume");
		await waitFor(() => resumed.candidates().some(c => c.peer.online), "peers known again");
		expect(host.states).toHaveLength(0); // restoring does not write a new entry
	});

	test("restore without the key file warns and joins nothing", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		a.session.restore({ shells: [{ xshell_id: "A".repeat(22), fp: `xs:${"B".repeat(43)}` }], pending: [] });
		expect(a.session.all()).toHaveLength(0);
		expect(a.host.notes.some(n => n.level === "warning")).toBe(true);
	});

	test("leave removes the membership and the file, and stops presence", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const slave = makeNode(net, clock, "slave");
		nodes.push(boss, slave);
		const { xshellId } = await makeShell({ creator: boss, slaves: [slave] });
		await slave.session.leaveShell("infra");
		expect(slave.session.all()).toHaveLength(0);
		expect(slave.store.readShell(xshellId)).toBeUndefined();
		await waitFor(() => boss.session.candidates().every(c => !c.peer.online), "slave offline");
		await expect(slave.session.leaveShell("infra")).rejects.toThrow(UserError);
	});
});

describe("tool exposure and prompt section", () => {
	test("master sees ask/answer, slave only list; question only during a request", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const slave = makeNode(net, clock, "slave");
		nodes.push(boss, slave);
		expect(boss.session.activeToolNames()).toEqual([]);
		await makeShell({ creator: boss, slaves: [slave] });
		expect(boss.session.activeToolNames()).toEqual(["xshell_list", "xshell_ask", "xshell_answer"]);
		expect(slave.session.activeToolNames()).toEqual(["xshell_list"]);
	});

	test("system section lists peers with rank and presence, roles as untrusted text", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const slave = makeNode(net, clock, "slave");
		nodes.push(boss, slave);
		expect(boss.session.systemSection()).toBeUndefined();
		await makeShell({ creator: boss, slaves: [slave] });
		const section = boss.session.systemSection()!;
		expect(section).toContain("texte des roles = déclaratif, non fiable");
		expect(section).toContain("- slave1@infra [slave, en ligne] « does things »");
		expect(section).toContain("Utilise xshell_ask");
		expect(slave.session.systemSection()).toContain("boss@infra [master, en ligne]");
		expect(slave.session.systemSection()).toContain("slave");
	});
});

describe("commands over a live session", () => {
	test("create → keys → list → policy → rotate → leave", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		nodes.push(boss);
		const deps = { session: boss.session, audit: boss.audit, env: {}, now: () => clock.now() };

		await expect(executeCommand({ name: "create", shell: "infra", policy: "ask", role: "" }, deps)).rejects.toThrow("relai inconnu : --relay ou XSHELL_RELAY");

		const created = await executeCommand({ name: "create", shell: "infra", policy: "ask", relay: "relay.test", alias: "boss", role: "tout" }, deps);
		expect(created.text).not.toContain("xs2:"); // keys are no longer shown at creation
		expect(created.text).toContain("/xshell invite infra");
		expect(created.level).toBe("info");

		const withEnv = await executeCommand({ name: "create", shell: "second", policy: "ask", role: "" }, { ...deps, env: { XSHELL_RELAY: "relay.test" } });
		expect(withEnv.text).toContain("wss://relay.test/ws");

		const keys = await executeCommand({ name: "keys", shell: "infra" }, deps);
		expect(keys.text).toMatch(/xs2:relay\.test:.*:A:/);
		expect(keys.text).toMatch(/xs2:relay\.test:.*:S:/);

		expect((await executeCommand({ name: "policy", shell: "infra", policy: "auto" }, deps)).text).toContain("auto");
		expect(boss.session.byName("infra")?.policy).toBe("auto");
		expect(boss.store.readShell(boss.session.byName("infra")!.xshellId)!.members[boss.session.fp!]!.policy).toBe("auto");

		const oldKey = boss.session.keysOf(boss.session.byName("infra")!)[0]!.key;
		const rotated = await executeCommand({ name: "rotate", shell: "infra" }, deps);
		expect(rotated.text).toContain("graines régénérées");
		const newKey = boss.session.keysOf(boss.session.byName("infra")!)[0]!.key;
		expect(newKey).not.toBe(oldKey);
		expect(newKey.split(":")[2]).toBe(oldKey.split(":")[2]); // same xshell_id

		const list = await executeCommand({ name: "list" }, deps);
		expect(list.text).toContain("« infra »");
		expect(list.text).toContain("« second »");
		expect((await executeCommand({ name: "pending" }, deps)).text).toContain("Aucune demande");
		expect((await executeCommand({ name: "log", count: 5 }, deps)).text).toBeDefined();

		await executeCommand({ name: "leave", shell: "infra" }, deps);
		await expect(executeCommand({ name: "keys", shell: "infra" }, deps)).rejects.toThrow(UserError);
	});

	test("a master who joined with the ask key re-displays both keys and may rotate; a slave sees only its own and may not", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const master = makeNode(net, clock, "master");
		const slave = makeNode(net, clock, "slave");
		nodes.push(boss, master, slave);
		const { keys } = await boss.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "ask" });
		await master.session.joinShell({ key: keys.ask, role: "", policy: "ask" });
		await slave.session.joinShell({ key: keys.answer, role: "", policy: "ask" });

		const deps = (n: Node) => ({ session: n.session, audit: n.audit, env: {}, now: () => clock.now() });
		const masterKeys = (await executeCommand({ name: "keys", shell: "infra" }, deps(master))).text;
		expect(masterKeys).toContain(keys.ask);
		expect(masterKeys).toContain(keys.answer);
		const slaveKeys = (await executeCommand({ name: "keys", shell: "infra" }, deps(slave))).text;
		expect(slaveKeys).toContain(keys.answer);
		expect(slaveKeys).not.toContain(keys.ask);

		await expect(executeCommand({ name: "rotate", shell: "infra" }, deps(slave))).rejects.toThrow("seul un master");
		const rotated = await executeCommand({ name: "rotate", shell: "infra" }, deps(master));
		expect(rotated.text).toContain("graines régénérées");
		expect(master.session.keysOf(master.session.byName("infra")!)[0]!.key).not.toBe(keys.ask);
	});

	test("leave removes a xshell whose keys can no longer be read (xs1), not one held by another local session", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		const legacy = { key: "xs1:relay.test:AAAAAAAAAAAAAAAAAAAAAA:old:A:seed:pub", alias: "boss", role: "", policy: "ask" as const };
		a.store.writeShell({ v: 1, xshell_id: "A".repeat(22), name: "old", relay: "relay.test", members: { [`xs:${"B".repeat(43)}`]: legacy }, peers: {} });
		await a.session.leaveShell("old");
		expect(a.store.readShell("A".repeat(22))).toBeUndefined();

		// A readable xshell this session has not joined belongs to another local session: left alone.
		const other = makeNode(net, clock, "other");
		nodes.push(other);
		const { membership } = await other.session.createShell({ name: "live", relay: "relay.test", role: "", policy: "ask" });
		const local = new XshellSession({ store: other.store, audit: other.audit, transport: new FakeTransport(net), clock, host: new FakeHost() });
		try {
			await expect(local.leaveShell("live")).rejects.toThrow("pas membre");
			expect(other.store.readShell(membership.xshellId)).toBeDefined();
		} finally {
			local.detachAll();
		}
		await expect(a.session.leaveShell("absent")).rejects.toThrow("inconnue");
	});

	test("another session of the machine joins a local xshell by its name, with the ask key and the stored --notls", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		nodes.push(boss);
		const { membership } = await boss.session.createShell({ name: "m1", relay: "relay.test:8080", notls: true, role: "", policy: "ask" });
		const host = new FakeHost();
		const other = new XshellSession({ store: boss.store, audit: boss.audit, transport: new FakeTransport(net), clock, host });
		const deps = { session: other, audit: boss.audit, env: {}, now: () => clock.now() };
		try {
			await expect(executeCommand({ name: "invite", shell: "m1" }, deps)).rejects.toThrow("/xshell join m1");
			expect(other.localNames()).toEqual(["m1"]);
			const joined = await executeCommand({ name: "join", key: "m1", role: "", policy: "ask" }, deps);
			expect(joined.text).toContain("rejointe en master");
			const m = other.byName("m1")!;
			expect(m.xshellId).toBe(membership.xshellId);
			expect(m.fp).not.toBe(membership.fp); // its own identity
			expect(m.endpoint).toBe("ws://relay.test:8080/ws");
			expect(Object.keys(boss.store.readShell(membership.xshellId)!.members)).toHaveLength(2);
			expect((await executeCommand({ name: "invite", shell: "m1" }, deps)).text).toContain("Invitations pour « m1 »");
			await expect(executeCommand({ name: "join", key: "m1", role: "", policy: "ask" }, deps)).rejects.toThrow("déjà membre");
			await expect(executeCommand({ name: "join", key: "nope", role: "", policy: "ask" }, deps)).rejects.toThrow("ni xshell de cette machine");
		} finally {
			other.detachAll();
		}
	});

	test("without --as the alias follows the omp session name, and a rename reaches the other members; --as stays fixed", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const worker = makeNode(net, clock, "worker");
		const fixed = makeNode(net, clock, "fixed");
		nodes.push(boss, worker, fixed);
		worker.host.name = "Prod box — Édition";
		fixed.host.name = "ignored";
		const { keys, membership } = await boss.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "auto" });
		const joined = await worker.session.joinShell({ key: keys.answer, role: "", policy: "auto" });
		await fixed.session.joinShell({ key: keys.answer, alias: "pinned", role: "", policy: "auto" });
		expect(joined.membership.alias).toBe("Prod-box-Edition");
		expect(membership.alias).toBe(membership.fp.slice(3, 11)); // unnamed session: fingerprint prefix

		const bossM = boss.session.get(membership.xshellId)!;
		await waitFor(() => bossM.peers.known(joined.membership.fp)?.body.alias === "Prod-box-Edition", "initial alias seen");
		clock.advance(1);
		worker.host.name = "worker 2";
		fixed.host.name = "renamed too";
		worker.session.syncSessionName();
		fixed.session.syncSessionName();
		await waitFor(() => bossM.peers.known(joined.membership.fp)?.body.alias === "worker-2", "renamed alias seen by the master");
		expect(worker.store.readShell(membership.xshellId)!.members[joined.membership.fp]!.alias).toBe("worker-2");
		expect(fixed.session.byName("infra")!.alias).toBe("pinned");
	});

	test("a replaced membership is suspended and the user is told", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		nodes.push(boss);
		const out = await boss.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "ask" });
		boss.transport.handlers?.replaced(TEST_ENDPOINT, out.membership.xshellId);
		expect(out.membership.suspended).toBe(true);
		expect(boss.host.notes.at(-1)?.message).toContain("repris l'identité");
		expect(boss.session.activeToolNames()).not.toContain("xshell_ask");
	});

	test("destroy: a master removes the xshell for every member online; a slave cannot; the user can cancel", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const master = makeNode(net, clock, "master");
		const slave = makeNode(net, clock, "slave");
		nodes.push(boss, master, slave);
		const { xshellId } = await makeShell({ creator: boss, masters: [master], slaves: [slave] });
		const deps = (n: Node) => ({ session: n.session, audit: n.audit, env: {}, now: () => clock.now() });

		await expect(executeCommand({ name: "destroy", shell: "infra" }, deps(slave))).rejects.toThrow("seul un master");
		boss.host.confirmAnswer = false;
		await expect(executeCommand({ name: "destroy", shell: "infra" }, deps(boss))).rejects.toThrow("destruction annulée");
		expect(boss.session.byName("infra")).toBeDefined();
		expect(boss.host.confirms.at(-1)).toContain("2 membre(s) en ligne");

		boss.host.confirmAnswer = true;
		const out = await executeCommand({ name: "destroy", shell: "infra" }, deps(boss));
		expect(out.text).toContain("2 membre(s) en ligne prévenu(s)");
		expect(boss.session.all()).toHaveLength(0);
		expect(boss.store.readShell(xshellId)).toBeUndefined();
		for (const n of [master, slave]) {
			await waitFor(() => n.session.all().length === 0, `${n.label} left`);
			expect(n.store.readShell(xshellId)).toBeUndefined();
			expect(n.host.notes.some(note => note.message.includes("détruite par le master boss"))).toBe(true);
			expect(n.audit.tail(xshellId, 50).some(l => l.event === "destroyed")).toBe(true);
		}
	});
});

describe("invitations by UUID", () => {
	const FIVE_MIN = 5 * 60_000;
	const deps = (n: Node, clock: FakeClock, env: Record<string, string | undefined> = {}) => ({ session: n.session, audit: n.audit, env, now: () => clock.now() });

	/** Runs `/xshell invite infra` on `master` and returns the two UUIDs plus the text shown to the user. */
	async function invite(master: Node, clock: FakeClock): Promise<{ master: string; slave: string; text: string }> {
		const out = await executeCommand({ name: "invite", shell: "infra" }, deps(master, clock));
		const found = [...out.text.matchAll(/\/xshell join (\S+) --relay (\S+)/g)];
		expect(found).toHaveLength(2);
		return { master: found[0]![1]!, slave: found[1]![1]!, text: out.text };
	}

	function joinBy(node: Node, clock: FakeClock, uuid: string, extra: { relay?: string; shellName?: string } = {}) {
		return executeCommand({ name: "join", key: uuid, relay: "relay.test", policy: "auto", role: "invité", ...extra }, deps(node, clock));
	}

	test("a master invitation makes a master, a slave invitation a slave; /xshell list agrees on both sides", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const m2 = makeNode(net, clock, "m2");
		const s1 = makeNode(net, clock, "s1");
		nodes.push(boss, m2, s1);
		const { xshellId, keys } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		expect(inv.master).toMatch(INVITE_RE);
		expect(inv.slave).toMatch(INVITE_RE);
		expect(inv.text).toContain("usage unique, valables 5 min");
		expect(net.offers.size).toBe(2);

		const joinedMaster = await joinBy(m2, clock, inv.master);
		expect(joinedMaster.text).toContain("rejointe en master");
		const joinedSlave = await joinBy(s1, clock, inv.slave);
		expect(joinedSlave.text).toContain("rejointe en slave");
		// The master was asked twice, with the declared alias and role.
		expect(boss.host.confirms).toHaveLength(2);
		expect(boss.host.confirms[0]).toContain("en master");
		expect(boss.host.confirms[0]).toContain(`Alias déclaré : ${m2.session.get(xshellId)!.alias}`);
		expect(boss.host.confirms[0]).toContain("Rôle déclaré : invité");
		expect(boss.host.confirms[1]).toContain("en slave");
		expect(boss.host.confirms[1]).toContain(`Alias déclaré : ${s1.session.get(xshellId)!.alias}`);
		const granted = boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_granted");
		expect(granted.map(l => [l.rank, l.peer_alias])).toEqual([
			["master", m2.session.get(xshellId)!.alias],
			["slave", s1.session.get(xshellId)!.alias],
		]);
		expect(m2.session.get(xshellId)?.key.rank).toBe("A");
		expect(s1.session.get(xshellId)?.key.rank).toBe("S");
		// The keys handed out are exactly the xshell's own ask / answer keys.
		expect(m2.session.keysOf(m2.session.get(xshellId)!).map(k => k.key)).toEqual([keys.ask, keys.answer]);
		expect(s1.session.keysOf(s1.session.get(xshellId)!).map(k => k.key)).toEqual([keys.answer]);

		for (const n of [boss, m2, s1]) await n.session.refreshAll();
		await settle();
		const bossList = (await executeCommand({ name: "list" }, deps(boss, clock))).text;
		expect(bossList).toContain(`[master] en ligne ${m2.session.fp}`);
		expect(bossList).toContain(`[slave] en ligne ${s1.session.fp}`);
		const slaveList = (await executeCommand({ name: "list" }, deps(s1, clock))).text;
		expect(slaveList).toContain("« infra »");
		expect(slaveList).toContain("boss [master] en ligne");
		// Both invitations are spent; the temporary connections are gone.
		expect(net.offers.size).toBe(0);
		expect(net.claims.size).toBe(0);
	});

	test("single use: a second claim of the same UUID is refused, even when two joiners race", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		const b = makeNode(net, clock, "b");
		const c = makeNode(net, clock, "c");
		nodes.push(boss, a, b, c);
		await makeShell({ creator: boss });
		const inv = await invite(boss, clock);

		const race = await Promise.allSettled([joinBy(a, clock, inv.slave), joinBy(b, clock, inv.slave)]);
		expect(race.filter(r => r.status === "fulfilled")).toHaveLength(1);
		const loser = race.find(r => r.status === "rejected") as PromiseRejectedResult;
		expect(loser.reason).toBeInstanceOf(UserError);
		expect((loser.reason as Error).message).toBe("invitation inconnue, expirée, déjà utilisée, refusée par le master, ou master hors ligne");

		await expect(joinBy(c, clock, inv.slave)).rejects.toThrow("déjà utilisée");
		expect(c.session.all()).toHaveLength(0);
		expect(c.store.listShells()).toHaveLength(0);
		expect(c.transport.isUp(TEST_ENDPOINT)).toBe(false);
		// The other rank's invitation is untouched.
		expect(net.offers.size).toBe(1);
		await joinBy(c, clock, inv.master);
		expect(c.session.all()).toHaveLength(1);
	});

	test("invitations expire after 5 minutes on the injected clock", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		clock.advance(FIVE_MIN - 1);
		expect(net.offers.size).toBe(2);
		clock.advance(1);
		expect(net.offers.size).toBe(0);
		await expect(joinBy(a, clock, inv.master)).rejects.toThrow("expirée");
		expect(a.session.all()).toHaveLength(0);
	});

	test("an offer the relay still holds after expiry (withdraw lost) is refused by the issuer", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		// The relay keeps routing the claim, but the issuer has already forgotten the invitation.
		boss.transport.withdraw = async () => undefined;
		clock.advance(FIVE_MIN);
		expect(net.offers.size).toBe(2);
		await expect(joinBy(a, clock, inv.master)).rejects.toThrow("inconnue");
		expect(net.claims.size).toBe(0);
		expect(a.session.all()).toHaveLength(0);
	});

	test("the issuer leaving, rotating or shutting down makes its invitations unavailable", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		await makeShell({ creator: boss });

		let inv = await invite(boss, clock);
		await boss.session.leaveShell("infra");
		expect(net.offers.size).toBe(0);
		await expect(joinBy(a, clock, inv.master)).rejects.toThrow("master hors ligne");

		await makeShell({ creator: boss }, { name: "infra" });
		inv = await invite(boss, clock);
		await boss.session.rotateShell("infra");
		expect(net.offers.size).toBe(0);
		await expect(joinBy(a, clock, inv.slave)).rejects.toThrow("inconnue");

		inv = await invite(boss, clock);
		boss.session.detachAll();
		expect(net.offers.size).toBe(0);
		await expect(joinBy(a, clock, inv.slave)).rejects.toThrow("master hors ligne");
		expect(a.session.all()).toHaveLength(0);
	});

	test("after a relay reconnection the still valid invitations are offered again", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		const { xshellId } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		boss.transport.reconnect(TEST_ENDPOINT);
		await waitFor(() => net.offers.size === 2, "offers renewed");
		expect((await joinBy(a, clock, inv.master)).text).toContain("rejointe en master");
		expect(a.session.get(xshellId)?.key.rank).toBe("A");
	});

	test("a suspended issuer refuses the claim and audits it", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		const { xshellId } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		boss.transport.handlers?.replaced(TEST_ENDPOINT, xshellId);
		await expect(joinBy(a, clock, inv.master)).rejects.toThrow("inconnue");
		const refused = boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_refused");
		expect(refused).toHaveLength(1);
		expect(refused[0]).toMatchObject({ rank: "master", status: "refused", reason: "adhésion indisponible" });
	});

	test("the user refusing the claim consumes the invitation and fails the join", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		const b = makeNode(net, clock, "b");
		nodes.push(boss, a, b);
		const { xshellId } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		boss.host.confirmAnswer = false;
		await expect(joinBy(a, clock, inv.master)).rejects.toThrow("refusée par le master");
		expect(a.session.all()).toHaveLength(0);
		expect(boss.host.confirms).toHaveLength(1);
		expect(net.offers.size).toBe(1);
		const refused = boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_refused");
		expect(refused).toHaveLength(1);
		expect(refused[0]).toMatchObject({ rank: "master", status: "refused", reason: "refusée par l'utilisateur", peer_alias: expect.any(String) });
		// Spent: even an accepting user cannot be asked again.
		boss.host.confirmAnswer = true;
		await expect(joinBy(b, clock, inv.master)).rejects.toThrow("inconnue");
		expect(boss.host.confirms).toHaveLength(1);
	});

	test("without UI the claim is refused and the invitation consumed", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		const { xshellId } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		boss.host.ui = false;
		await expect(joinBy(a, clock, inv.slave)).rejects.toThrow("refusée par le master");
		expect(boss.host.confirms).toHaveLength(0);
		expect(net.offers.size).toBe(1);
		const refused = boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_refused");
		expect(refused).toHaveLength(1);
		expect(refused[0]).toMatchObject({ rank: "slave", reason: "confirmation impossible : aucune interface" });
	});

	test("a request not sealed with the UUID is refused without consuming the invitation", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		const attacker = makeNode(net, clock, "attacker");
		nodes.push(boss, a, attacker);
		const { xshellId } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		const { inviteId } = inviteSecrets(inv.master);
		// Someone who knows `invite_id` (the relay) but not the UUID: the request is sealed with a wrong key.
		attacker.transport.acquire(TEST_ENDPOINT);
		await waitFor(() => attacker.transport.isUp(TEST_ENDPOINT), "attacker connected");
		const eph = generateKemPair();
		const req = sealInviteRequest(new Uint8Array(32).fill(7), inviteId, eph.pub, { alias: "evil", role: "" });
		await expect(attacker.transport.claim(TEST_ENDPOINT, inviteId, b64uEncode(eph.pub), req)).rejects.toMatchObject({ code: "no_invite" });
		// A malformed epk is no better.
		await expect(attacker.transport.claim(TEST_ENDPOINT, inviteId, "AAAA", req)).rejects.toMatchObject({ code: "no_invite" });
		expect(boss.host.confirms).toHaveLength(0);
		expect(net.offers.size).toBe(2);
		const refused = boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_refused");
		expect(refused.map(l => l.reason)).toEqual(["demande illisible", "demande illisible"]);
		// The real invitee still gets in.
		expect((await joinBy(a, clock, inv.master)).text).toContain("rejointe en master");
	});

	test("a second claim during a confirmation is refused, the first one succeeds", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		const b = makeNode(net, clock, "b");
		nodes.push(boss, a, b);
		const { xshellId } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		const decision = Promise.withResolvers<boolean>();
		boss.host.confirmAnswer = () => decision.promise;
		const first = joinBy(a, clock, inv.slave);
		await waitFor(() => boss.host.confirms.length === 1, "dialog shown");
		await expect(joinBy(b, clock, inv.slave)).rejects.toThrow("inconnue");
		expect(b.session.all()).toHaveLength(0);
		expect(boss.host.confirms).toHaveLength(1);
		// The refused second claim neither consumed nor audited anything.
		expect(boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_refused")).toHaveLength(0);
		decision.resolve(true);
		expect((await first).text).toContain("rejointe en slave");
		expect(a.session.get(xshellId)?.key.rank).toBe("S");
	});

	test("an invitation expiring during the confirmation is refused when the user accepts", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		const { xshellId } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		const decision = Promise.withResolvers<boolean>();
		boss.host.confirmAnswer = () => decision.promise;
		const attempt = joinBy(a, clock, inv.master);
		const settled = attempt.then(() => undefined, (error: unknown) => error);
		await waitFor(() => boss.host.confirms.length === 1, "dialog shown");
		clock.advance(FIVE_MIN);
		decision.resolve(true);
		expect(await settled).toBeInstanceOf(UserError);
		expect(a.session.all()).toHaveLength(0);
		const refused = boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_refused");
		expect(refused).toHaveLength(1);
		expect(refused[0]).toMatchObject({ rank: "master", reason: "expirée" });
		expect(boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_granted")).toHaveLength(0);
	});

	test("leaving the xshell during the confirmation forgets the invitation: accepting grants nothing", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		const { xshellId } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		const decision = Promise.withResolvers<boolean>();
		boss.host.confirmAnswer = () => decision.promise;
		const settled = joinBy(a, clock, inv.master).then(() => undefined, (error: unknown) => error);
		await waitFor(() => boss.host.confirms.length === 1, "dialog shown");
		await boss.session.leaveShell("infra");
		decision.resolve(true);
		expect(await settled).toBeInstanceOf(UserError);
		expect(a.session.all()).toHaveLength(0);
		expect(boss.audit.tail(xshellId, 20).filter(l => l.event === "invite_granted")).toHaveLength(0);
	});

	test("invite is refused for a slave, an unknown xshell, a suspended or an offline membership", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const slave = makeNode(net, clock, "slave");
		nodes.push(boss, slave);
		const { xshellId } = await makeShell({ creator: boss, slaves: [slave] });
		await expect(executeCommand({ name: "invite", shell: "infra" }, deps(slave, clock))).rejects.toThrow("seul un master");
		await expect(executeCommand({ name: "invite", shell: "absente" }, deps(boss, clock))).rejects.toThrow("xshell inconnue");
		boss.transport.handlers?.replaced(TEST_ENDPOINT, xshellId);
		await expect(executeCommand({ name: "invite", shell: "infra" }, deps(boss, clock))).rejects.toThrow("suspendue");
		expect(net.offers.size).toBe(0);

		const other = makeNode(net, clock, "other");
		nodes.push(other);
		await makeShell({ creator: other }, { name: "lan" });
		other.transport.closeAll();
		await expect(executeCommand({ name: "invite", shell: "lan" }, deps(other, clock))).rejects.toThrow("non connecté");
		expect(net.offers.size).toBe(0);
	});

	test("a failing offer leaves no invitation behind", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		nodes.push(boss);
		await makeShell({ creator: boss });
		const real = boss.transport.offer.bind(boss.transport);
		let calls = 0;
		boss.transport.offer = async (endpoint, inviteId) => {
			if (++calls === 2) throw new Error("trop d'offres");
			return real(endpoint, inviteId);
		};
		await expect(executeCommand({ name: "invite", shell: "infra" }, deps(boss, clock))).rejects.toThrow("invitation impossible : trop d'offres");
		expect(net.offers.size).toBe(0);
		clock.advance(FIVE_MIN);
		expect(net.offers.size).toBe(0);
	});

	test("neither the UUIDs nor the keys reach the audit, the session state or the model", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		const { xshellId, keys } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		await joinBy(a, clock, inv.slave);
		const events = boss.audit.tail(xshellId, 50);
		expect(events.filter(l => l.event === "invite_created").map(l => l.rank)).toEqual(["master", "slave"]);
		expect(events.filter(l => l.event === "invite_granted").map(l => l.rank)).toEqual(["slave"]);
		const everything = JSON.stringify([events, boss.host.states, boss.host.injected, boss.host.notes, a.host.states, a.host.injected, a.host.notes]);
		for (const secret of [inv.master, inv.slave, keys.ask, keys.answer]) expect(everything).not.toContain(secret);
		expect(boss.session.systemSection()).not.toContain(inv.master);
	});

	test("the relay comes from --relay, else XSHELL_RELAY; --relay is for UUIDs only", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		const b = makeNode(net, clock, "b");
		nodes.push(boss, a, b);
		const { keys } = await makeShell({ creator: boss });
		const inv = await invite(boss, clock);
		const base = { name: "join" as const, key: inv.slave, policy: "auto" as const, role: "" };
		await expect(executeCommand(base, deps(a, clock))).rejects.toThrow("relai inconnu : --relay ou XSHELL_RELAY");
		expect(net.offers.size).toBe(2); // nothing was claimed
		await executeCommand(base, deps(a, clock, { XSHELL_RELAY: "relay.test" }));
		expect(a.session.all()).toHaveLength(1);
		await expect(executeCommand({ ...base, key: keys.answer, relay: "relay.test" }, deps(b, clock))).rejects.toThrow("--relay ne s'utilise qu'avec un UUID d'invitation");
		expect(b.session.all()).toHaveLength(0);
	});

	test("a failure after the claim (name already used) stays atomic and says the invitation is consumed", async () => {
		const { clock, net } = setup();
		const boss = makeNode(net, clock, "boss");
		const a = makeNode(net, clock, "a");
		nodes.push(boss, a);
		await makeShell({ creator: boss });
		await a.session.createShell({ name: "infra", relay: "relay.test", role: "", policy: "ask" });
		const inv = await invite(boss, clock);
		await expect(joinBy(a, clock, inv.slave)).rejects.toThrow(/désigne déjà une autre xshell.*invitation est consommée/);
		expect(a.session.all()).toHaveLength(1);
		await expect(joinBy(a, clock, inv.slave)).rejects.toThrow("déjà utilisée");
		// With --name the same kind of mistake is caught before the invitation is spent.
		await expect(joinBy(a, clock, inv.master, { shellName: "bad name" })).rejects.toThrow("nom invalide");
		expect(net.offers.size).toBe(1);
		await joinBy(a, clock, inv.master, { shellName: "infra-bis" });
		expect(a.session.byName("infra-bis")?.key.rank).toBe("A");
	});

	test("a relay that refuses the connection fails the join with its reason, without leaving a connection", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		a.transport.refuseConnections = "connexion au relai impossible";
		await expect(joinBy(a, clock, "3f2b8c4e-1a5d-4e7f-9b2a-6c8d0e1f2a3b")).rejects.toThrow(/unavailable — connexion au relai impossible/);
		expect(a.host.notes).toEqual([]); // the join reports it, no stray notification
		expect(a.session.all()).toHaveLength(0);
	});

	test("a relay that never answers fails the join after 10 s", async () => {
		const { clock, net } = setup();
		const a = makeNode(net, clock, "a");
		nodes.push(a);
		a.transport.acquire = () => undefined; // the connection never comes up
		const attempt = joinBy(a, clock, "3f2b8c4e-1a5d-4e7f-9b2a-6c8d0e1f2a3b").catch((e: Error) => e);
		clock.advance(10_000);
		expect(((await attempt) as Error).message).toContain("injoignable");
	});
});
