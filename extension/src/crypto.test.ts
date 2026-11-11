import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import {
	INVITE_RE,
	type Cert,
	type CryptoErrorCode,
	type Header,
	type Kind,
	type KemPair,
	type Plain,
	type ParleyKey,
	type SignPair,
	CERT_MAX_AGE_MS,
	PLAIN_MAX,
	ROLE_MAX,
	ParleyCryptoError,
	b64uDecode,
	b64uEncode,
	certFingerprint,
	fingerprint,
	formatParleyKey,
	formatTimestamp,
	generateKemPair,
	answerKey,
	generateParley,
	generateSignPair,
	groupKey,
	jcs,
	newMsgId,
	openCertBox,
	inviteSecrets,
	kemPairFromPriv,
	newInviteCode,
	openInvite,
	openInviteRequest,
	sealInvite,
	sealInviteRequest,
	sealInviteRequestWithNonce,
	sealInviteWithEphemeral,
	openEnvelope,
	parseParleyKey,
	parseTimestamp,
	plainSize,
	rankPubs,
	sanitizeRole,
	sealCertBox,
	sealCertBoxWithNonce,
	sealEnvelope,
	sealEnvelopeWithEkm,
	signCert,
	signPairFromSeed,
	truncateToFit,
	verifyCert,
} from "./crypto.ts";
import { VECTOR_FILES, VECTORS_DIR, buildAllVectors, serializeVector } from "../scripts/gen-vectors.ts";

function code(fn: () => unknown): CryptoErrorCode | "no_error" {
	try {
		fn();
	} catch (e) {
		if (e instanceof ParleyCryptoError) return e.code;
		throw e;
	}
	return "no_error";
}

async function codeAsync(fn: () => Promise<unknown>): Promise<CryptoErrorCode | "no_error"> {
	try {
		await fn();
	} catch (e) {
		if (e instanceof ParleyCryptoError) return e.code;
		throw e;
	}
	return "no_error";
}

function loadVector<T>(name: string): T {
	return JSON.parse(readFileSync(new URL(`${name}.json`, VECTORS_DIR), "utf8")) as T;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NOW = new Date("2026-11-09T12:00:00.000Z");

interface Member {
	sign: SignPair;
	kem: KemPair;
	fp: string;
	cert: Cert;
}

function makeMember(key: ParleyKey, alias: string, issuedAt: Date = NOW): Member {
	const sign = generateSignPair();
	const kem = generateKemPair();
	const cert = signCert(key, { signPub: sign.pub, kemPub: kem.pub, alias, role: "role de test", issuedAt });
	return { sign, kem, fp: fingerprint(sign.pub), cert };
}

function fixture() {
	const { ask, answer } = generateParley("relay.example.com:8443", "prod-k8s");
	const master = makeMember(ask, "master");
	const slave = makeMember(answer, "prod-box");
	return { ask, answer, master, slave };
}

function header(from: Member, to: Member, key: ParleyKey, over: Partial<Header> = {}): Header {
	return {
		v: 1,
		parley_id: key.parleyId,
		msg_id: newMsgId(),
		kind: "request",
		from: from.fp,
		to: to.fp,
		reply_to: null,
		ts: formatTimestamp(NOW),
		...over,
	};
}

type Json = { [k: string]: unknown };

/** Deep-clones `v` and sets the dotted `path` to `value` (deletes it when `value` is undefined). */
function patch<T>(v: T, path: string, value: unknown): T {
	const c = structuredClone(v);
	const keys = path.split(".");
	const last = keys.pop() as string;
	let node = c as Json;
	for (const k of keys) node = node[k] as Json;
	if (value === undefined) delete node[last];
	else node[last] = value;
	return c;
}

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

describe("encodings", () => {
	test("b64u round trip and strictness", () => {
		const bytes = new Uint8Array([0xfb, 0xff, 0x00, 0x01]);
		expect(b64uEncode(bytes)).toBe("-_8AAQ");
		expect(b64uDecode("-_8AAQ")).toEqual(bytes);
		expect(b64uDecode("-_8AAQ", 4)).toEqual(bytes);
		expect(code(() => b64uDecode("-_8AAQ", 5))).toBe("bad_encoding");
		expect(code(() => b64uDecode("-_8AAQ=="))).toBe("bad_encoding"); // padding
		expect(code(() => b64uDecode("+/8AAQ"))).toBe("bad_encoding"); // standard alphabet
		expect(code(() => b64uDecode("A"))).toBe("bad_encoding"); // impossible length
		expect(code(() => b64uDecode("QR"))).toBe("bad_encoding"); // non-zero trailing bits
		expect(code(() => b64uDecode("QQ=="))).toBe("bad_encoding");
		expect(code(() => b64uDecode("QQ\n"))).toBe("bad_encoding");
		expect(b64uDecode("")).toEqual(new Uint8Array(0));
	});

	test("timestamp profile", () => {
		expect(parseTimestamp("2026-11-09T12:00:00.000Z").toISOString()).toBe("2026-11-09T12:00:00.000Z");
		for (const bad of [
			"2026-11-09T12:00:00Z",
			"2026-11-09T12:00:00.0000Z",
			"2026-11-09t12:00:00.000z",
			"2026-11-09T12:00:00.000+00:00",
			"2026-02-30T12:00:00.000Z",
			"2026-11-09T24:00:00.000Z",
			"2026-11-09 12:00:00.000Z",
		]) {
			expect(code(() => parseTimestamp(bad))).toBe("bad_timestamp");
		}
		expect(code(() => parseTimestamp(42 as unknown as string))).toBe("bad_timestamp");
	});

	test("sanitizeRole", () => {
		expect(sanitizeRole("a\nb\tc\u0001d\u0085e\u2028f")).toBe("abcdef");
		expect(sanitizeRole("x".repeat(500))).toHaveLength(ROLE_MAX);
		const emoji = sanitizeRole("\u{1F600}".repeat(400));
		expect(Array.from(emoji)).toHaveLength(ROLE_MAX);
		expect(emoji.isWellFormed()).toBe(true);
	});

	test("jcs is RFC 8785 canonical", () => {
		expect(jcs({ b: 1, a: [true, null, "é\u0001"], c: { z: 1, y: 2 } })).toBe(
			'{"a":[true,null,"é\\u0001"],"b":1,"c":{"y":2,"z":1}}',
		);
		expect(code(() => jcs({ a: "\ud800" }))).toBe("bad_structure");
	});
});

// ---------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------

describe("vectors", () => {
	test("files match the generator output", async () => {
		const all = await buildAllVectors();
		for (const name of VECTOR_FILES) {
			expect(readFileSync(new URL(`${name}.json`, VECTORS_DIR), "utf8")).toBe(serializeVector(all[name]));
		}
	});

	test("fingerprint", () => {
		const v = loadVector<{ cases: { sign_seed: string; sign_pub: string; fp: string }[] }>("fingerprint");
		expect(v.cases.length).toBeGreaterThan(0);
		for (const c of v.cases) {
			const pair = signPairFromSeed(b64uDecode(c.sign_seed, 32));
			expect(b64uEncode(pair.pub)).toBe(c.sign_pub);
			expect(fingerprint(b64uDecode(c.sign_pub, 32))).toBe(c.fp);
			expect(c.fp).toHaveLength(46);
		}
	});

	test("parley-key", () => {
		const v = loadVector<{
			cases: { key: string; relay: string; parley_id: string; name: string; rank: string; seed: string; other: string }[];
		}>("parley-key");
		expect(v.cases.map(c => c.relay)).toContain("relay.example.com:8443");
		for (const c of v.cases) {
			const k = parseParleyKey(c.key);
			expect(k.relay).toBe(c.relay);
			expect(k.parleyId).toBe(c.parley_id);
			expect(k.name).toBe(c.name);
			expect(k.rank).toBe(c.rank as "A" | "S");
			expect(b64uEncode(k.seed)).toBe(c.seed);
			expect(b64uEncode(k.rank === "A" ? k.answerSeed : k.askPub)).toBe(c.other);
			expect(formatParleyKey(k)).toBe(c.key);
		}
	});

	test("K_grp", () => {
		const v = loadVector<{
			parley_id: string;
			pub_ask: string;
			pub_answer: string;
			key_ask: string;
			key_answer: string;
			k_grp: string;
		}>("k-grp");
		const ask = parseParleyKey(v.key_ask);
		const answer = parseParleyKey(v.key_answer);
		for (const key of [ask, answer]) {
			const pubs = rankPubs(key);
			expect(b64uEncode(pubs.pubAsk)).toBe(v.pub_ask);
			expect(b64uEncode(pubs.pubAnswer)).toBe(v.pub_answer);
			expect(b64uEncode(groupKey(key))).toBe(v.k_grp);
		}
		expect(ask.parleyId).toBe(v.parley_id);
	});

	test("cert", () => {
		const v = loadVector<{
			now: string;
			cases: { signing_key: string; parley_id: string; sign_pub: string; kem_pub: string; jcs_body: string; cert: Cert; fp: string }[];
		}>("cert");
		const now = new Date(v.now);
		for (const c of v.cases) {
			const key = parseParleyKey(c.signing_key);
			const rebuilt = signCert(key, {
				signPub: b64uDecode(c.sign_pub, 32),
				kemPub: b64uDecode(c.kem_pub, 32),
				alias: c.cert.body.alias,
				role: c.cert.body.role,
				issuedAt: new Date(c.cert.body.issued_at),
			});
			expect(rebuilt).toEqual(c.cert);
			expect(jcs(c.cert.body)).toBe(c.jcs_body);
			expect(certFingerprint(c.cert)).toBe(c.fp);
			expect(verifyCert(structuredClone(c.cert), key, c.parley_id, c.fp, now)).toEqual(c.cert);
		}
	});

	test("cert_box", () => {
		const v = loadVector<{ parley_id: string; k_grp: string; nonce: string; cert: Cert; fp: string; cert_box: string }>("cert-box");
		const kGrp = b64uDecode(v.k_grp, 32);
		expect(sealCertBoxWithNonce(kGrp, v.parley_id, v.cert, b64uDecode(v.nonce, 24))).toBe(v.cert_box);
		expect(openCertBox(kGrp, v.parley_id, v.cert_box)).toEqual(v.cert);
		expect(b64uDecode(v.cert_box).length).toBe(24 + 16 + new TextEncoder().encode(jcs(v.cert)).length);
	});

	test("envelope", async () => {
		const v = loadVector<{
			now: string;
			parley_id: string;
			verifier_key: string;
			sender_sign_seed: string;
			recipient_kem_priv: string;
			recipient_kem_pub: string;
			hpke_ephemeral_ikm: string;
			h: Header;
			jcs_h: string;
			plain: Plain;
			jcs_plain: string;
			envelope: { h: Header; enc: string; ct: string; sig: string };
		}>("envelope");
		expect(jcs(v.h)).toBe(v.jcs_h);
		expect(jcs(v.plain)).toBe(v.jcs_plain);
		const rebuilt = await sealEnvelopeWithEkm(
			v.h,
			v.plain,
			b64uDecode(v.recipient_kem_pub, 32),
			b64uDecode(v.sender_sign_seed, 32),
			b64uDecode(v.hpke_ephemeral_ikm, 32),
		);
		expect(rebuilt).toEqual(v.envelope);
		const opened = await openEnvelope(structuredClone(v.envelope), {
			frameParleyId: v.parley_id,
			selfFp: v.h.to,
			key: parseParleyKey(v.verifier_key),
			kemPrivs: [b64uDecode(v.recipient_kem_priv, 32)],
			now: new Date(v.now),
		});
		expect(opened.h).toEqual(v.h);
		expect(opened.plain).toEqual(v.plain);
		expect(opened.cert).toEqual(v.plain.cert);
	});

	test("invite", () => {
		const v = loadVector<{
			uuid: string;
			invite_id: string;
			k_inv: string;
			claimant_ephemeral_priv: string;
			claimant_ephemeral_pub: string;
			hello: { alias: string; role: string };
			jcs_hello: string;
			request_nonce: string;
			req: string;
			master_ephemeral_priv: string;
			master_ephemeral_pub: string;
			shared: string;
			k_box: string;
			parley_key: string;
			box_nonce: string;
			box: string;
		}>("invite");
		const secrets = inviteSecrets(v.uuid);
		expect(secrets.inviteId).toBe(v.invite_id);
		expect(b64uEncode(secrets.key)).toBe(v.k_inv);
		const eJ = kemPairFromPriv(b64uDecode(v.claimant_ephemeral_priv, 32));
		const eM = kemPairFromPriv(b64uDecode(v.master_ephemeral_priv, 32));
		expect(b64uEncode(eJ.pub)).toBe(v.claimant_ephemeral_pub);
		expect(b64uEncode(eM.pub)).toBe(v.master_ephemeral_pub);
		// Both sides reach the same shared secret and box key.
		expect(b64uEncode(x25519.getSharedSecret(eM.priv, eJ.pub))).toBe(v.shared);
		expect(b64uEncode(x25519.getSharedSecret(eJ.priv, eM.pub))).toBe(v.shared);
		const kBox = hkdf(
			sha256,
			concatBytes(secrets.key, b64uDecode(v.shared, 32)),
			new Uint8Array(0),
			concatBytes(new TextEncoder().encode("xs-parley invite box v2"), new TextEncoder().encode(v.invite_id), eJ.pub, eM.pub),
			32,
		);
		expect(b64uEncode(kBox)).toBe(v.k_box);

		expect(jcs({ v: 1, ...v.hello })).toBe(v.jcs_hello);
		expect(sealInviteRequestWithNonce(secrets.key, v.invite_id, eJ.pub, v.hello, b64uDecode(v.request_nonce, 24))).toBe(v.req);
		expect(openInviteRequest(secrets.key, v.invite_id, eJ.pub, v.req)).toEqual(v.hello);

		expect(sealInviteWithEphemeral(secrets.key, v.invite_id, eJ.pub, v.parley_key, eM.priv, b64uDecode(v.box_nonce, 24))).toBe(v.box);
		expect(openInvite(secrets.key, v.invite_id, eJ.priv, v.box)).toBe(v.parley_key);
		expect(b64uDecode(v.box).length).toBe(32 + 24 + 16 + new TextEncoder().encode(jcs({ v: 1, key: v.parley_key })).length);
		// Without e_j.priv, K_inv alone does not open the recorded box.
		const raw = b64uDecode(v.box);
		expect(() => xchacha20poly1305(secrets.key, raw.subarray(32, 56), new TextEncoder().encode(v.invite_id)).decrypt(raw.subarray(56))).toThrow();
	});
});

// ---------------------------------------------------------------------------
// Parley keys
// ---------------------------------------------------------------------------

describe("parley keys", () => {
	test("generate, format, parse round trip (relay with port)", () => {
		const { ask, answer } = generateParley("relay.example.com:8443", "prod-k8s");
		for (const key of [ask, answer]) {
			const text = formatParleyKey(key);
			expect(text.startsWith("xs2:relay.example.com:8443:")).toBe(true);
			expect(parseParleyKey(text)).toEqual(key);
			expect(parseParleyKey(`  ${text}\n`)).toEqual(key);
		}
		expect(ask.parleyId).toBe(answer.parleyId);
		expect(ask.parleyId).toHaveLength(22);
		expect(ask.rank).toBe("A");
		expect(answer.rank).toBe("S");
		// Each key verifies both ranks.
		expect(rankPubs(ask)).toEqual(rankPubs(answer));
		expect(groupKey(ask)).toEqual(groupKey(answer));
	});

	test("a master key yields the answer key; an answer key yields nothing more", () => {
		const { ask, answer } = generateParley("relay.example.com", "prod-k8s");
		const reparsed = parseParleyKey(formatParleyKey(ask));
		if (reparsed.rank !== "A") throw new Error("ask key parsed with rank S");
		expect(formatParleyKey(answerKey(reparsed))).toBe(formatParleyKey(answer));
		// The answer key carries the ask public key, never the ask seed.
		expect(formatParleyKey(answer)).not.toContain(b64uEncode(ask.seed));
	});

	test("relay without port and with IPv6 literal", () => {
		const { ask } = generateParley("localhost", "x");
		expect(parseParleyKey(formatParleyKey(ask)).relay).toBe("localhost");
		const v6 = { ...ask, relay: "[::1]:8080" };
		expect(parseParleyKey(formatParleyKey(v6)).relay).toBe("[::1]:8080");
	});

	test("rejects malformed keys", () => {
		const { ask } = generateParley("relay.example.com:8443", "prod-k8s");
		const good = formatParleyKey(ask);
		const parts = good.split(":");
		const withTail = (i: number, value: string) => {
			const p = [...parts];
			p[p.length - 5 + i] = value;
			return p.join(":");
		};
		const cases = [
			"",
			"garbage",
			good.replace(/^xs2/, "xs3"),
			good.replace(/^xs2/, "xs1"), // obsolete format
			good.slice(0, good.lastIndexOf(":")), // missing field
			`${good}:extra`, // shifts every field: invalid rank
			withTail(0, "short"), // parley_id length
			withTail(1, "bad name"), // name
			withTail(1, ""),
			withTail(2, "X"), // rank
			withTail(3, b64uEncode(new Uint8Array(31))), // seed length
			withTail(4, b64uEncode(new Uint8Array(33))), // pub length
			withTail(3, `${parts[parts.length - 2]!.slice(0, -1)}=`), // bad alphabet
			`xs2::${parts.slice(2).join(":")}`, // empty relay
			good.replace("relay.example.com:8443", "relay example"),
			good.replace("8443", "port"),
		];
		for (const bad of cases) expect(code(() => parseParleyKey(bad))).toBe("bad_key");
		expect(code(() => generateParley("bad relay", "n"))).toBe("bad_key");
		expect(code(() => generateParley("relay.example.com", "bad:name"))).toBe("bad_key");
	});
});

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

describe("verifyCert", () => {
	test("accepts a valid cert of each rank", () => {
		const f = fixture();
		for (const m of [f.master, f.slave]) {
			const out = verifyCert(structuredClone(m.cert), f.ask, f.ask.parleyId, m.fp, NOW);
			expect(out).toEqual(m.cert);
			// Same result with the other rank's key (each key verifies both ranks).
			expect(verifyCert(structuredClone(m.cert), f.answer, f.ask.parleyId, m.fp, NOW)).toEqual(m.cert);
		}
	});

	test("rejects a cert signed with the wrong rank seed", () => {
		const f = fixture();
		const sign = generateSignPair();
		const kem = generateKemPair();
		// Claims rank S but is signed by the ask seed.
		const forged = signCert({ ...f.answer, seed: f.ask.seed }, {
			signPub: sign.pub,
			kemPub: kem.pub,
			alias: "evil",
			role: "r",
			issuedAt: NOW,
		});
		expect(forged.body.rank).toBe("S");
		expect(code(() => verifyCert(forged, f.ask, f.ask.parleyId, fingerprint(sign.pub), NOW))).toBe("bad_signature");
		// Claims rank A but signed by the answer seed.
		const forged2 = signCert({ ...f.ask, seed: f.answer.seed }, {
			signPub: sign.pub,
			kemPub: kem.pub,
			alias: "evil",
			role: "r",
			issuedAt: NOW,
		});
		expect(code(() => verifyCert(forged2, f.ask, f.ask.parleyId, fingerprint(sign.pub), NOW))).toBe("bad_signature");
		// Cert from an unrelated parley, same parley_id claimed.
		const other = generateParley("relay.example.com", "other");
		const alien = signCert({ ...other.ask, parleyId: f.ask.parleyId }, {
			signPub: sign.pub,
			kemPub: kem.pub,
			alias: "alien",
			role: "r",
			issuedAt: NOW,
		});
		expect(code(() => verifyCert(alien, f.ask, f.ask.parleyId, fingerprint(sign.pub), NOW))).toBe("bad_signature");
	});

	test("rejects a rank altered after signing", () => {
		const f = fixture();
		const swapped = patch(f.slave.cert, "body.rank", "A");
		expect(code(() => verifyCert(swapped, f.ask, f.ask.parleyId, f.slave.fp, NOW))).toBe("bad_signature");
	});

	test("rejects computed fingerprint ≠ announced", () => {
		const f = fixture();
		expect(code(() => verifyCert(f.master.cert, f.ask, f.ask.parleyId, f.slave.fp, NOW))).toBe("fp_mismatch");
	});

	test("rejects another parley_id", () => {
		const f = fixture();
		const other = generateParley("relay.example.com", "other");
		expect(code(() => verifyCert(f.master.cert, f.ask, other.ask.parleyId, f.master.fp, NOW))).toBe("wrong_parley");
	});

	test("freshness window: 25 h in the past, 5 min in the future", () => {
		const f = fixture();
		const at = (offsetMs: number) => makeMember(f.ask, "m", new Date(NOW.getTime() + offsetMs));
		for (const [offset, expected] of [
			[-CERT_MAX_AGE_MS, "no_error"],
			[-CERT_MAX_AGE_MS - 1, "stale_cert"],
			[-26 * 3600_000, "stale_cert"],
			[5 * 60_000, "no_error"],
			[5 * 60_000 + 1, "stale_cert"],
			[10 * 60_000, "stale_cert"],
		] as const) {
			const m = at(offset);
			expect(code(() => verifyCert(m.cert, f.ask, f.ask.parleyId, m.fp, NOW))).toBe(expected);
		}
	});

	test("rejects extra, missing or mistyped fields", () => {
		const f = fixture();
		const check = (c: unknown, expected: CryptoErrorCode) =>
			expect(code(() => verifyCert(c, f.ask, f.ask.parleyId, f.master.fp, NOW))).toBe(expected);
		check(patch(f.master.cert, "extra", 1), "bad_structure");
		check(patch(f.master.cert, "body.extra", 1), "bad_structure");
		check(patch(f.master.cert, "body.role", undefined), "bad_structure");
		check(patch(f.master.cert, "sig", undefined), "bad_structure");
		check(patch(f.master.cert, "body.v", 2), "bad_structure");
		check(patch(f.master.cert, "body.v", "1"), "bad_structure");
		check(patch(f.master.cert, "body.rank", "M"), "bad_structure");
		check(patch(f.master.cert, "body.alias", "bad alias"), "bad_structure");
		check(patch(f.master.cert, "body.role", "two\nlines"), "bad_structure");
		check(patch(f.master.cert, "body.role", "x".repeat(ROLE_MAX + 1)), "bad_structure");
		check(patch(f.master.cert, "body.sign_pub", 1), "bad_structure");
		check(patch(f.master.cert, "body.issued_at", "2026-11-09T12:00:00Z"), "bad_timestamp");
		check(patch(f.master.cert, "body.kem_pub", f.master.cert.body.kem_pub.slice(1)), "bad_encoding");
		check(patch(f.master.cert, "sig", `${f.master.cert.sig}AA`), "bad_encoding");
		check(null, "bad_structure");
		check([], "bad_structure");
		check("cert", "bad_structure");
	});

	test("rejects a non-canonical signature (S ≥ L)", () => {
		const f = fixture();
		const L = 2n ** 252n + 27742317777372353535851937790883648493n;
		const sig = b64uDecode(f.master.cert.sig, 64);
		let s = 0n;
		for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sig[32 + i]!);
		const malleated = new Uint8Array(sig);
		let t = s + L;
		for (let i = 0; i < 32; i++) {
			malleated[32 + i] = Number(t & 0xffn);
			t >>= 8n;
		}
		expect(t).toBe(0n); // S + L still fits in 256 bits
		const cert = { body: f.master.cert.body, sig: b64uEncode(malleated) };
		// Plain (non-strict) noble verification would accept it; ours must not.
		const msg = new TextEncoder().encode(jcs(cert.body));
		expect(ed25519.verify(sig, msg, rankPubs(f.ask).pubAsk, { zip215: false })).toBe(true);
		expect(code(() => verifyCert(cert, f.ask, f.ask.parleyId, f.master.fp, NOW))).toBe("bad_signature");
	});

	test("role is sanitized at signing", () => {
		const f = fixture();
		const sign = generateSignPair();
		const cert = signCert(f.ask, {
			signPub: sign.pub,
			kemPub: generateKemPair().pub,
			alias: "a",
			role: "accès\nprod\u0001 ".padEnd(400, "é"),
			issuedAt: NOW,
		});
		expect(Array.from(cert.body.role)).toHaveLength(ROLE_MAX);
		expect(cert.body.role.startsWith("accèsprod")).toBe(true);
		expect(verifyCert(cert, f.ask, f.ask.parleyId, fingerprint(sign.pub), NOW)).toEqual(cert);
	});
});

describe("cert_box", () => {
	test("round trip and validation", () => {
		const f = fixture();
		const kGrp = groupKey(f.ask);
		const box = sealCertBox(kGrp, f.ask.parleyId, f.master.cert);
		expect(box).not.toBe(sealCertBox(kGrp, f.ask.parleyId, f.master.cert)); // random nonce
		const opened = openCertBox(kGrp, f.ask.parleyId, box);
		expect(verifyCert(opened, f.answer, f.ask.parleyId, f.master.fp, NOW)).toEqual(f.master.cert);
	});

	test("rejects undecryptable boxes", () => {
		const f = fixture();
		const other = generateParley("relay.example.com", "other");
		const kGrp = groupKey(f.ask);
		const box = sealCertBox(kGrp, f.ask.parleyId, f.master.cert);
		expect(code(() => openCertBox(groupKey(other.ask), f.ask.parleyId, box))).toBe("decrypt_failed"); // wrong K_grp
		expect(code(() => openCertBox(kGrp, other.ask.parleyId, box))).toBe("decrypt_failed"); // wrong aad
		const raw = b64uDecode(box);
		raw[raw.length - 1] = raw[raw.length - 1]! ^ 1;
		expect(code(() => openCertBox(kGrp, f.ask.parleyId, b64uEncode(raw)))).toBe("decrypt_failed");
		raw[raw.length - 1] = raw[raw.length - 1]! ^ 1;
		raw[3] = raw[3]! ^ 1; // nonce
		expect(code(() => openCertBox(kGrp, f.ask.parleyId, b64uEncode(raw)))).toBe("decrypt_failed");
		expect(code(() => openCertBox(kGrp, f.ask.parleyId, b64uEncode(new Uint8Array(39))))).toBe("bad_encoding");
		expect(code(() => openCertBox(kGrp, f.ask.parleyId, "not base64!"))).toBe("bad_encoding");
		expect(code(() => openCertBox(kGrp, f.ask.parleyId, `${box}=`))).toBe("bad_encoding");
	});
});

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

describe("envelopes", () => {
	async function sealed(over: Partial<Header> = {}, plain?: Plain) {
		const f = fixture();
		const h = header(f.master, f.slave, f.ask, over);
		const env = await sealEnvelope(h, plain ?? { cert: f.master.cert, text: "ls -la" }, f.slave.kem.pub, f.master.sign.seed);
		const open = (input: unknown, o: Partial<Parameters<typeof openEnvelope>[1]> = {}) =>
			openEnvelope(input, {
				frameParleyId: f.ask.parleyId,
				selfFp: f.slave.fp,
				key: f.answer,
				kemPrivs: [f.slave.kem.priv],
				now: NOW,
				...o,
			});
		return { f, h, env, open };
	}

	test("round trip", async () => {
		const { f, h, env, open } = await sealed();
		const out = await open(JSON.parse(JSON.stringify(env)));
		expect(out.h).toEqual(h);
		expect(out.plain).toEqual({ cert: f.master.cert, text: "ls -la" });
		expect(out.cert).toEqual(f.master.cert);
		expect(env.enc).toHaveLength(43);
	});

	test("accepted/response carry status and reason", async () => {
		const f = fixture();
		const base = (kind: Kind) => header(f.slave, f.master, f.ask, { kind, reply_to: newMsgId() });
		const open = (env: unknown) =>
			openEnvelope(env, {
				frameParleyId: f.ask.parleyId,
				selfFp: f.master.fp,
				key: f.ask,
				kemPrivs: [f.master.kem.priv],
				now: NOW,
			});
		for (const kind of ["accepted", "response"] as const) {
			const plain: Plain = { cert: f.slave.cert, text: "done", status: "refused", reason: "non" };
			const env = await sealEnvelope(base(kind), plain, f.master.kem.pub, f.slave.sign.seed);
			expect((await open(env)).plain).toEqual(plain);
		}
		for (const kind of ["request", "question", "answer"] as const) {
			const plain: Plain = { cert: f.slave.cert, text: "x", status: "ok" };
			const env = await sealEnvelope(base(kind), plain, f.master.kem.pub, f.slave.sign.seed);
			expect(await codeAsync(() => open(env))).toBe("bad_structure");
		}
		const badStatus = await sealEnvelope(
			base("response"),
			{ cert: f.slave.cert, text: "x", status: "weird" as never },
			f.master.kem.pub,
			f.slave.sign.seed,
		);
		expect(await codeAsync(() => open(badStatus))).toBe("bad_structure");
	});

	test("rejects wrong recipient or wrong parley_id", async () => {
		const { f, env, open } = await sealed();
		expect(await codeAsync(() => open(env, { selfFp: f.master.fp }))).toBe("bad_address");
		expect(await codeAsync(() => open(env, { frameParleyId: generateParley("r", "n").ask.parleyId }))).toBe("bad_address");
		// h.to ≠ self at sealing time
		const wrongTo = await sealed({ to: makeMember(f.ask, "z").fp });
		expect(await codeAsync(() => wrongTo.open(wrongTo.env))).toBe("bad_address");
		// h.parley_id differs from the frame (and from the joined parley)
		const other = generateParley("relay.example.com", "other");
		const wrongParley = await sealed({ parley_id: other.ask.parleyId });
		expect(await codeAsync(() => wrongParley.open(wrongParley.env))).toBe("bad_address");
		// key of another parley
		expect(await codeAsync(() => open(env, { key: other.answer }))).toBe("bad_address");
	});

	test("rejects structural deviations", async () => {
		const { env, open } = await sealed();
		const check = async (input: unknown, expected: CryptoErrorCode) => expect(await codeAsync(() => open(input))).toBe(expected);
		await check(patch(env, "extra", 1), "bad_structure");
		await check(patch(env, "h.extra", 1), "bad_structure");
		await check(patch(env, "h.reply_to", undefined), "bad_structure");
		await check(patch(env, "sig", undefined), "bad_structure");
		await check(patch(env, "h.kind", "ping"), "bad_structure");
		await check(patch(env, "h.v", 2), "bad_structure");
		await check(patch(env, "h.msg_id", "not-a-uuid"), "bad_structure");
		await check(null, "bad_structure");
		await check({ h: null }, "bad_structure");
		await check(patch(env, "enc", env.enc.slice(1)), "bad_encoding");
		await check(patch(env, "enc", b64uEncode(new Uint8Array(33))), "bad_encoding");
		await check(patch(env, "ct", "!!"), "bad_encoding");
	});

	test("rejects tampering (AEAD binds h, signature binds enc/ct)", async () => {
		const { f, env, open } = await sealed();
		// Changing the header breaks the HPKE AAD.
		const other = patch(env, "h.msg_id", newMsgId());
		expect(await codeAsync(() => open(other))).toBe("decrypt_failed");
		const ct = b64uDecode(env.ct);
		ct[0] = ct[0]! ^ 1;
		expect(await codeAsync(() => open({ ...env, ct: b64uEncode(ct) }))).toBe("decrypt_failed");
		// Re-sealed under a different signer: signature does not match the certificate.
		const forged = await sealEnvelope(env.h, { cert: f.master.cert, text: "x" }, f.slave.kem.pub, generateSignPair().seed);
		expect(await codeAsync(() => open(forged))).toBe("bad_signature");
		// Signature with a flipped bit.
		const sig = b64uDecode(env.sig);
		sig[10] = sig[10]! ^ 1;
		expect(await codeAsync(() => open({ ...env, sig: b64uEncode(sig) }))).toBe("bad_signature");
	});

	test("rejects a header whose from does not match the certificate", async () => {
		const f = fixture();
		const impostor = makeMember(f.ask, "impostor");
		// Header claims the impostor's fp but the plain carries the master's cert.
		const h = header(impostor, f.slave, f.ask);
		const env = await sealEnvelope(h, { cert: f.master.cert, text: "x" }, f.slave.kem.pub, f.master.sign.seed);
		const out = openEnvelope(env, {
			frameParleyId: f.ask.parleyId,
			selfFp: f.slave.fp,
			key: f.answer,
			kemPrivs: [f.slave.kem.priv],
			now: NOW,
		});
		expect(await codeAsync(() => out)).toBe("fp_mismatch");
	});

	test("rejects a stale or foreign embedded cert", async () => {
		const f = fixture();
		const old = makeMember(f.ask, "old", new Date(NOW.getTime() - CERT_MAX_AGE_MS - 1000));
		const env = await sealEnvelope(header(old, f.slave, f.ask), { cert: old.cert, text: "x" }, f.slave.kem.pub, old.sign.seed);
		expect(
			await codeAsync(() =>
				openEnvelope(env, { frameParleyId: f.ask.parleyId, selfFp: f.slave.fp, key: f.answer, kemPrivs: [f.slave.kem.priv], now: NOW }),
			),
		).toBe("stale_cert");
	});

	test("decrypts with the previous key, fails with unrelated keys", async () => {
		const { f, env, open } = await sealed();
		const fresh = generateKemPair();
		expect((await open(env, { kemPrivs: [fresh.priv, f.slave.kem.priv] })).plain.text).toBe("ls -la");
		expect(await codeAsync(() => open(env, { kemPrivs: [fresh.priv] }))).toBe("decrypt_failed");
		expect(await codeAsync(() => open(env, { kemPrivs: [] }))).toBe("decrypt_failed");
	});

	test("timestamp window of 5 minutes", async () => {
		for (const [offset, expected] of [
			[0, "no_error"],
			[-5 * 60_000, "no_error"],
			[5 * 60_000, "no_error"],
			[-5 * 60_000 - 1, "bad_timestamp"],
			[5 * 60_000 + 1, "bad_timestamp"],
			[-3600_000, "bad_timestamp"],
		] as const) {
			const f = fixture();
			const m = makeMember(f.ask, "m", NOW);
			const h = header(m, f.slave, f.ask, { ts: formatTimestamp(new Date(NOW.getTime() + offset)) });
			const env = await sealEnvelope(h, { cert: m.cert, text: "x" }, f.slave.kem.pub, m.sign.seed);
			expect(
				await codeAsync(() =>
					openEnvelope(env, { frameParleyId: f.ask.parleyId, selfFp: f.slave.fp, key: f.answer, kemPrivs: [f.slave.kem.priv], now: NOW }),
				),
			).toBe(expected);
		}
		// Non-conforming profile.
		const f = fixture();
		const m = makeMember(f.ask, "m", NOW);
		const h = header(m, f.slave, f.ask, { ts: "2026-11-09T12:00:00Z" });
		const env = await sealEnvelope(h, { cert: m.cert, text: "x" }, f.slave.kem.pub, m.sign.seed);
		expect(
			await codeAsync(() =>
				openEnvelope(env, { frameParleyId: f.ask.parleyId, selfFp: f.slave.fp, key: f.answer, kemPrivs: [f.slave.kem.priv], now: NOW }),
			),
		).toBe("bad_timestamp");
	});

	test("each message uses a fresh ephemeral key", async () => {
		const { f, h } = await sealed();
		const plain: Plain = { cert: f.master.cert, text: "same" };
		const a = await sealEnvelope(h, plain, f.slave.kem.pub, f.master.sign.seed);
		const b = await sealEnvelope(h, plain, f.slave.kem.pub, f.master.sign.seed);
		expect(a.enc).not.toBe(b.enc);
		expect(a.ct).not.toBe(b.ct);
	});
});

// ---------------------------------------------------------------------------
// msg_id, truncation
// ---------------------------------------------------------------------------

describe("newMsgId", () => {
	test("UUIDv7 layout", () => {
		const before = Date.now();
		const id = newMsgId();
		const after = Date.now();
		expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
		const ms = Number.parseInt(id.replace(/-/g, "").slice(0, 12), 16);
		expect(ms).toBeGreaterThanOrEqual(before);
		expect(ms).toBeLessThanOrEqual(after);
		expect(new Set(Array.from({ length: 200 }, newMsgId)).size).toBe(200);
	});
});

describe("truncateToFit", () => {
	const SUFFIX = "[tronqué]";
	const samples: Record<string, string> = {
		quotes: '"'.repeat(80_000),
		newlines: "ligne\n".repeat(30_000),
		control: "\u0001".repeat(60_000),
		emoji: "\u{1F600}".repeat(60_000),
		backslash: "\\".repeat(80_000),
		mixed: 'a"b\n\u0001\u{1F680}é\\'.repeat(15_000),
		ascii: "x".repeat(100_000),
		bmp: "é€".repeat(40_000),
	};

	for (const [name, text] of Object.entries(samples)) {
		test(`fits PLAIN_MAX and a 64 KiB deliver frame: ${name}`, async () => {
			const f = fixture();
			const plain = truncateToFit({ cert: f.slave.cert, text, status: "ok" });
			expect(plainSize(plain)).toBeLessThanOrEqual(PLAIN_MAX);
			expect(plainSize({ ...plain, text: "" })).toBeLessThan(PLAIN_MAX);
			expect(plain.text.endsWith(SUFFIX)).toBe(true);
			expect(plain.text.isWellFormed()).toBe(true);
			expect(plain.text.length).toBeLessThan(text.length);
			// As tight as possible: one more code point (at most 12 bytes escaped) would not fit.
			expect(PLAIN_MAX - plainSize(plain)).toBeLessThan(12);
			expect(plain.status).toBe("ok");
			expect(plain.cert).toEqual(f.slave.cert);

			const h = header(f.slave, f.master, f.ask, { kind: "response", reply_to: newMsgId() });
			const env = await sealEnvelope(h, plain, f.master.kem.pub, f.slave.sign.seed);
			const frame = JSON.stringify({ v: 1, t: "deliver", parley_id: f.ask.parleyId, env });
			expect(new TextEncoder().encode(frame).length).toBeLessThanOrEqual(65536);
			const out = await openEnvelope(JSON.parse(frame).env, {
				frameParleyId: f.ask.parleyId,
				selfFp: f.master.fp,
				key: f.ask,
				kemPrivs: [f.master.kem.priv],
				now: NOW,
			});
			expect(out.plain.text).toBe(plain.text);
		});
	}

	test("a text that already fits is returned untouched", () => {
		const f = fixture();
		const plain: Plain = { cert: f.master.cert, text: "court" };
		expect(truncateToFit(plain)).toBe(plain);
	});

	test("never splits a surrogate pair, keeps the longest prefix", () => {
		const f = fixture();
		const text = "\u{1F600}".repeat(30_000);
		const plain = truncateToFit({ cert: f.master.cert, text });
		const body = plain.text.slice(0, -"\n[tronqué]".length);
		expect(Array.from(body).every(c => c === "\u{1F600}")).toBe(true);
		const longer = { ...plain, text: `${body}\u{1F600}\n[tronqué]` };
		expect(plainSize(longer)).toBeGreaterThan(PLAIN_MAX);
	});
});

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

describe("invitations", () => {
	test("newInviteCode is a lowercase UUID v4 accepted by INVITE_RE", () => {
		const a = newInviteCode();
		expect(a).toMatch(INVITE_RE);
		expect(a).toBe(a.toLowerCase());
		expect(newInviteCode()).not.toBe(a);
	});

	test("INVITE_RE rejects other shapes (non-v4, wrong variant, parley keys)", () => {
		expect(INVITE_RE.test("3f2b8c4e-1a5d-4e7f-9b2a-6c8d0e1f2a3b")).toBe(true);
		expect(INVITE_RE.test("3F2B8C4E-1A5D-4E7F-9B2A-6C8D0E1F2A3B")).toBe(true);
		expect(INVITE_RE.test("3f2b8c4e-1a5d-1e7f-9b2a-6c8d0e1f2a3b")).toBe(false);
		expect(INVITE_RE.test("3f2b8c4e-1a5d-4e7f-cb2a-6c8d0e1f2a3b")).toBe(false);
		expect(INVITE_RE.test("xs2:relay:id:name:A:s:s")).toBe(false);
		expect(INVITE_RE.test(" 3f2b8c4e-1a5d-4e7f-9b2a-6c8d0e1f2a3b")).toBe(false);
	});

	test("inviteSecrets is deterministic, case-insensitive, and separates id from key", () => {
		const uuid = newInviteCode();
		const a = inviteSecrets(uuid);
		const b = inviteSecrets(uuid.toUpperCase());
		expect(b64uEncode(a.key)).toBe(b64uEncode(b.key));
		expect(a.inviteId).toBe(b.inviteId);
		expect(a.inviteId).toHaveLength(22);
		expect(inviteSecrets(newInviteCode()).inviteId).not.toBe(a.inviteId);
		expect(code(() => inviteSecrets("not-a-uuid"))).toBe("bad_key");
	});

	const derivation = (kInv: Uint8Array, inviteId: string, ePriv: Uint8Array, peerPub: Uint8Array, epkJ: Uint8Array, epkM: Uint8Array) =>
		hkdf(
			sha256,
			concatBytes(kInv, x25519.getSharedSecret(ePriv, peerPub)),
			new Uint8Array(0),
			concatBytes(new TextEncoder().encode("xs-parley invite box v2"), new TextEncoder().encode(inviteId), epkJ, epkM),
			32,
		);

	test("a box opens only with the claimant's ephemeral key, the right UUID secrets and invite_id", () => {
		const mine = inviteSecrets(newInviteCode());
		const other = inviteSecrets(newInviteCode());
		const eJ = generateKemPair();
		const parleyKey = formatParleyKey(generateParley("relay.test", "infra").answer);
		const box = sealInvite(mine.key, mine.inviteId, eJ.pub, parleyKey);
		expect(openInvite(mine.key, mine.inviteId, eJ.priv, box)).toBe(parleyKey);
		expect(b64uDecode(box).length).toBe(32 + 24 + 16 + new TextEncoder().encode(jcs({ v: 1, key: parleyKey })).length);
		expect(code(() => openInvite(other.key, mine.inviteId, eJ.priv, box))).toBe("decrypt_failed");
		expect(code(() => openInvite(mine.key, other.inviteId, eJ.priv, box))).toBe("decrypt_failed");
		expect(code(() => openInvite(mine.key, mine.inviteId, generateKemPair().priv, box))).toBe("decrypt_failed");
		expect(code(() => openInvite(mine.key, mine.inviteId, eJ.priv, "***"))).toBe("bad_encoding");
		expect(code(() => openInvite(mine.key, mine.inviteId, eJ.priv, b64uEncode(new Uint8Array(70))))).toBe("bad_encoding");
		// Each box carries a fresh master ephemeral key.
		expect(sealInvite(mine.key, mine.inviteId, eJ.pub, parleyKey).slice(0, 43)).not.toBe(box.slice(0, 43));
	});

	test("forward secrecy: the UUID alone (K_inv, invite_id) cannot open a recorded box", () => {
		const secrets = inviteSecrets(newInviteCode());
		const eJ = generateKemPair();
		const box = sealInvite(secrets.key, secrets.inviteId, eJ.pub, "xs2:secret");
		const raw = b64uDecode(box);
		// Someone who learned the UUID later and used K_inv directly (as in invitations v1) gets nothing.
		const aad = new TextEncoder().encode(secrets.inviteId);
		expect(() => xchacha20poly1305(secrets.key, raw.subarray(32, 56), aad).decrypt(raw.subarray(56))).toThrow();
		// Any other claimant key does not work either; only e_j.priv does.
		expect(code(() => openInvite(secrets.key, secrets.inviteId, generateKemPair().priv, box))).toBe("decrypt_failed");
		expect(openInvite(secrets.key, secrets.inviteId, eJ.priv, box)).toBe("xs2:secret");
	});

	test("openInvite does not alter the caller's private key and refuses a low-order master key", () => {
		const secrets = inviteSecrets(newInviteCode());
		const eJ = generateKemPair();
		const priv = new Uint8Array(eJ.priv);
		const box = sealInvite(secrets.key, secrets.inviteId, eJ.pub, "xs2:k");
		openInvite(secrets.key, secrets.inviteId, eJ.priv, box);
		expect(eJ.priv).toEqual(priv);
		const lowOrder = concatBytes(new Uint8Array(32), b64uDecode(box).subarray(32));
		expect(code(() => openInvite(secrets.key, secrets.inviteId, eJ.priv, b64uEncode(lowOrder)))).toBe("bad_key");
		expect(code(() => sealInvite(secrets.key, secrets.inviteId, new Uint8Array(32), "xs2:k"))).toBe("bad_key");
		expect(code(() => sealInvite(secrets.key, secrets.inviteId, new Uint8Array(31), "xs2:k"))).toBe("bad_key");
	});

	test("box failures on authentic ciphertexts with a wrong structure are bad_structure", () => {
		const secrets = inviteSecrets(newInviteCode());
		const eJ = generateKemPair();
		const eM = generateKemPair();
		const kBox = derivation(secrets.key, secrets.inviteId, eM.priv, eJ.pub, eJ.pub, eM.pub);
		const nonce = new Uint8Array(24);
		const aad = new TextEncoder().encode(secrets.inviteId);
		for (const body of [{ v: 2, key: "k" }, { v: 1 }, { v: 1, key: "k", extra: 1 }, { v: 1, key: 3 }]) {
			const ct = xchacha20poly1305(kBox, nonce, aad).encrypt(new TextEncoder().encode(jcs(body)));
			expect(code(() => openInvite(secrets.key, secrets.inviteId, eJ.priv, b64uEncode(concatBytes(eM.pub, nonce, ct))))).toBe("bad_structure");
		}
	});

	test("a request opens only with the right UUID secrets, invite_id and epk_j; the hello is validated", () => {
		const mine = inviteSecrets(newInviteCode());
		const other = inviteSecrets(newInviteCode());
		const eJ = generateKemPair();
		const hello = { alias: "prod-box", role: "accès prod \u{1F680}" };
		const req = sealInviteRequest(mine.key, mine.inviteId, eJ.pub, hello);
		expect(openInviteRequest(mine.key, mine.inviteId, eJ.pub, req)).toEqual(hello);
		expect(code(() => openInviteRequest(other.key, mine.inviteId, eJ.pub, req))).toBe("decrypt_failed");
		expect(code(() => openInviteRequest(mine.key, other.inviteId, eJ.pub, req))).toBe("decrypt_failed");
		// epk_j is bound by the AAD: swapping the ephemeral key is detected.
		expect(code(() => openInviteRequest(mine.key, mine.inviteId, generateKemPair().pub, req))).toBe("decrypt_failed");
		expect(code(() => openInviteRequest(mine.key, mine.inviteId, eJ.pub, "***"))).toBe("bad_encoding");
		expect(code(() => openInviteRequest(mine.key, mine.inviteId, eJ.pub, b64uEncode(new Uint8Array(10))))).toBe("bad_encoding");

		const nonce = new Uint8Array(24);
		const aad = concatBytes(new TextEncoder().encode(mine.inviteId), eJ.pub);
		const bodies: unknown[] = [
			{ v: 2, alias: "a", role: "" },
			{ v: 1, alias: "a" },
			{ v: 1, alias: "a", role: "", extra: 1 },
			{ v: 1, alias: "bad alias", role: "" },
			{ v: 1, alias: "", role: "" },
			{ v: 1, alias: 3, role: "" },
			{ v: 1, alias: "a", role: 3 },
			{ v: 1, alias: "a", role: "line\nbreak" },
			{ v: 1, alias: "a", role: "x".repeat(ROLE_MAX + 1) },
		];
		for (const body of bodies) {
			const ct = xchacha20poly1305(mine.key, nonce, aad).encrypt(new TextEncoder().encode(jcs(body)));
			expect(code(() => openInviteRequest(mine.key, mine.inviteId, eJ.pub, b64uEncode(concatBytes(nonce, ct))))).toBe("bad_structure");
		}
		// The limits themselves are accepted.
		const edge = { alias: "a".repeat(32), role: "x".repeat(ROLE_MAX) };
		expect(openInviteRequest(mine.key, mine.inviteId, eJ.pub, sealInviteRequest(mine.key, mine.inviteId, eJ.pub, edge))).toEqual(edge);
	});
});
