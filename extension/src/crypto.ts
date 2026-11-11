/**
 * xs-parley cryptography (SPEC §3–§5): encodings, parley keys, member certificates,
 * cert boxes and end-to-end envelopes. Pure functions, no I/O, no global state.
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import canonicalize from "canonicalize";

export type Rank = "A" | "S";
export type CryptoErrorCode =
	| "bad_key"
	| "bad_encoding"
	| "bad_structure"
	| "stale_cert"
	| "wrong_parley"
	| "bad_signature"
	| "fp_mismatch"
	| "decrypt_failed"
	| "bad_timestamp"
	| "bad_address";

export class ParleyCryptoError extends Error {
	constructor(
		readonly code: CryptoErrorCode,
		message?: string,
	) {
		super(message ?? code);
		this.name = "ParleyCryptoError";
	}
}

const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder("utf-8", { fatal: true });

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

export function b64uEncode(bytes: Uint8Array): string {
	return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
}

const B64U_RE = /^[A-Za-z0-9_-]*$/;

/** Strict base64url (no padding, canonical trailing bits). */
export function b64uDecode(s: string, expectedLength?: number): Uint8Array {
	if (typeof s !== "string" || !B64U_RE.test(s) || s.length % 4 === 1) {
		throw new ParleyCryptoError("bad_encoding", "base64url invalide");
	}
	const out = new Uint8Array(Buffer.from(s, "base64url"));
	if (b64uEncode(out) !== s) {
		throw new ParleyCryptoError("bad_encoding", "base64url non canonique");
	}
	if (expectedLength !== undefined && out.length !== expectedLength) {
		throw new ParleyCryptoError("bad_encoding", `longueur attendue ${expectedLength} octets, reçu ${out.length}`);
	}
	return out;
}

/** RFC 8785 canonical JSON. */
export function jcs(value: unknown): string {
	let out: string | undefined;
	try {
		out = canonicalize(value);
	} catch (e) {
		throw new ParleyCryptoError("bad_structure", `JSON non canonicalisable : ${(e as Error).message}`);
	}
	if (out === undefined) throw new ParleyCryptoError("bad_structure", "valeur non sérialisable");
	return out;
}

export const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function formatTimestamp(d: Date): string {
	return d.toISOString();
}

export function parseTimestamp(s: string): Date {
	if (typeof s !== "string" || !TIMESTAMP_RE.test(s)) {
		throw new ParleyCryptoError("bad_timestamp", "horodatage non conforme au profil");
	}
	const d = new Date(s);
	// Rejects calendar overflows such as 2026-02-30 (Date normalizes them).
	if (Number.isNaN(d.getTime()) || d.toISOString() !== s) {
		throw new ParleyCryptoError("bad_timestamp", "horodatage invalide");
	}
	return d;
}

export const NAME_RE = /^[A-Za-z0-9_-]{1,32}$/;
export const ROLE_MAX = 280;

const CONTROL_RE = /[\p{Cc}\u2028\u2029]/gu;
const HAS_CONTROL_RE = /[\p{Cc}\u2028\u2029]/u;

export function sanitizeRole(role: string): string {
	const clean = role.toWellFormed().replace(CONTROL_RE, "").trim();
	const cps = Array.from(clean);
	return cps.length > ROLE_MAX ? cps.slice(0, ROLE_MAX).join("") : clean;
}

function isRoleValid(role: string): boolean {
	return role.isWellFormed() && !HAS_CONTROL_RE.test(role) && Array.from(role).length <= ROLE_MAX;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
	if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
	const proto = Object.getPrototypeOf(v);
	return proto === Object.prototype || proto === null;
}

function hasExactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
	const own = Object.keys(o);
	return own.length === keys.length && keys.every(k => Object.hasOwn(o, k));
}

function toArrayBuffer(u: Uint8Array): ArrayBuffer {
	return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

function copy(u: Uint8Array): Uint8Array {
	return new Uint8Array(u);
}

function requireLength(u: Uint8Array, n: number, what: string): void {
	if (!(u instanceof Uint8Array) || u.length !== n) {
		throw new ParleyCryptoError("bad_key", `${what} : ${n} octets attendus`);
	}
}

// ---------------------------------------------------------------------------
// Identity (§3)
// ---------------------------------------------------------------------------

export function fingerprint(signPub: Uint8Array): string {
	requireLength(signPub, 32, "clé publique Ed25519");
	return `xs:${b64uEncode(sha256(signPub))}`;
}

export interface SignPair {
	seed: Uint8Array;
	pub: Uint8Array;
}

export function signPairFromSeed(seed: Uint8Array): SignPair {
	requireLength(seed, 32, "graine Ed25519");
	return { seed: copy(seed), pub: ed25519.getPublicKey(seed) };
}

export function generateSignPair(): SignPair {
	return signPairFromSeed(ed25519.utils.randomSecretKey());
}

export interface KemPair {
	priv: Uint8Array;
	pub: Uint8Array;
}

export function kemPairFromPriv(priv: Uint8Array): KemPair {
	requireLength(priv, 32, "clé privée X25519");
	return { priv: copy(priv), pub: x25519.getPublicKey(priv) };
}

export function generateKemPair(): KemPair {
	return kemPairFromPriv(x25519.utils.randomSecretKey());
}

function signBytes(seed: Uint8Array, message: Uint8Array): Uint8Array {
	return ed25519.sign(message, seed);
}

/** Strict RFC 8032 verification (S < L, canonical encodings). Never throws. */
function verifyBytes(sig: Uint8Array, message: Uint8Array, pub: Uint8Array): boolean {
	try {
		return ed25519.verify(sig, message, pub, { zip215: false });
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Parley keys (§4.1)
// ---------------------------------------------------------------------------

interface ParleyKeyBase {
	relay: string;
	parleyId: string;
	name: string;
}

/**
 * A master (ask) key holds both rank seeds, so every master can derive the answer key (`answerKey`); a slave
 * (answer) key holds its seed and the ask public key only.
 */
export type ParleyKey =
	| (ParleyKeyBase & { rank: "A"; seed: Uint8Array; answerSeed: Uint8Array })
	| (ParleyKeyBase & { rank: "S"; seed: Uint8Array; askPub: Uint8Array });
export type AskKey = Extract<ParleyKey, { rank: "A" }>;
export type AnswerKey = Extract<ParleyKey, { rank: "S" }>;

const RELAY_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;
const KEY_VERSION = "xs2";

function badKey(message: string): never {
	throw new ParleyCryptoError("bad_key", message);
}

/** `xs2:<relay>:<parley_id>:<name>:A:<seed_ask>:<seed_answer>` or `xs2:<relay>:<parley_id>:<name>:S:<seed_answer>:<pub_ask>`. */
export function parseParleyKey(text: string): ParleyKey {
	if (typeof text !== "string") badKey("clé de parley invalide");
	const s = text.trim();
	if (s.startsWith("xs1:")) badKey("clé de parley d'un format obsolète (xs1) : le créateur doit recréer la parley");
	if (!s.startsWith(`${KEY_VERSION}:`)) badKey(`clé de parley invalide : préfixe ${KEY_VERSION}: attendu`);
	const parts = s.slice(KEY_VERSION.length + 1).split(":");
	if (parts.length < 6) badKey("clé de parley invalide : champs manquants");
	const tail = parts.splice(parts.length - 5, 5);
	const relay = parts.join(":");
	const [parleyId, name, rank, seedS, otherS] = tail as [string, string, string, string, string];
	if (!RELAY_RE.test(relay)) badKey("clé de parley invalide : relai");
	if (!NAME_RE.test(name)) badKey("clé de parley invalide : nom");
	if (rank !== "A" && rank !== "S") badKey("clé de parley invalide : rang");
	let seed: Uint8Array;
	let other: Uint8Array;
	try {
		b64uDecode(parleyId, 16);
		seed = b64uDecode(seedS, 32);
		other = b64uDecode(otherS, 32);
	} catch {
		return badKey("clé de parley invalide : encodage");
	}
	if (rank === "A") return { relay, parleyId, name, rank, seed, answerSeed: other };
	if (!ed25519.utils.isValidPublicKey(other, false)) badKey("clé de parley invalide : clé publique");
	return { relay, parleyId, name, rank, seed, askPub: other };
}

export function formatParleyKey(key: ParleyKey): string {
	return [
		KEY_VERSION,
		key.relay,
		key.parleyId,
		key.name,
		key.rank,
		b64uEncode(key.seed),
		b64uEncode(key.rank === "A" ? key.answerSeed : key.askPub),
	].join(":");
}

/** The answer (slave) key of the parley, derived from a master key. */
export function answerKey(ask: AskKey): AnswerKey {
	return {
		relay: ask.relay,
		parleyId: ask.parleyId,
		name: ask.name,
		rank: "S",
		seed: copy(ask.answerSeed),
		askPub: ed25519.getPublicKey(ask.seed),
	};
}

export function newParleyId(): string {
	return b64uEncode(randomBytes(16));
}

export function generateParley(relay: string, name: string): { ask: AskKey; answer: AnswerKey } {
	if (!RELAY_RE.test(relay)) badKey("relai invalide");
	if (!NAME_RE.test(name)) badKey("nom invalide");
	const ask = { relay, parleyId: newParleyId(), name, rank: "A" as const, seed: generateSignPair().seed, answerSeed: generateSignPair().seed };
	return { ask, answer: answerKey(ask) };
}

export function rankPubs(key: ParleyKey): { pubAsk: Uint8Array; pubAnswer: Uint8Array } {
	requireLength(key.seed, 32, "graine Ed25519");
	const own = ed25519.getPublicKey(key.seed);
	if (key.rank === "A") {
		requireLength(key.answerSeed, 32, "graine Ed25519");
		return { pubAsk: own, pubAnswer: ed25519.getPublicKey(key.answerSeed) };
	}
	requireLength(key.askPub, 32, "clé publique Ed25519");
	return { pubAsk: copy(key.askPub), pubAnswer: own };
}

/** K_grp = HKDF-SHA256(pub_ask ‖ pub_answer, salt = empty, info = "xs-parley cert v1" ‖ parley_id, 32). */
export function groupKey(key: ParleyKey): Uint8Array {
	const { pubAsk, pubAnswer } = rankPubs(key);
	const info = concatBytes(utf8.encode("xs-parley cert v1"), utf8.encode(key.parleyId));
	return hkdf(sha256, concatBytes(pubAsk, pubAnswer), new Uint8Array(0), info, 32);
}

// ---------------------------------------------------------------------------
// Certificates (§4.2)
// ---------------------------------------------------------------------------

export interface CertBody {
	v: 1;
	parley_id: string;
	rank: Rank;
	sign_pub: string;
	kem_pub: string;
	alias: string;
	role: string;
	issued_at: string;
}
export interface Cert {
	body: CertBody;
	sig: string;
}

export const CERT_MAX_AGE_MS = 25 * 3600_000;
const CERT_MAX_FUTURE_MS = 5 * 60_000;
const CERT_BODY_KEYS = ["v", "parley_id", "rank", "sign_pub", "kem_pub", "alias", "role", "issued_at"] as const;

export function signCert(
	key: ParleyKey,
	fields: { signPub: Uint8Array; kemPub: Uint8Array; alias: string; role: string; issuedAt: Date },
): Cert {
	requireLength(fields.signPub, 32, "clé publique de signature");
	requireLength(fields.kemPub, 32, "clé publique X25519");
	if (!NAME_RE.test(fields.alias)) {
		throw new ParleyCryptoError("bad_structure", "alias invalide");
	}
	const body: CertBody = {
		v: 1,
		parley_id: key.parleyId,
		rank: key.rank,
		sign_pub: b64uEncode(fields.signPub),
		kem_pub: b64uEncode(fields.kemPub),
		alias: fields.alias,
		role: sanitizeRole(fields.role),
		issued_at: formatTimestamp(fields.issuedAt),
	};
	return { body, sig: b64uEncode(signBytes(key.seed, utf8.encode(jcs(body)))) };
}

export function certFingerprint(cert: Cert): string {
	return fingerprint(b64uDecode(cert.body.sign_pub, 32));
}

function fail(code: CryptoErrorCode, message: string): never {
	throw new ParleyCryptoError(code, message);
}

/** §4.2 validation, steps 1 to 6 in order; the first failure aborts. Returns a normalized copy. */
export function verifyCert(input: unknown, key: ParleyKey, parleyId: string, fpAnnounced: string, now: Date): Cert {
	// 1. Structure.
	if (!isObject(input) || !hasExactKeys(input, ["body", "sig"])) fail("bad_structure", "certificat : structure");
	const { body, sig } = input;
	if (!isObject(body) || !hasExactKeys(body, CERT_BODY_KEYS)) fail("bad_structure", "certificat : corps");
	if (body.v !== 1) fail("bad_structure", "certificat : version");
	if (body.rank !== "A" && body.rank !== "S") fail("bad_structure", "certificat : rang");
	for (const k of ["parley_id", "sign_pub", "kem_pub", "alias", "role", "issued_at"] as const) {
		if (typeof body[k] !== "string") fail("bad_structure", `certificat : ${k}`);
	}
	if (typeof sig !== "string") fail("bad_structure", "certificat : sig");
	const b = body as unknown as CertBody;

	// 2. Encodings.
	b64uDecode(b.sign_pub, 32);
	b64uDecode(b.kem_pub, 32);
	const sigBytes = b64uDecode(sig, 64);
	if (!NAME_RE.test(b.alias)) fail("bad_structure", "certificat : alias");
	if (!isRoleValid(b.role)) fail("bad_structure", "certificat : role");
	const issuedAt = parseTimestamp(b.issued_at);

	// 3. Freshness.
	const nowMs = now.getTime();
	const issuedMs = issuedAt.getTime();
	if (issuedMs < nowMs - CERT_MAX_AGE_MS || issuedMs > nowMs + CERT_MAX_FUTURE_MS) {
		fail("stale_cert", "certificat hors fenêtre de fraîcheur");
	}

	// 4. parley binding (the local key belongs to exactly one parley).
	if (b.parley_id !== parleyId || key.parleyId !== parleyId) fail("wrong_parley", "certificat d'une autre parley");

	// 5. Signature by the rank key derived from the local key.
	const pubs = rankPubs(key);
	const rankPub = b.rank === "A" ? pubs.pubAsk : pubs.pubAnswer;
	const normalized: CertBody = {
		v: 1,
		parley_id: b.parley_id,
		rank: b.rank,
		sign_pub: b.sign_pub,
		kem_pub: b.kem_pub,
		alias: b.alias,
		role: b.role,
		issued_at: b.issued_at,
	};
	if (!verifyBytes(sigBytes, utf8.encode(jcs(normalized)), rankPub)) {
		fail("bad_signature", "signature du certificat invalide");
	}

	// 6. Fingerprint computed from sign_pub must match the announced one.
	const cert: Cert = { body: normalized, sig };
	if (certFingerprint(cert) !== fpAnnounced) fail("fp_mismatch", "empreinte du certificat ≠ empreinte annoncée");
	return cert;
}

const NONCE_LEN = 24;
const TAG_LEN = 16;

/** Test-vector entry point: caller supplies the 24-byte nonce. */
export function sealCertBoxWithNonce(kGrp: Uint8Array, parleyId: string, cert: Cert, nonce: Uint8Array): string {
	requireLength(kGrp, 32, "K_grp");
	requireLength(nonce, NONCE_LEN, "nonce");
	const clear = utf8.encode(jcs({ body: cert.body, sig: cert.sig }));
	const ct = xchacha20poly1305(kGrp, nonce, utf8.encode(parleyId)).encrypt(clear);
	return b64uEncode(concatBytes(nonce, ct));
}

export function sealCertBox(kGrp: Uint8Array, parleyId: string, cert: Cert): string {
	return sealCertBoxWithNonce(kGrp, parleyId, cert, randomBytes(NONCE_LEN));
}

/** Decrypts and JSON-parses a cert_box; the result MUST then be validated with `verifyCert`. */
export function openCertBox(kGrp: Uint8Array, parleyId: string, box: string): unknown {
	requireLength(kGrp, 32, "K_grp");
	const raw = b64uDecode(box);
	if (raw.length < NONCE_LEN + TAG_LEN) fail("bad_encoding", "cert_box trop court");
	let clear: Uint8Array;
	try {
		clear = xchacha20poly1305(kGrp, raw.subarray(0, NONCE_LEN), utf8.encode(parleyId)).decrypt(
			raw.subarray(NONCE_LEN),
		);
	} catch {
		return fail("decrypt_failed", "cert_box indéchiffrable");
	}
	try {
		return JSON.parse(utf8Strict.decode(clear));
	} catch {
		return fail("bad_encoding", "cert_box : JSON invalide");
	}
}

// ---------------------------------------------------------------------------
// Invitations (UUID v4 handed out by a master, claimed through the blind relay)
// ---------------------------------------------------------------------------

export const INVITE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const INVITE_ID_INFO = utf8.encode("xs-parley invite id v1");
const INVITE_KEY_INFO = utf8.encode("xs-parley invite key v1");

/** A fresh invitation code: UUID v4, lowercase. */
export function newInviteCode(): string {
	return crypto.randomUUID();
}

/**
 * `invite_id` (what the relay sees, to route the claim) and `key` (seals the xs2 key) are both derived from the
 * 16 UUID bytes with HKDF-SHA256 (salt = empty): neither reveals the other nor the UUID.
 */
export function inviteSecrets(code: string): { inviteId: string; key: Uint8Array } {
	if (typeof code !== "string" || !INVITE_RE.test(code)) fail("bad_key", "UUID d'invitation invalide");
	const ikm = new Uint8Array(Buffer.from(code.replaceAll("-", ""), "hex"));
	const empty = new Uint8Array(0);
	return {
		inviteId: b64uEncode(hkdf(sha256, ikm, empty, INVITE_ID_INFO, 16)),
		key: hkdf(sha256, ikm, empty, INVITE_KEY_INFO, 32),
	};
}

const INVITE_BOX_INFO = utf8.encode("xs-parley invite box v2");

/** `aad_req = UTF-8(invite_id) ‖ epk_j` (raw 32 bytes). */
function inviteRequestAad(inviteId: string, epkJ: Uint8Array): Uint8Array {
	requireLength(epkJ, 32, "clé publique éphémère");
	return concatBytes(utf8.encode(inviteId), epkJ);
}

/** Test-vector entry point: caller supplies the 24-byte nonce. */
export function sealInviteRequestWithNonce(
	kInv: Uint8Array,
	inviteId: string,
	epkJ: Uint8Array,
	hello: { alias: string; role: string },
	nonce: Uint8Array,
): string {
	requireLength(kInv, 32, "clé d'invitation");
	requireLength(nonce, NONCE_LEN, "nonce");
	const clear = utf8.encode(jcs({ v: 1, alias: hello.alias, role: hello.role }));
	const ct = xchacha20poly1305(kInv, nonce, inviteRequestAad(inviteId, epkJ)).encrypt(clear);
	return b64uEncode(concatBytes(nonce, ct));
}

/**
 * The claimant's request: `req = b64u(nonce(24) ‖ XChaCha20-Poly1305(K_inv, nonce, JCS({v: 1, alias, role}),
 * aad = UTF-8(invite_id) ‖ epk_j))`. Only a holder of the UUID can produce it.
 */
export function sealInviteRequest(
	kInv: Uint8Array,
	inviteId: string,
	epkJ: Uint8Array,
	hello: { alias: string; role: string },
): string {
	return sealInviteRequestWithNonce(kInv, inviteId, epkJ, hello, randomBytes(NONCE_LEN));
}

/** Decrypts and validates a claim request; the declared alias and role are unverified claims. */
export function openInviteRequest(
	kInv: Uint8Array,
	inviteId: string,
	epkJ: Uint8Array,
	req: string,
): { alias: string; role: string } {
	requireLength(kInv, 32, "clé d'invitation");
	const aad = inviteRequestAad(inviteId, epkJ);
	const raw = b64uDecode(req);
	if (raw.length < NONCE_LEN + TAG_LEN) fail("bad_encoding", "demande d'invitation trop courte");
	let clear: Uint8Array;
	try {
		clear = xchacha20poly1305(kInv, raw.subarray(0, NONCE_LEN), aad).decrypt(raw.subarray(NONCE_LEN));
	} catch {
		return fail("decrypt_failed", "demande d'invitation indéchiffrable");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(utf8Strict.decode(clear));
	} catch {
		return fail("bad_encoding", "demande d'invitation : JSON invalide");
	}
	if (
		!isObject(parsed) ||
		!hasExactKeys(parsed, ["v", "alias", "role"]) ||
		parsed.v !== 1 ||
		typeof parsed.alias !== "string" ||
		!NAME_RE.test(parsed.alias) ||
		typeof parsed.role !== "string" ||
		!isRoleValid(parsed.role)
	) {
		return fail("bad_structure", "demande d'invitation : structure invalide");
	}
	return { alias: parsed.alias, role: parsed.role };
}

/**
 * `K_box = HKDF-SHA256(ikm = K_inv ‖ X25519(e_priv, peer_pub), salt = empty,
 * info = "xs-parley invite box v2" ‖ UTF-8(invite_id) ‖ epk_j ‖ epk_m, 32)`. Fails `bad_key` on a low-order point.
 */
function inviteBoxKey(
	kInv: Uint8Array,
	inviteId: string,
	ePriv: Uint8Array,
	peerPub: Uint8Array,
	epkJ: Uint8Array,
	epkM: Uint8Array,
): Uint8Array {
	let shared: Uint8Array;
	try {
		shared = x25519.getSharedSecret(ePriv, peerPub);
	} catch {
		return badKey("clé publique éphémère invalide");
	}
	if (shared.every(b => b === 0)) badKey("clé publique éphémère invalide");
	const info = concatBytes(INVITE_BOX_INFO, utf8.encode(inviteId), epkJ, epkM);
	const key = hkdf(sha256, concatBytes(kInv, shared), new Uint8Array(0), info, 32);
	shared.fill(0);
	return key;
}

/** Test-vector entry point: caller supplies the master's ephemeral private key and the 24-byte nonce. */
export function sealInviteWithEphemeral(
	kInv: Uint8Array,
	inviteId: string,
	epkJ: Uint8Array,
	parleyKey: string,
	ePrivM: Uint8Array,
	nonce: Uint8Array,
): string {
	requireLength(kInv, 32, "clé d'invitation");
	requireLength(epkJ, 32, "clé publique éphémère");
	requireLength(nonce, NONCE_LEN, "nonce");
	const eM = kemPairFromPriv(ePrivM);
	const kBox = inviteBoxKey(kInv, inviteId, eM.priv, epkJ, epkJ, eM.pub);
	const clear = utf8.encode(jcs({ v: 1, key: parleyKey }));
	const ct = xchacha20poly1305(kBox, nonce, utf8.encode(inviteId)).encrypt(clear);
	kBox.fill(0);
	eM.priv.fill(0);
	return b64uEncode(concatBytes(eM.pub, nonce, ct));
}

/**
 * The master's answer: `box = b64u(epk_m(32) ‖ nonce(24) ‖ XChaCha20-Poly1305(K_box, nonce,
 * JCS({v: 1, key: parleyKey}), aad = UTF-8(invite_id)))`, with a fresh ephemeral `e_m`. `K_box` depends on the
 * X25519 secret shared with `epk_j`: knowing the UUID later does not open a recorded box.
 */
export function sealInvite(kInv: Uint8Array, inviteId: string, epkJ: Uint8Array, parleyKey: string): string {
	return sealInviteWithEphemeral(kInv, inviteId, epkJ, parleyKey, x25519.utils.randomSecretKey(), randomBytes(NONCE_LEN));
}

/** Decrypts an invitation box with the claimant's ephemeral private key; returns the xs2 key it carries (the caller validates it with `parseParleyKey`). */
export function openInvite(kInv: Uint8Array, inviteId: string, ePrivJ: Uint8Array, box: string): string {
	requireLength(kInv, 32, "clé d'invitation");
	const eJ = kemPairFromPriv(ePrivJ);
	const raw = b64uDecode(box);
	if (raw.length < 32 + NONCE_LEN + TAG_LEN) fail("bad_encoding", "invitation trop courte");
	const epkM = raw.subarray(0, 32);
	const kBox = inviteBoxKey(kInv, inviteId, eJ.priv, epkM, eJ.pub, epkM);
	let clear: Uint8Array;
	try {
		clear = xchacha20poly1305(kBox, raw.subarray(32, 32 + NONCE_LEN), utf8.encode(inviteId)).decrypt(
			raw.subarray(32 + NONCE_LEN),
		);
	} catch {
		return fail("decrypt_failed", "invitation indéchiffrable");
	} finally {
		kBox.fill(0);
		eJ.priv.fill(0);
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(utf8Strict.decode(clear));
	} catch {
		return fail("bad_encoding", "invitation : JSON invalide");
	}
	if (!isObject(parsed) || !hasExactKeys(parsed, ["v", "key"]) || parsed.v !== 1 || typeof parsed.key !== "string") {
		return fail("bad_structure", "invitation : structure invalide");
	}
	return parsed.key;
}

// ---------------------------------------------------------------------------
// Envelopes (§5)
// ---------------------------------------------------------------------------

export type Kind = "request" | "accepted" | "response" | "question" | "answer" | "destroy";
export type Status = "ok" | "refused" | "aborted" | "error" | "busy";
export interface Header {
	v: 1;
	parley_id: string;
	msg_id: string;
	kind: Kind;
	from: string;
	to: string;
	reply_to: string | null;
	ts: string;
}
export interface Plain {
	cert: Cert;
	text: string;
	status?: Status;
	reason?: string;
}
export interface Envelope {
	h: Header;
	enc: string;
	ct: string;
	sig: string;
}

export const PLAIN_MAX = 47104;
const TRUNCATION_SUFFIX = "\n[tronqué]";
const TS_SKEW_MS = 5 * 60_000;
const HPKE_INFO = utf8.encode("xs-parley env v1");

const KINDS: readonly string[] = ["request", "accepted", "response", "question", "answer", "destroy"];
const STATUSES: readonly string[] = ["ok", "refused", "aborted", "error", "busy"];
const HEADER_KEYS = ["v", "parley_id", "msg_id", "kind", "from", "to", "reply_to", "ts"] as const;
const FP_RE = /^xs:[A-Za-z0-9_-]{43}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const suite = new CipherSuite({
	kem: new DhkemX25519HkdfSha256(),
	kdf: new HkdfSha256(),
	aead: new Chacha20Poly1305(),
});

/** UUIDv7 (RFC 9562): 48-bit Unix ms timestamp, version 7, variant 10, random remainder. */
export function newMsgId(): string {
	const b = randomBytes(16);
	const ms = BigInt(Date.now());
	for (let i = 0; i < 6; i++) b[i] = Number((ms >> BigInt(8 * (5 - i))) & 0xffn);
	b[6] = (b[6]! & 0x0f) | 0x70;
	b[8] = (b[8]! & 0x3f) | 0x80;
	const hex = Buffer.from(b).toString("hex");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function plainSize(plain: Plain): number {
	return utf8.encode(jcs(plain)).length;
}

/** Truncates `plain.text` (by code points, never splitting a surrogate pair) so that JCS(plain) ≤ PLAIN_MAX. */
export function truncateToFit(plain: Plain): Plain {
	if (plainSize(plain) <= PLAIN_MAX) return plain;
	const cps = Array.from(plain.text);
	const build = (n: number): Plain => ({ ...plain, text: cps.slice(0, n).join("") + TRUNCATION_SUFFIX });
	// Each code point costs at least one byte, so PLAIN_MAX is a safe upper bound.
	let lo = 0;
	let hi = Math.min(cps.length, PLAIN_MAX);
	if (plainSize(build(0)) > PLAIN_MAX) {
		fail("bad_structure", "clair trop volumineux même sans texte");
	}
	while (lo < hi) {
		const mid = (lo + hi + 1) >> 1;
		if (plainSize(build(mid)) <= PLAIN_MAX) lo = mid;
		else hi = mid - 1;
	}
	return build(lo);
}

function envelopeSigInput(h: unknown, enc: string, ct: string): Uint8Array {
	return utf8.encode(jcs({ h, enc, ct }));
}

/** Test-vector entry point: `ekm` is the 32-byte IKM from which HPKE derives the ephemeral key pair. */
export async function sealEnvelopeWithEkm(
	h: Header,
	plain: Plain,
	recipientKemPub: Uint8Array,
	signSeed: Uint8Array,
	ekm?: Uint8Array,
): Promise<Envelope> {
	requireLength(recipientKemPub, 32, "kem_pub du destinataire");
	requireLength(signSeed, 32, "graine Ed25519");
	const recipientPublicKey = await suite.kem.importKey("raw", toArrayBuffer(recipientKemPub), true);
	const { enc, ct } = await suite.seal(
		{ recipientPublicKey, info: HPKE_INFO, ...(ekm ? { ekm: toArrayBuffer(ekm) } : {}) },
		utf8.encode(jcs(plain)),
		utf8.encode(jcs(h)),
	);
	const encB64 = b64uEncode(new Uint8Array(enc));
	const ctB64 = b64uEncode(new Uint8Array(ct));
	return { h, enc: encB64, ct: ctB64, sig: b64uEncode(signBytes(signSeed, envelopeSigInput(h, encB64, ctB64))) };
}

export async function sealEnvelope(
	h: Header,
	plain: Plain,
	recipientKemPub: Uint8Array,
	signSeed: Uint8Array,
): Promise<Envelope> {
	return sealEnvelopeWithEkm(h, plain, recipientKemPub, signSeed);
}

function parseHeader(h: Record<string, unknown>): Header {
	if (!hasExactKeys(h, HEADER_KEYS)) fail("bad_structure", "en-tête : champs");
	if (h.v !== 1) fail("bad_structure", "en-tête : version");
	if (typeof h.parley_id !== "string") fail("bad_structure", "en-tête : parley_id");
	if (typeof h.msg_id !== "string" || !UUID_RE.test(h.msg_id)) fail("bad_structure", "en-tête : msg_id");
	if (typeof h.kind !== "string" || !KINDS.includes(h.kind)) fail("bad_structure", "en-tête : kind");
	if (typeof h.from !== "string" || !FP_RE.test(h.from)) fail("bad_structure", "en-tête : from");
	if (typeof h.to !== "string" || !FP_RE.test(h.to)) fail("bad_structure", "en-tête : to");
	if (h.reply_to !== null && (typeof h.reply_to !== "string" || !UUID_RE.test(h.reply_to))) {
		fail("bad_structure", "en-tête : reply_to");
	}
	if (typeof h.ts !== "string") fail("bad_structure", "en-tête : ts");
	return h as unknown as Header;
}

function parsePlain(raw: Uint8Array, kind: Kind): { cert: unknown; text: string; status?: Status; reason?: string } {
	let value: unknown;
	try {
		value = JSON.parse(utf8Strict.decode(raw));
	} catch {
		return fail("bad_structure", "clair : JSON invalide");
	}
	if (!isObject(value)) fail("bad_structure", "clair : objet attendu");
	const allowed = kind === "accepted" || kind === "response" ? ["cert", "text", "status", "reason"] : ["cert", "text"];
	if (!Object.keys(value).every(k => allowed.includes(k))) fail("bad_structure", "clair : champ non autorisé");
	if (!Object.hasOwn(value, "cert") || typeof value.text !== "string") fail("bad_structure", "clair : cert/text");
	const out: { cert: unknown; text: string; status?: Status; reason?: string } = {
		cert: value.cert,
		text: value.text,
	};
	if (Object.hasOwn(value, "status")) {
		if (typeof value.status !== "string" || !STATUSES.includes(value.status)) fail("bad_structure", "clair : status");
		out.status = value.status as Status;
	}
	if (Object.hasOwn(value, "reason")) {
		if (typeof value.reason !== "string") fail("bad_structure", "clair : reason");
		out.reason = value.reason;
	}
	return out;
}

/** §5.2 steps 1 to 5 (the anti-replay cache is the caller's job). `kemPrivs`: current key first, then the previous one. */
export async function openEnvelope(
	input: unknown,
	opts: { frameParleyId: string; selfFp: string; key: ParleyKey; kemPrivs: Uint8Array[]; now: Date },
): Promise<{ h: Header; plain: Plain; cert: Cert }> {
	// 1. Addressing, then strict structure.
	if (!isObject(input) || !isObject(input.h)) fail("bad_structure", "enveloppe : structure");
	if (input.h.parley_id !== opts.frameParleyId || input.h.parley_id !== opts.key.parleyId) {
		fail("bad_address", "parley_id ≠ trame ou parley non rejointe");
	}
	if (input.h.to !== opts.selfFp) fail("bad_address", "destinataire ≠ cette session");
	if (!hasExactKeys(input, ["h", "enc", "ct", "sig"])) fail("bad_structure", "enveloppe : champs");
	const { enc, ct, sig } = input;
	if (typeof enc !== "string" || typeof ct !== "string" || typeof sig !== "string") {
		fail("bad_structure", "enveloppe : types");
	}
	const h = parseHeader(input.h);

	// 2. HPKE decryption: current key first, then the previous one.
	const encBytes = b64uDecode(enc, 32);
	const ctBytes = b64uDecode(ct);
	if (ctBytes.length < TAG_LEN) fail("bad_encoding", "ct trop court");
	const aad = utf8.encode(jcs(h));
	let clear: Uint8Array | undefined;
	for (const priv of opts.kemPrivs) {
		try {
			const recipientKey = await suite.kem.importKey("raw", toArrayBuffer(priv), false);
			clear = new Uint8Array(
				await suite.open({ recipientKey, enc: toArrayBuffer(encBytes), info: HPKE_INFO }, ctBytes, aad),
			);
			break;
		} catch {
			// Try the next (previous) key.
		}
	}
	if (!clear) return fail("decrypt_failed", "déchiffrement HPKE impossible");
	const parsed = parsePlain(clear, h.kind);

	// 3. Sender certificate, validated against the header's parley and sender fingerprint.
	const cert = verifyCert(parsed.cert, opts.key, h.parley_id, h.from, opts.now);

	// 4. Envelope signature by the certificate's sign_pub.
	const sigBytes = b64uDecode(sig, 64);
	if (!verifyBytes(sigBytes, envelopeSigInput(input.h, enc, ct), b64uDecode(cert.body.sign_pub, 32))) {
		fail("bad_signature", "signature de l'enveloppe invalide");
	}

	// 5. Timestamp profile and clock skew.
	const ts = parseTimestamp(h.ts);
	if (Math.abs(opts.now.getTime() - ts.getTime()) > TS_SKEW_MS) fail("bad_timestamp", "ts hors fenêtre de 5 min");

	const plain: Plain = { cert, text: parsed.text };
	if (parsed.status !== undefined) plain.status = parsed.status;
	if (parsed.reason !== undefined) plain.reason = parsed.reason;
	return { h, plain, cert };
}
