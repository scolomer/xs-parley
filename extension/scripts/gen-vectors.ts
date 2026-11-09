/**
 * Generates the fixed cross-language test vectors in `doc/protocol/vectors/*.json`.
 *
 * Every secret and nonce is derived from a constant label, so the output is
 * byte-for-byte reproducible (Ed25519 signatures are deterministic; HPKE uses
 * the `ekm` test hook of @hpke/core to fix the ephemeral key).
 * Run with: `bun scripts/gen-vectors.ts`.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import {
	type Cert,
	type Header,
	type Plain,
	type ShellKey,
	answerKey as deriveAnswerKey,
	b64uEncode,
	certFingerprint,
	fingerprint,
	formatShellKey,
	groupKey,
	jcs,
	kemPairFromPriv,
	rankPubs,
	sealCertBoxWithNonce,
	sealEnvelopeWithEkm,
	signCert,
	signPairFromSeed,
	inviteSecrets,
	sealInviteRequestWithNonce,
	sealInviteWithEphemeral,
} from "../src/crypto.ts";

const utf8 = new TextEncoder();
const label = (name: string): Uint8Array => sha256(utf8.encode(`xshell test vector: ${name}`));

export const VECTOR_FILES = ["fingerprint", "shell-key", "k-grp", "cert", "cert-box", "envelope", "invite"] as const;
export type VectorName = (typeof VECTOR_FILES)[number];

export const VECTOR_RELAY = "relay.example.com:8443";
export const VECTOR_NAME = "prod-k8s";
export const VECTOR_ISSUED_AT = "2026-11-01T10:00:00.000Z";
export const VECTOR_TS = "2026-11-01T12:00:00.000Z";
export const VECTOR_INVITE_UUID = "3f2b8c4e-1a5d-4e7f-9b2a-6c8d0e1f2a3b";
export const VECTOR_NOW = "2026-11-01T12:00:01.000Z";

export async function buildAllVectors(): Promise<Record<VectorName, unknown>> {
	const xshellId = b64uEncode(label("xshell_id").subarray(0, 16));
	const askPair = signPairFromSeed(label("seed ask"));
	const answerPair = signPairFromSeed(label("seed answer"));
	const askKey = {
		relay: VECTOR_RELAY,
		xshellId,
		name: VECTOR_NAME,
		rank: "A" as const,
		seed: askPair.seed,
		answerSeed: answerPair.seed,
	};
	const answerKey: ShellKey = deriveAnswerKey(askKey);

	const alice = signPairFromSeed(label("member alice sign"));
	const bob = signPairFromSeed(label("member bob sign"));
	const aliceKem = kemPairFromPriv(label("member alice kem"));
	const bobKem = kemPairFromPriv(label("member bob kem"));
	const issuedAt = new Date(VECTOR_ISSUED_AT);
	const aliceCert: Cert = signCert(askKey, {
		signPub: alice.pub,
		kemPub: aliceKem.pub,
		alias: "alice",
		role: "master « accès prod » \u{1F680}",
		issuedAt,
	});
	const bobCert: Cert = signCert(answerKey, {
		signPub: bob.pub,
		kemPub: bobKem.pub,
		alias: "prod-box",
		role: "accès prod k8s, kubectl lecture",
		issuedAt,
	});
	const kGrp = groupKey(askKey);
	const pubs = rankPubs(askKey);

	const fingerprintVec = {
		description: "fp = 'xs:' + base64url(SHA-256(raw Ed25519 public key))",
		cases: [alice, bob, askPair].map(p => ({
			sign_seed: b64uEncode(p.seed),
			sign_pub: b64uEncode(p.pub),
			fp: fingerprint(p.pub),
		})),
	};

	const shellKeyVec = {
		description:
			"Shell key format xs2:<relay>:<xshell_id>:<name>:<rank>:<seed>:<other>; other = seed_answer for rank A, pub_ask for rank S; the relay may contain a port",
		cases: [askKey, answerKey, { ...askKey, relay: "relay.example.com" }].map(k => ({
			key: formatShellKey(k),
			relay: k.relay,
			xshell_id: k.xshellId,
			name: k.name,
			rank: k.rank,
			seed: b64uEncode(k.seed),
			other: b64uEncode(k.rank === "A" ? k.answerSeed : k.askPub),
		})),
	};

	const kGrpVec = {
		description:
			"K_grp = HKDF-SHA256(ikm = pub_ask || pub_answer, salt = empty, info = 'xshell cert v1' || xshell_id (UTF-8), L = 32)",
		xshell_id: xshellId,
		pub_ask: b64uEncode(pubs.pubAsk),
		pub_answer: b64uEncode(pubs.pubAnswer),
		key_ask: formatShellKey(askKey),
		key_answer: formatShellKey(answerKey),
		k_grp: b64uEncode(kGrp),
	};

	const certCase = (key: ShellKey, cert: Cert, signPub: Uint8Array, kemPub: Uint8Array) => ({
		signing_key: formatShellKey(key),
		xshell_id: xshellId,
		sign_pub: b64uEncode(signPub),
		kem_pub: b64uEncode(kemPub),
		jcs_body: jcs(cert.body),
		cert,
		fp: certFingerprint(cert),
	});
	const certVec = {
		description: "cert = {body, sig}; sig = Ed25519(rank seed, UTF-8(JCS(body))), base64url",
		now: VECTOR_NOW,
		cases: [
			certCase(askKey, aliceCert, alice.pub, aliceKem.pub),
			certCase(answerKey, bobCert, bob.pub, bobKem.pub),
		],
	};

	const nonce = label("cert box nonce").subarray(0, 24);
	const certBoxVec = {
		description:
			"cert_box = base64url(nonce || XChaCha20-Poly1305(K_grp, nonce, JCS({body, sig}), aad = UTF-8(xshell_id)))",
		xshell_id: xshellId,
		k_grp: b64uEncode(kGrp),
		nonce: b64uEncode(nonce),
		cert: aliceCert,
		fp: certFingerprint(aliceCert),
		cert_box: sealCertBoxWithNonce(kGrp, xshellId, aliceCert, nonce),
	};

	const ekm = label("envelope hpke ephemeral ikm");
	const h: Header = {
		v: 1,
		xshell_id: xshellId,
		msg_id: "01939f0c-7a3e-7b2d-8c4e-5f6a7b8c9d0e",
		kind: "request",
		from: fingerprint(alice.pub),
		to: fingerprint(bob.pub),
		reply_to: null,
		ts: VECTOR_TS,
	};
	const plain: Plain = {
		cert: aliceCert,
		text: 'Liste les pods :\n\t"kubectl get pods" \u0001 \u{1F600} é',
	};
	const envelopeVec = {
		description:
			"HPKE base mode, KEM 0x0020, KDF 0x0001, AEAD 0x0003, info = 'xshell env v1', aad = UTF-8(JCS(h)); sig = Ed25519(sender seed, UTF-8(JCS({h, enc, ct})))",
		now: VECTOR_NOW,
		xshell_id: xshellId,
		verifier_key: formatShellKey(answerKey),
		sender_sign_seed: b64uEncode(alice.seed),
		recipient_kem_priv: b64uEncode(bobKem.priv),
		recipient_kem_pub: b64uEncode(bobKem.pub),
		hpke_ephemeral_ikm: b64uEncode(ekm),
		h,
		jcs_h: jcs(h),
		plain,
		jcs_plain: jcs(plain),
		envelope: await sealEnvelopeWithEkm(h, plain, bobKem.pub, alice.seed, ekm),
	};

	const invite = inviteSecrets(VECTOR_INVITE_UUID);
	const ephJ = kemPairFromPriv(label("invite claimant ephemeral"));
	const ephM = kemPairFromPriv(label("invite master ephemeral"));
	const reqNonce = label("invite request nonce").subarray(0, 24);
	const boxNonce = label("invite box nonce").subarray(0, 24);
	const hello = { alias: "prod-box", role: "accès prod k8s, kubectl lecture" };
	const inviteShellKey = formatShellKey(answerKey);
	const inviteShared = x25519.getSharedSecret(ephM.priv, ephJ.pub);
	const inviteBoxKey = hkdf(
		sha256,
		concatBytes(invite.key, inviteShared),
		new Uint8Array(0),
		concatBytes(utf8.encode("xshell invite box v2"), utf8.encode(invite.inviteId), ephJ.pub, ephM.pub),
		32,
	);
	const inviteVec = {
		description:
			"ikm = the 16 UUID bytes; invite_id = base64url(HKDF-SHA256(ikm, salt = empty, info = 'xshell invite id v1', L = 16)); k_inv = HKDF-SHA256(ikm, salt = empty, info = 'xshell invite key v1', L = 32). Claimant: ephemeral X25519 pair e_j; req = base64url(nonce || XChaCha20-Poly1305(k_inv, nonce, UTF-8(JCS({v: 1, alias, role})), aad = UTF-8(invite_id) || epk_j (32 raw bytes))). Master: ephemeral X25519 pair e_m; shared = X25519(e_m.priv, epk_j) (= X25519(e_j.priv, epk_m), all-zero is refused); k_box = HKDF-SHA256(ikm = k_inv || shared, salt = empty, info = 'xshell invite box v2' || UTF-8(invite_id) || epk_j || epk_m, L = 32); box = base64url(epk_m || nonce || XChaCha20-Poly1305(k_box, nonce, UTF-8(JCS({v: 1, key: shell_key})), aad = UTF-8(invite_id)))",
		uuid: VECTOR_INVITE_UUID,
		invite_id: invite.inviteId,
		k_inv: b64uEncode(invite.key),
		claimant_ephemeral_priv: b64uEncode(ephJ.priv),
		claimant_ephemeral_pub: b64uEncode(ephJ.pub),
		hello,
		jcs_hello: jcs({ v: 1, ...hello }),
		request_nonce: b64uEncode(reqNonce),
		req: sealInviteRequestWithNonce(invite.key, invite.inviteId, ephJ.pub, hello, reqNonce),
		master_ephemeral_priv: b64uEncode(ephM.priv),
		master_ephemeral_pub: b64uEncode(ephM.pub),
		shared: b64uEncode(inviteShared),
		k_box: b64uEncode(inviteBoxKey),
		shell_key: inviteShellKey,
		box_nonce: b64uEncode(boxNonce),
		box: sealInviteWithEphemeral(invite.key, invite.inviteId, ephJ.pub, inviteShellKey, ephM.priv, boxNonce),
	};

	return {
		fingerprint: fingerprintVec,
		"shell-key": shellKeyVec,
		"k-grp": kGrpVec,
		cert: certVec,
		"cert-box": certBoxVec,
		envelope: envelopeVec,
		invite: inviteVec,
	};
}

export const VECTORS_DIR = new URL("../../doc/protocol/vectors/", import.meta.url);

export function serializeVector(value: unknown): string {
	return `${JSON.stringify(value, null, 2)}\n`;
}

if (import.meta.main) {
	mkdirSync(VECTORS_DIR, { recursive: true });
	const all = await buildAllVectors();
	for (const name of VECTOR_FILES) {
		writeFileSync(new URL(`${name}.json`, VECTORS_DIR), serializeVector(all[name]));
		console.log(`doc/protocol/vectors/${name}.json`);
	}
}
