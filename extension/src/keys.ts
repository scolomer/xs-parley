/**
 * Member identity and key lifecycle (§3, §4.2): per-session Ed25519 identity, ephemeral X25519 pairs with
 * rotation, memberships (a session's view of one joined xshell), peer certificate cache.
 */
import {
	b64uDecode,
	b64uEncode,
	CERT_MAX_AGE_MS,
	type Cert,
	certFingerprint,
	fingerprint,
	generateKemPair,
	generateSignPair,
	groupKey,
	type KemPair,
	openCertBox,
	type Rank,
	type ShellKey,
	type SignPair,
	signCert,
	signPairFromSeed,
	verifyCert,
} from "./crypto.ts";
import type { Policy, Store } from "./store.ts";

export const KEM_ROTATE_MS = 24 * 3600_000;
/** Fallback window for the previous X25519 key: the `ts` window of §5.2 (5 min) plus margin. */
export const KEM_GRACE_MS = 10 * 60_000;

// --- identity ---------------------------------------------------------------------------------------------

export interface Identity {
	pair: SignPair;
	/** `xs:` + base64url(SHA-256(sign_pub)); never changes. */
	fp: string;
}

export function createIdentity(store: Store): Identity {
	const pair = generateSignPair();
	const fp = fingerprint(pair.pub);
	store.writeIdentity(fp, { v: 1, seed: b64uEncode(pair.seed), pub: b64uEncode(pair.pub) });
	return { pair, fp };
}

/** Reloads the identity of a resumed session; undefined if the key file is gone or inconsistent. */
export function loadIdentity(store: Store, fp: string): Identity | undefined {
	const file = store.readIdentity(fp);
	if (!file) return undefined;
	const pair = signPairFromSeed(b64uDecode(file.seed, 32));
	if (fingerprint(pair.pub) !== fp) return undefined;
	return { pair, fp };
}

/** Default alias (§3): the first 8 characters of the fingerprint after `xs:`. */
export function defaultAlias(fp: string): string {
	return fp.slice(3, 11);
}

/**
 * Alias derived from the omp session name (§3): accents dropped, every run of characters outside
 * `[A-Za-z0-9_-]` becomes `-`, 32 characters at most. `undefined` when nothing usable is left.
 */
export function aliasFromSessionName(name: string | undefined): string | undefined {
	if (!name) return undefined;
	const slug = name
		.normalize("NFD")
		.replace(/\p{M}/gu, "")
		.replace(/[^A-Za-z0-9_-]+/g, "-")
		.replace(/-{2,}/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 32)
		.replace(/-+$/, "");
	return slug || undefined;
}

// --- ephemeral X25519 -------------------------------------------------------------------------------------

/** In-memory only: never written to disk. One keeper per relay connection. */
export class KemKeeper {
	private current: KemPair;
	private createdAt: number;
	private retired: { pair: KemPair; until: number }[] = [];

	constructor(private readonly now: () => number) {
		this.current = generateKemPair();
		this.createdAt = now();
	}

	get pub(): Uint8Array {
		return this.current.pub;
	}

	/** New current pair; the old one stays usable for decryption for 10 min, then is wiped. */
	rotate(): void {
		this.purge();
		this.retired.push({ pair: this.current, until: this.now() + KEM_GRACE_MS });
		this.current = generateKemPair();
		this.createdAt = this.now();
	}

	/** Private keys to try, current first. */
	privs(): Uint8Array[] {
		this.purge();
		return [this.current.priv, ...this.retired.map(r => r.pair.priv)];
	}

	dueForRotation(): boolean {
		return this.now() - this.createdAt >= KEM_ROTATE_MS;
	}

	/** Milliseconds until the next scheduled rotation. */
	untilRotation(): number {
		return Math.max(0, this.createdAt + KEM_ROTATE_MS - this.now());
	}

	wipe(): void {
		this.current.priv.fill(0);
		for (const r of this.retired) r.pair.priv.fill(0);
		this.retired = [];
	}

	private purge(): void {
		const now = this.now();
		this.retired = this.retired.filter(r => {
			if (r.until > now) return true;
			r.pair.priv.fill(0);
			return false;
		});
	}
}

// --- peers ------------------------------------------------------------------------------------------------

export interface PeerView {
	fp: string;
	cert: Cert;
	rank: Rank;
	alias: string;
	role: string;
	online: boolean;
}

/** Certificates of the other members of one xshell (§4.2: cache) plus their current presence. */
export class PeerBook {
	private readonly certs = new Map<string, Cert>();
	private readonly online = new Set<string>();

	constructor(
		initial: Record<string, Cert>,
		private readonly onChange: () => void,
	) {
		for (const [fp, cert] of Object.entries(initial)) this.certs.set(fp, cert);
	}

	/**
	 * A valid certificate replaces the cached one only if strictly more recent (a relay cannot roll a sender back
	 * to an old `kem_pub`). Returns true if the cache changed.
	 */
	accept(cert: Cert): boolean {
		const fp = certFingerprint(cert);
		const known = this.certs.get(fp);
		if (known && known.body.issued_at >= cert.body.issued_at) return false;
		this.certs.set(fp, cert);
		this.onChange();
		return true;
	}

	/** Certificate usable to encrypt: cached and not older than 25 h; otherwise the member counts as offline. */
	usable(fp: string, now: number): Cert | undefined {
		const cert = this.certs.get(fp);
		if (!cert) return undefined;
		return now - Date.parse(cert.body.issued_at) <= CERT_MAX_AGE_MS ? cert : undefined;
	}

	known(fp: string): Cert | undefined {
		return this.certs.get(fp);
	}

	setOnline(fp: string, online: boolean): void {
		if (online) this.online.add(fp);
		else this.online.delete(fp);
	}

	/** Replaces the whole presence set (`members` answer). */
	resetOnline(fps: Iterable<string>): void {
		this.online.clear();
		for (const fp of fps) this.online.add(fp);
	}

	isOnline(fp: string): boolean {
		return this.online.has(fp);
	}

	clear(): void {
		this.certs.clear();
		this.online.clear();
		this.onChange();
	}

	snapshot(): Record<string, Cert> {
		return Object.fromEntries(this.certs);
	}

	/** Known peers (excluding `selfFp`). Peers whose certificate is older than 25 h are listed as offline. */
	views(selfFp: string, now: number): PeerView[] {
		const out: PeerView[] = [];
		for (const [fp, cert] of this.certs) {
			if (fp === selfFp) continue;
			const fresh = this.usable(fp, now) !== undefined;
			out.push({
				fp,
				cert,
				rank: cert.body.rank,
				alias: cert.body.alias,
				role: cert.body.role,
				online: fresh && this.online.has(fp),
			});
		}
		return out;
	}
}

// --- membership -------------------------------------------------------------------------------------------

/** A session's view of one joined xshell. */
export interface Membership {
	xshellId: string;
	name: string;
	relay: string;
	/** WebSocket URL of the relay (`relayUrl`): identifies the transport connection. */
	endpoint: string;
	fp: string;
	key: ShellKey;
	alias: string;
	/** The alias follows the omp session name (no `--as` given); a rename republishes the certificate. */
	autoAlias: boolean;
	role: string;
	policy: Policy;
	peers: PeerBook;
	/** Certificate currently published to the relay. */
	cert?: Cert;
	/** Another connection took over our fingerprint: not republished until the user joins again. */
	suspended: boolean;
	/** Cached K_grp. */
	kGrp?: Uint8Array;
}

export function membershipGroupKey(m: Membership): Uint8Array {
	m.kGrp ??= groupKey(m.key);
	return m.kGrp;
}

/** Decrypts and validates a `cert_box` received from the relay (§4.2). Throws `XshellCryptoError`. */
export function readCertBox(m: Membership, fpAnnounced: string, box: string, now: Date): Cert {
	const raw = openCertBox(membershipGroupKey(m), m.xshellId, box);
	return verifyCert(raw, m.key, m.xshellId, fpAnnounced, now);
}

/** Signs a fresh certificate for `m` carrying `kemPub` (§3, §4.2). */
export function issueCert(m: Membership, identity: Identity, kemPub: Uint8Array, now: number): Cert {
	return signCert(m.key, {
		signPub: identity.pair.pub,
		kemPub,
		alias: m.alias,
		role: m.role,
		issuedAt: new Date(now),
	});
}
