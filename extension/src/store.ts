/**
 * Local persistence (§7.5): `~/.omp/xs-parley/` (override with `XSP_HOME`).
 *
 *   keys/<fp>.key             Ed25519 identity of one omp session (0600)
 *   parleys/<parley_id>.json  parley keys, aliases, roles, policies, signed certs, peer cert cache (0600)
 *   audit/<parley_id>.jsonl   local audit trail (see audit.ts)
 *
 * Directories are 0700, files 0600, writes are atomic (temp file + rename). All I/O is synchronous: the files
 * are tiny, and a synchronous read-modify-write cannot interleave with another handler of the same process.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Cert } from "./crypto.ts";

export type Policy = "ask" | "auto";

export interface IdentityFile {
	v: 1;
	/** Ed25519 seed, base64url. */
	seed: string;
	/** Ed25519 public key, base64url. */
	pub: string;
}

/** One membership (one omp session, identified by its fingerprint) in a parley. */
export interface MemberRecord {
	/** Formatted parley key this session joined with (its rank is the key's rank). */
	key: string;
	alias: string;
	/** No `--as` at join: the alias follows the omp session name. */
	autoAlias?: true;
	role: string;
	policy: Policy;
	/** Last signed certificate published to the relay (kem_pub is ephemeral: informational only). */
	cert?: Cert;
}

export interface ParleyFile {
	v: 1;
	parley_id: string;
	name: string;
	relay: string;
	/** Plain `ws://` to the relay (`--notls`); absent: `wss://`. */
	notls?: true;
	/** fp → membership; several local sessions may join the same parley. */
	members: Record<string, MemberRecord>;
	/** fp → last valid certificate seen for that peer (§4.2). */
	peers: Record<string, Cert>;
}

export const PARLEY_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const FP_RE = /^xs:[A-Za-z0-9_-]{43}$/;

export function defaultRoot(): string {
	return process.env.XSP_HOME || path.join(os.homedir(), ".omp", "xs-parley");
}

function isNotFound(error: unknown): boolean {
	return (error as NodeJS.ErrnoException | undefined)?.code === "ENOENT";
}

export class Store {
	readonly root: string;

	constructor(root: string = defaultRoot()) {
		this.root = root;
	}

	dir(...parts: string[]): string {
		const dir = path.join(this.root, ...parts);
		this.mkdirp(dir);
		return dir;
	}

	private mkdirp(dir: string): void {
		// Create every missing level with 0700 (the umask can only remove bits, and chmod fixes the rest).
		const missing: string[] = [];
		let current = dir;
		while (!fs.existsSync(current)) {
			missing.unshift(current);
			const parent = path.dirname(current);
			if (parent === current) break;
			current = parent;
		}
		for (const d of missing) {
			fs.mkdirSync(d, { mode: 0o700 });
			fs.chmodSync(d, 0o700);
		}
	}

	/** Atomic 0600 write. */
	writeFile(file: string, content: string): void {
		this.mkdirp(path.dirname(file));
		const tmp = `${file}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
		try {
			fs.writeFileSync(tmp, content, { mode: 0o600 });
			fs.chmodSync(tmp, 0o600);
			fs.renameSync(tmp, file);
		} catch (error) {
			fs.rmSync(tmp, { force: true });
			throw error;
		}
	}

	private readText(file: string): string | undefined {
		try {
			return fs.readFileSync(file, "utf8");
		} catch (error) {
			if (isNotFound(error)) return undefined;
			throw error;
		}
	}

	// --- identities ---------------------------------------------------------------------------------------

	identityPath(fp: string): string {
		if (!FP_RE.test(fp)) throw new Error("empreinte invalide");
		return path.join(this.dir("keys"), `${fp}.key`);
	}

	readIdentity(fp: string): IdentityFile | undefined {
		const text = this.readText(this.identityPath(fp));
		if (text === undefined) return undefined;
		const value = JSON.parse(text) as Partial<IdentityFile>;
		if (value.v !== 1 || typeof value.seed !== "string" || typeof value.pub !== "string") {
			throw new Error(`fichier de clé illisible : ${fp}`);
		}
		return { v: 1, seed: value.seed, pub: value.pub };
	}

	writeIdentity(fp: string, identity: IdentityFile): void {
		this.writeFile(this.identityPath(fp), `${JSON.stringify(identity)}\n`);
	}

	// --- parleys -------------------------------------------------------------------------------------------

	parleyPath(parleyId: string): string {
		if (!PARLEY_ID_RE.test(parleyId)) throw new Error("parley_id invalide");
		return path.join(this.dir("parleys"), `${parleyId}.json`);
	}

	readParley(parleyId: string): ParleyFile | undefined {
		const text = this.readText(this.parleyPath(parleyId));
		if (text === undefined) return undefined;
		const value = JSON.parse(text) as ParleyFile;
		if (value.v !== 1 || value.parley_id !== parleyId) throw new Error(`fichier de parley illisible : ${parleyId}`);
		value.members ??= {};
		value.peers ??= {};
		return value;
	}

	writeParley(file: ParleyFile): void {
		this.writeFile(this.parleyPath(file.parley_id), `${JSON.stringify(file, null, 2)}\n`);
	}

	/** Read-modify-write; `fn` returns false to skip the write. Returns the file after the change, if any. */
	updateParley(parleyId: string, fn: (file: ParleyFile) => boolean | void): ParleyFile | undefined {
		const file = this.readParley(parleyId);
		if (!file) return undefined;
		if (fn(file) === false) return file;
		this.writeParley(file);
		return file;
	}

	removeParley(parleyId: string): void {
		fs.rmSync(this.parleyPath(parleyId), { force: true });
	}

	listParleys(): ParleyFile[] {
		const dir = this.dir("parleys");
		const out: ParleyFile[] = [];
		for (const entry of fs.readdirSync(dir)) {
			if (!entry.endsWith(".json")) continue;
			const id = entry.slice(0, -".json".length);
			if (!PARLEY_ID_RE.test(id)) continue;
			try {
				const file = this.readParley(id);
				if (file) out.push(file);
			} catch {
				// A corrupt file must not hide the other parleys.
			}
		}
		return out;
	}

	// --- audit --------------------------------------------------------------------------------------------

	auditDir(): string {
		return this.dir("audit");
	}

	auditPath(parleyId: string): string {
		if (!PARLEY_ID_RE.test(parleyId)) throw new Error("parley_id invalide");
		return path.join(this.auditDir(), `${parleyId}.jsonl`);
	}
}
