/**
 * Local persistence (§7.5): `~/.omp/xshell/` (override with `XSHELL_HOME`).
 *
 *   keys/<fp>.key            Ed25519 identity of one omp session (0600)
 *   shells/<xshell_id>.json  xshell keys, aliases, roles, policies, signed certs, peer cert cache (0600)
 *   audit/<xshell_id>.jsonl  local audit trail (see audit.ts)
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

/** One membership (one omp session, identified by its fingerprint) in a xshell. */
export interface MemberRecord {
	/** Formatted xshell key this session joined with (its rank is the key's rank). */
	key: string;
	alias: string;
	/** No `--as` at join: the alias follows the omp session name. */
	autoAlias?: true;
	role: string;
	policy: Policy;
	/** Last signed certificate published to the relay (kem_pub is ephemeral: informational only). */
	cert?: Cert;
}

export interface ShellFile {
	v: 1;
	xshell_id: string;
	name: string;
	relay: string;
	/** Plain `ws://` to the relay (`--notls`); absent: `wss://`. */
	notls?: true;
	/** fp → membership; several local sessions may join the same xshell. */
	members: Record<string, MemberRecord>;
	/** fp → last valid certificate seen for that peer (§4.2). */
	peers: Record<string, Cert>;
}

export const XSHELL_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const FP_RE = /^xs:[A-Za-z0-9_-]{43}$/;

export function defaultRoot(): string {
	return process.env.XSHELL_HOME || path.join(os.homedir(), ".omp", "xshell");
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

	// --- shells -------------------------------------------------------------------------------------------

	shellPath(xshellId: string): string {
		if (!XSHELL_ID_RE.test(xshellId)) throw new Error("xshell_id invalide");
		return path.join(this.dir("shells"), `${xshellId}.json`);
	}

	readShell(xshellId: string): ShellFile | undefined {
		const text = this.readText(this.shellPath(xshellId));
		if (text === undefined) return undefined;
		const value = JSON.parse(text) as ShellFile;
		if (value.v !== 1 || value.xshell_id !== xshellId) throw new Error(`fichier xshell illisible : ${xshellId}`);
		value.members ??= {};
		value.peers ??= {};
		return value;
	}

	writeShell(file: ShellFile): void {
		this.writeFile(this.shellPath(file.xshell_id), `${JSON.stringify(file, null, 2)}\n`);
	}

	/** Read-modify-write; `fn` returns false to skip the write. Returns the file after the change, if any. */
	updateShell(xshellId: string, fn: (file: ShellFile) => boolean | void): ShellFile | undefined {
		const file = this.readShell(xshellId);
		if (!file) return undefined;
		if (fn(file) === false) return file;
		this.writeShell(file);
		return file;
	}

	removeShell(xshellId: string): void {
		fs.rmSync(this.shellPath(xshellId), { force: true });
	}

	listShells(): ShellFile[] {
		const dir = this.dir("shells");
		const out: ShellFile[] = [];
		for (const entry of fs.readdirSync(dir)) {
			if (!entry.endsWith(".json")) continue;
			const id = entry.slice(0, -".json".length);
			if (!XSHELL_ID_RE.test(id)) continue;
			try {
				const file = this.readShell(id);
				if (file) out.push(file);
			} catch {
				// A corrupt file must not hide the other xshells.
			}
		}
		return out;
	}

	// --- audit --------------------------------------------------------------------------------------------

	auditDir(): string {
		return this.dir("audit");
	}

	auditPath(xshellId: string): string {
		if (!XSHELL_ID_RE.test(xshellId)) throw new Error("xshell_id invalide");
		return path.join(this.auditDir(), `${xshellId}.jsonl`);
	}
}
