/**
 * Relay transport (§6.3, §7.5): one native WebSocket per distinct endpoint (`wss://<relai>/ws`, or `ws://` for an
 * parley joined with `--notls`), request/response correlation by `id`, reconnection with exponential backoff.
 *
 * The transport knows nothing about ranks, certificates or envelopes: `env` and `cert_box` are opaque here.
 */

// --- clock ------------------------------------------------------------------------------------------------

/** Injectable time source: tests drive it by hand. */
export interface Clock {
	now(): number;
	setTimeout(fn: () => void, ms: number): unknown;
	clearTimeout(handle: unknown): void;
}

/** Real clock. A throwing callback must not become an `uncaughtException` (it would tear the session down). */
export const realClock: Clock = {
	now: () => Date.now(),
	setTimeout(fn, ms) {
		const handle = setTimeout(() => {
			try {
				fn();
			} catch {
				// Contained on purpose.
			}
		}, ms);
		handle.unref();
		return handle;
	},
	clearTimeout: handle => clearTimeout(handle as NodeJS.Timeout),
};

// --- types ------------------------------------------------------------------------------------------------

export type RelayErrorCode =
	| "offline"
	| "not_joined"
	| "replaced"
	| "bad_frame"
	| "too_large"
	/** Local conditions. */
	| "unavailable"
	| "timeout"
	| "closed";

export class RelayError extends Error {
	constructor(
		readonly code: RelayErrorCode | string,
		message?: string,
	) {
		super(message ?? code);
		this.name = "RelayError";
	}
}

export interface MemberFrame {
	fp: string;
	cert_box: string;
}

export interface PresenceFrame {
	parley_id: string;
	fp: string;
	online: boolean;
	cert_box?: string;
}

/** Every `endpoint` below is a WebSocket URL built by `relayUrl`; it identifies one connection. */
export interface TransportHandlers {
	/** The connection to `endpoint` is open (first connection or reconnection). */
	up(endpoint: string): void;
	down(endpoint: string, reason: string): void;
	deliver(endpoint: string, parleyId: string, env: unknown): void;
	presence(endpoint: string, frame: PresenceFrame): void;
	/** Another connection took over this (parley, fp). */
	replaced(endpoint: string, parleyId: string): void;
	/** Connection-level problem worth showing the user (relay unreachable, error frame not tied to a request…). */
	problem(endpoint: string, code: string, message: string): void;
	/**
	 * A joiner asks the holder of the offer `inviteId` (this connection) for the key. `epk` (its ephemeral X25519
	 * public key) and `req` (its sealed hello) are relayed as is; answer with `grant` or `refuse`.
	 */
	claimRequest(endpoint: string, inviteId: string, claim: string, epk: string, req: string): void;
}

export interface Transport {
	setHandlers(handlers: TransportHandlers): void;
	/** Reference-counted: opens the connection on first use. */
	acquire(endpoint: string): void;
	release(endpoint: string): void;
	isUp(endpoint: string): boolean;
	join(endpoint: string, parleyId: string, fp: string, certBox: string): Promise<void>;
	leave(endpoint: string, parleyId: string): Promise<void>;
	list(endpoint: string, parleyId: string): Promise<MemberFrame[]>;
	send(endpoint: string, parleyId: string, to: string, env: unknown): Promise<void>;
	/** Invitations (§6.3): none of these needs a prior `join`. */
	offer(endpoint: string, inviteId: string): Promise<void>;
	withdraw(endpoint: string, inviteId: string): Promise<void>;
	/** Resolves with the sealed box the holder granted; rejects `no_invite` (unknown, gone or refused) or `timeout`. */
	claim(endpoint: string, inviteId: string, epk: string, req: string): Promise<string>;
	grant(endpoint: string, claim: string, box: string): Promise<void>;
	refuse(endpoint: string, claim: string): Promise<void>;
	closeAll(): void;
}

/** The few event fields the transport reads; native and fake sockets both satisfy it. */
export interface WebSocketEvent {
	data?: unknown;
	code?: number;
	reason?: string;
	message?: string;
	error?: { message?: string };
}

export interface WebSocketLike {
	readonly readyState: number;
	send(data: string): void;
	close(code?: number, reason?: string): void;
	addEventListener(type: "open" | "message" | "error" | "close", listener: (event: WebSocketEvent) => void): void;
}

export type WebSocketFactory = (url: string) => WebSocketLike;

export const defaultWebSocketFactory: WebSocketFactory = url => new WebSocket(url) as unknown as WebSocketLike;

export const MAX_FRAME_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
/** The relay waits up to 120 s for the holder of an offer to answer a `claim` (a human confirms it). */
const CLAIM_TIMEOUT_MS = 130_000;
const BACKOFF_MIN_MS = 1_000;
const BACKOFF_MAX_MS = 60_000;
const STABLE_MS = 10_000;
const OPEN = 1;

/** `wss://<relay>/ws`, or `ws://<relay>/ws` without TLS (`--notls`, §6.4). Throws on a malformed relay. */
export function relayUrl(relay: string, tls: boolean): string {
	try {
		new URL(`ws://${relay}`);
	} catch {
		throw new RelayError("bad_frame", `relai invalide : ${relay}`);
	}
	return `${tls ? "wss" : "ws"}://${relay}/ws`;
}

export interface RelayTransportOptions {
	clock?: Clock;
	webSocket?: WebSocketFactory;
	random?: () => number;
}

interface Deps {
	clock: Clock;
	webSocket: WebSocketFactory;
	random: () => number;
	handlers: () => TransportHandlers | undefined;
}

interface PendingFrame {
	resolve(frame: Record<string, unknown>): void;
	reject(error: Error): void;
	timer: unknown;
}

class Connection {
	private ws: WebSocketLike | undefined;
	private open = false;
	private stopped = false;
	private attempt = 0;
	private openedAt = 0;
	private counter = 0;
	private lastProblem = "";
	private lastError = "";
	private readonly pending = new Map<string, PendingFrame>();
	private reconnectTimer: unknown;
	/** Bumped on every attempt: a callback from a superseded socket is ignored. */
	private generation = 0;

	constructor(
		readonly endpoint: string,
		private readonly deps: Deps,
	) {}

	get isOpen(): boolean {
		return this.open;
	}

	start(): void {
		this.connect();
	}

	stop(): void {
		this.stopped = true;
		this.generation++;
		this.deps.clock.clearTimeout(this.reconnectTimer);
		this.failAll(new RelayError("closed", "connexion fermée"));
		const ws = this.ws;
		this.ws = undefined;
		this.open = false;
		try {
			ws?.close(1000, "bye");
		} catch {
			// Already gone.
		}
	}

	private problem(code: string, message: string): void {
		const key = `${code}:${message}`;
		if (key === this.lastProblem) return;
		this.lastProblem = key;
		this.safe(h => h.problem(this.endpoint, code, message));
	}

	private safe(fn: (handlers: TransportHandlers) => void): void {
		const handlers = this.deps.handlers();
		if (!handlers) return;
		try {
			fn(handlers);
		} catch {
			// A handler bug must not kill the socket loop.
		}
	}

	private connect(): void {
		if (this.stopped) return;
		const generation = ++this.generation;
		try {
			const ws = this.deps.webSocket(this.endpoint);
			this.ws = ws;
			this.lastError = "";
			ws.addEventListener("open", () => {
				if (generation !== this.generation) return;
				this.open = true;
				this.openedAt = this.deps.clock.now();
				this.lastProblem = "";
				this.safe(h => h.up(this.endpoint));
			});
			ws.addEventListener("message", event => {
				if (generation === this.generation) this.onMessage(event.data);
			});
			ws.addEventListener("error", event => {
				if (generation === this.generation) this.lastError = String(event.message ?? event.error?.message ?? "");
			});
			ws.addEventListener("close", event => {
				if (generation === this.generation) this.onClose(event.code, event.reason);
			});
		} catch (error) {
			if (generation !== this.generation || this.stopped) return;
			this.problem("unavailable", error instanceof Error ? error.message : String(error));
			this.scheduleReconnect();
		}
	}

	private onClose(code: number | undefined, reason: string | undefined): void {
		const wasOpen = this.open;
		this.open = false;
		this.ws = undefined;
		this.failAll(new RelayError("closed", "connexion au relai perdue"));
		if (this.stopped) return;
		if (!wasOpen && this.lastError) {
			const hint = this.endpoint.startsWith("wss:") && /TLS|SSL/.test(this.lastError) ? " (relai sans TLS ? rejoindre avec --notls)" : "";
			this.problem("unavailable", `connexion au relai impossible : ${this.lastError}${hint}`);
		}
		if (wasOpen) {
			if (this.deps.clock.now() - this.openedAt >= STABLE_MS) this.attempt = 0;
			const why = reason || `code ${code ?? "?"}`;
			this.safe(h => h.down(this.endpoint, why));
		}
		this.scheduleReconnect();
	}

	private scheduleReconnect(): void {
		if (this.stopped) return;
		const base = Math.min(BACKOFF_MAX_MS, BACKOFF_MIN_MS * 2 ** this.attempt);
		this.attempt++;
		const delay = Math.min(BACKOFF_MAX_MS, base * (1 + 0.25 * this.deps.random()));
		this.deps.clock.clearTimeout(this.reconnectTimer);
		this.reconnectTimer = this.deps.clock.setTimeout(() => this.connect(), delay);
	}

	private onMessage(data: unknown): void {
		let frame: unknown;
		try {
			frame = JSON.parse(typeof data === "string" ? data : Buffer.from(data as ArrayBuffer).toString("utf8"));
		} catch {
			return;
		}
		if (typeof frame !== "object" || frame === null || Array.isArray(frame)) return;
		const f = frame as Record<string, unknown>;
		const id = typeof f.id === "string" ? f.id : undefined;
		const waiter = id ? this.pending.get(id) : undefined;
		if (id && waiter) {
			this.pending.delete(id);
			this.deps.clock.clearTimeout(waiter.timer);
			if (f.t === "error") {
				waiter.reject(new RelayError(String(f.code ?? "bad_frame"), String(f.message ?? f.code ?? "erreur du relai")));
			} else {
				waiter.resolve(f);
			}
			return;
		}
		switch (f.t) {
			case "deliver":
				if (typeof f.parley_id === "string") this.safe(h => h.deliver(this.endpoint, f.parley_id as string, f.env));
				break;
			case "presence":
				if (typeof f.parley_id === "string" && typeof f.fp === "string" && typeof f.online === "boolean") {
					const presence: PresenceFrame = { parley_id: f.parley_id, fp: f.fp, online: f.online };
					if (typeof f.cert_box === "string") presence.cert_box = f.cert_box;
					this.safe(h => h.presence(this.endpoint, presence));
				}
				break;
			case "error":
				if (f.code === "replaced" && typeof f.parley_id === "string") {
					this.safe(h => h.replaced(this.endpoint, f.parley_id as string));
				} else {
					this.problem(String(f.code ?? "error"), String(f.message ?? f.code ?? "erreur du relai"));
				}
				break;
			case "claim_request":
				if (
					typeof f.invite_id === "string" &&
					typeof f.claim === "string" &&
					typeof f.epk === "string" &&
					typeof f.req === "string"
				) {
					this.safe(h => h.claimRequest(this.endpoint, f.invite_id as string, f.claim as string, f.epk as string, f.req as string));
				}
				break;
			default:
				break;
		}
	}

	private failAll(error: Error): void {
		for (const waiter of this.pending.values()) {
			this.deps.clock.clearTimeout(waiter.timer);
			waiter.reject(error);
		}
		this.pending.clear();
	}

	private sendRaw(frame: Record<string, unknown>): void {
		const text = JSON.stringify(frame);
		if (Buffer.byteLength(text, "utf8") > MAX_FRAME_BYTES) throw new RelayError("too_large", "trame de plus de 64 Ko");
		if (!this.ws || !this.open || this.ws.readyState !== OPEN) throw new RelayError("unavailable", "relai non connecté");
		this.ws.send(text);
	}

	request(type: string, fields: Record<string, unknown>, timeoutMs = REQUEST_TIMEOUT_MS): Promise<Record<string, unknown>> {
		const { promise, resolve, reject } = Promise.withResolvers<Record<string, unknown>>();
		const id = `c${++this.counter}`;
		try {
			this.sendRaw({ v: 1, t: type, id, ...fields });
		} catch (error) {
			reject(error);
			return promise;
		}
		const timer = this.deps.clock.setTimeout(() => {
			this.pending.delete(id);
			reject(new RelayError("timeout", "le relai n'a pas répondu"));
		}, timeoutMs);
		this.pending.set(id, { resolve, reject, timer });
		return promise;
	}
}

export class RelayTransport implements Transport {
	private handlers: TransportHandlers | undefined;
	private readonly connections = new Map<string, { conn: Connection; refs: number }>();
	private readonly deps: Deps;

	constructor(options: RelayTransportOptions = {}) {
		this.deps = {
			clock: options.clock ?? realClock,
			webSocket: options.webSocket ?? defaultWebSocketFactory,
			random: options.random ?? Math.random,
			handlers: () => this.handlers,
		};
	}

	setHandlers(handlers: TransportHandlers): void {
		this.handlers = handlers;
	}

	acquire(endpoint: string): void {
		const existing = this.connections.get(endpoint);
		if (existing) {
			existing.refs++;
			return;
		}
		const conn = new Connection(endpoint, this.deps);
		this.connections.set(endpoint, { conn, refs: 1 });
		conn.start();
	}

	release(endpoint: string): void {
		const entry = this.connections.get(endpoint);
		if (!entry) return;
		if (--entry.refs > 0) return;
		this.connections.delete(endpoint);
		entry.conn.stop();
	}

	isUp(endpoint: string): boolean {
		return this.connections.get(endpoint)?.conn.isOpen ?? false;
	}

	private conn(endpoint: string): Connection {
		const entry = this.connections.get(endpoint);
		if (!entry) throw new RelayError("unavailable", "relai non connecté");
		return entry.conn;
	}

	async join(endpoint: string, parleyId: string, fp: string, certBox: string): Promise<void> {
		await this.conn(endpoint).request("join", { parley_id: parleyId, fp, cert_box: certBox });
	}

	async leave(endpoint: string, parleyId: string): Promise<void> {
		await this.conn(endpoint).request("leave", { parley_id: parleyId });
	}

	async list(endpoint: string, parleyId: string): Promise<MemberFrame[]> {
		const frame = await this.conn(endpoint).request("list", { parley_id: parleyId });
		const members = Array.isArray(frame.members) ? frame.members : [];
		const out: MemberFrame[] = [];
		for (const m of members) {
			if (m && typeof m.fp === "string" && typeof m.cert_box === "string") out.push({ fp: m.fp, cert_box: m.cert_box });
		}
		return out;
	}

	async send(endpoint: string, parleyId: string, to: string, env: unknown): Promise<void> {
		await this.conn(endpoint).request("send", { parley_id: parleyId, to, env });
	}

	async offer(endpoint: string, inviteId: string): Promise<void> {
		await this.conn(endpoint).request("offer", { invite_id: inviteId });
	}

	async withdraw(endpoint: string, inviteId: string): Promise<void> {
		await this.conn(endpoint).request("withdraw", { invite_id: inviteId });
	}

	async claim(endpoint: string, inviteId: string, epk: string, req: string): Promise<string> {
		const frame = await this.conn(endpoint).request("claim", { invite_id: inviteId, epk, req }, CLAIM_TIMEOUT_MS);
		if (frame.t !== "granted" || typeof frame.box !== "string") throw new RelayError("bad_frame", "réponse du relai invalide");
		return frame.box;
	}

	async grant(endpoint: string, claim: string, box: string): Promise<void> {
		await this.conn(endpoint).request("grant", { claim, box });
	}

	async refuse(endpoint: string, claim: string): Promise<void> {
		await this.conn(endpoint).request("refuse", { claim });
	}

	closeAll(): void {
		for (const { conn } of this.connections.values()) conn.stop();
		this.connections.clear();
	}
}
