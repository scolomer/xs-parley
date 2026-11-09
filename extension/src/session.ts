/**
 * Lifecycle of the xshell memberships of one omp main session (§3, §6.3, §7.5): create / join / leave / rotate,
 * connection events, X25519 rotation and republication, resume and switch, system-prompt section.
 *
 * `index.ts` only wires omp events to this class; the protocol itself lives in `inbox.ts`.
 */
import type { Audit } from "./audit.ts";
import {
	type AskKey,
	answerKey,
	b64uDecode,
	b64uEncode,
	formatShellKey,
	generateKemPair,
	generateShell,
	inviteSecrets,
	newInviteCode,
	openInvite,
	openInviteRequest,
	sealInvite,
	sealInviteRequest,
	NAME_RE,
	parseShellKey,
	type Rank,
	sanitizeRole,
	sealCertBox,
	type ShellKey,
	XshellCryptoError,
} from "./crypto.ts";
import { Inbox, type HostBridge, type PendingRecord } from "./inbox.ts";
import {
	createIdentity,
	defaultAlias,
	aliasFromSessionName,
	type Identity,
	issueCert,
	KemKeeper,
	loadIdentity,
	type Membership,
	membershipGroupKey,
	PeerBook,
	type PeerView,
	readCertBox,
} from "./keys.ts";
import type { MemberRecord, Policy, ShellFile, Store } from "./store.ts";
import { type Clock, type PresenceFrame, RelayError, relayUrl, type Transport, type TransportHandlers } from "./transport.ts";

/** Custom session entry holding the per-session state (§7.5). */
export const STATE_ENTRY = "xshell-state";
const PRUNE_INTERVAL_MS = 10 * 60_000;
const FIRST_PUBLISH_WAIT_MS = 10_000;
/** An invitation lives 5 minutes, in the memory of the master session that issued it. */
const INVITE_TTL_MS = 5 * 60_000;
/** How long `join <uuid>` waits for its temporary relay connection. */
const INVITE_CONNECT_WAIT_MS = 10_000;

/** What `pi.appendEntry` records: no secret (§7.5). */
export interface SessionState {
	shells: { xshell_id: string; fp: string }[];
	pending: PendingRecord[];
}

export interface SessionHost extends Omit<HostBridge, "pendingChanged" | "requestActiveChanged"> {
	persistState(state: SessionState): void;
	/** The set of tools the model should see may have changed. */
	toolsChanged(): void;
	/** Name of the omp session (`/name`, title), if any: the default alias follows it (§3). */
	sessionName(): string | undefined;
}

/** A failure whose message is meant for the user as is. */
export class UserError extends Error {}

export type PublishResult = { ok: true } | { ok: false; error: string };

export interface JoinOutcome {
	membership: Membership;
}

export interface ShellKeys {
	ask: string;
	answer: string;
}

export interface SessionOptions {
	store: Store;
	audit: Audit;
	transport: Transport;
	clock: Clock;
	host: SessionHost;
}

export interface PeerCandidate {
	m: Membership;
	peer: PeerView;
}

interface Deferred<T> {
	promise: Promise<T>;
	resolve(value: T): void;
}

/** An invitation this master session offers to the relay. Never persisted. */
interface InviteEntry {
	xshellId: string;
	rank: Rank;
	/** Opens the claimant's request and seals the answer (`inviteSecrets`). */
	key: Uint8Array;
	/** Connection the offer lives on: the relay forgets it with the connection. */
	endpoint: string;
	expiresAt: number;
	timer: unknown;
	/** A claim is waiting for the user's decision: any other claim of this invitation is refused. */
	confirming: boolean;
}

export function rankLabel(rank: Rank): "master" | "slave" {
	return rank === "A" ? "master" : "slave";
}

function errorText(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

export class XshellSession {
	readonly inbox: Inbox;
	private identity: Identity | undefined;
	private readonly memberships = new Map<string, Membership>();
	private readonly kems = new Map<string, { keeper: KemKeeper; timer: unknown }>();
	private readonly firstPublish = new Map<string, Deferred<PublishResult>>();
	private readonly everUp = new Set<string>();
	/** `invite_id` → invitation, for the xshells this session is master of. */
	private readonly invites = new Map<string, InviteEntry>();
	/** Invitation dialogs run one at a time, in arrival order. */
	private inviteConfirmChain: Promise<unknown> = Promise.resolve();
	/** `join <uuid>` calls waiting for their temporary connection to come up (or fail). */
	private readonly connectWaiters = new Map<string, Set<(result: PublishResult) => void>>();
	private pruneTimer: unknown;
	private lastPersisted = "";
	private persistEnabled = true;
	private readonly store: Store;
	private readonly audit: Audit;
	private readonly transport: Transport;
	private readonly clock: Clock;
	private readonly host: SessionHost;

	constructor(options: SessionOptions) {
		this.store = options.store;
		this.audit = options.audit;
		this.transport = options.transport;
		this.clock = options.clock;
		this.host = options.host;
		this.inbox = new Inbox({
			clock: this.clock,
			transport: this.transport,
			host: {
				hasUI: () => this.host.hasUI(),
				confirm: (title, message) => this.host.confirm(title, message),
				isIdle: () => this.host.isIdle(),
				inject: (message, opts) => this.host.inject(message, opts),
				notify: (message, level) => this.host.notify(message, level),
				pendingChanged: () => this.persist(),
				requestActiveChanged: () => this.host.toolsChanged(),
				sessionRef: () => this.host.sessionRef(),
			},
			audit: (xshellId, record) => this.audit.log(xshellId, record),
			membership: xshellId => this.memberships.get(xshellId),
			identity: () => this.identity,
			kemPrivs: endpoint => this.kems.get(endpoint)?.keeper.privs() ?? [],
			destroyed: (m, byAlias, byFp) => this.onDestroyed(m, byAlias, byFp),
		});
		const handlers: TransportHandlers = {
			up: endpoint => this.onUp(endpoint),
			down: (endpoint, reason) => this.onDown(endpoint, reason),
			deliver: (endpoint, xshellId, env) => void this.inbox.handleDeliver(endpoint, xshellId, env),
			presence: (endpoint, frame) => this.onPresence(endpoint, frame),
			replaced: (endpoint, xshellId) => this.onReplaced(endpoint, xshellId),
			problem: (endpoint, code, message) => this.onProblem(endpoint, code, message),
			claimRequest: (endpoint, inviteId, claim, epk, req) => void this.onClaimRequest(endpoint, inviteId, claim, epk, req),
		};
		this.transport.setHandlers(handlers);
	}

	// --- accessors ------------------------------------------------------------------------------------------

	get fp(): string | undefined {
		return this.identity?.fp;
	}

	all(): Membership[] {
		return [...this.memberships.values()];
	}

	get(xshellId: string): Membership | undefined {
		return this.memberships.get(xshellId);
	}

	byName(name: string): Membership | undefined {
		return this.all().find(m => m.name === name);
	}

	masters(): Membership[] {
		return this.all().filter(m => m.key.rank === "A" && !m.suspended);
	}

	/** Names of the xshell tools the model should currently see (§7.2). */
	activeToolNames(): string[] {
		const names: string[] = [];
		if (this.memberships.size > 0) names.push("xshell_list");
		if (this.masters().length > 0) names.push("xshell_ask", "xshell_answer");
		if (this.inbox.hasActiveRequest) names.push("xshell_question");
		return names;
	}

	// --- persistence of the session state --------------------------------------------------------------------

	private snapshot(): SessionState {
		return {
			shells: this.all().map(m => ({ xshell_id: m.xshellId, fp: m.fp })),
			pending: this.inbox.exportPending(),
		};
	}

	persist(): void {
		if (!this.persistEnabled) return;
		const state = this.snapshot();
		const text = JSON.stringify(state);
		if (text === this.lastPersisted) return;
		this.lastPersisted = text;
		this.host.persistState(state);
	}

	// --- relay events (keyed by endpoint: one connection, one X25519 pair) ------------------------------------

	private kem(endpoint: string): KemKeeper {
		let entry = this.kems.get(endpoint);
		if (!entry) {
			entry = { keeper: new KemKeeper(() => this.clock.now()), timer: undefined };
			this.kems.set(endpoint, entry);
			this.scheduleKemRotation(endpoint);
		}
		return entry.keeper;
	}

	private scheduleKemRotation(endpoint: string): void {
		const entry = this.kems.get(endpoint);
		if (!entry) return;
		this.clock.clearTimeout(entry.timer);
		entry.timer = this.clock.setTimeout(() => this.rotateKem(endpoint), entry.keeper.untilRotation());
	}

	/** New X25519 pair for `endpoint`, new certificates, new `join` for each xshell on it (§3). */
	private rotateKem(endpoint: string): void {
		this.kem(endpoint).rotate();
		this.scheduleKemRotation(endpoint);
		this.publishEndpoint(endpoint);
	}

	private onUp(endpoint: string): void {
		const entry = this.kems.get(endpoint);
		if (entry) {
			entry.keeper.rotate();
			this.scheduleKemRotation(endpoint);
		} else {
			this.kem(endpoint);
		}
		if (this.everUp.has(endpoint)) this.host.notify(`xshell : relai ${endpoint} reconnecté`, "info");
		this.everUp.add(endpoint);
		this.publishEndpoint(endpoint);
		this.reofferInvites(endpoint);
		this.settleConnectWaiters(endpoint, { ok: true });
	}

	private onDown(endpoint: string, reason: string): void {
		for (const m of this.all()) if (m.endpoint === endpoint) m.peers.resetOnline([]);
		this.host.notify(`xshell : connexion au relai ${endpoint} perdue (${reason}) ; reconnexion automatique`, "warning");
	}

	private onProblem(endpoint: string, code: string, message: string): void {
		const text = `${code} — ${message}`;
		// A create/join waiting on this endpoint reports the problem itself.
		let answered = this.settleConnectWaiters(endpoint, { ok: false, error: text });
		for (const m of this.all()) {
			if (m.endpoint === endpoint) answered = this.settleFirst(m.xshellId, { ok: false, error: text }) || answered;
		}
		if (!answered) this.host.notify(`xshell : relai ${endpoint} : ${text}`, "error");
	}

	/** Hands `result` to the create/join waiting on `xshellId`, if any. */
	private settleFirst(xshellId: string, result: PublishResult): boolean {
		const waiter = this.firstPublish.get(xshellId);
		if (!waiter) return false;
		this.firstPublish.delete(xshellId);
		waiter.resolve(result);
		return true;
	}

	private onReplaced(endpoint: string, xshellId: string): void {
		const m = this.memberships.get(xshellId);
		if (!m || m.endpoint !== endpoint) return;
		m.suspended = true;
		this.host.toolsChanged();
		this.host.notify(
			`xshell « ${m.name} » : une autre connexion a repris l'identité de cette session (autre processus omp sur la même session ?). Membre suspendu ; /xshell join <clé> pour le reprendre.`,
			"warning",
		);
	}

	private onPresence(endpoint: string, frame: PresenceFrame): void {
		const m = this.memberships.get(frame.xshell_id);
		if (!m || m.endpoint !== endpoint || frame.fp === m.fp) return;
		if (!frame.online) {
			m.peers.setOnline(frame.fp, false);
			return;
		}
		if (!frame.cert_box) return;
		try {
			m.peers.accept(readCertBox(m, frame.fp, frame.cert_box, new Date(this.clock.now())));
			m.peers.setOnline(frame.fp, true);
		} catch (error) {
			this.rejectedCertBox(m, frame.fp, error);
		}
	}

	private rejectedCertBox(m: Membership, fp: string, error: unknown): void {
		const code = error instanceof XshellCryptoError ? error.code : "internal";
		this.audit.log(m.xshellId, { event: "rejected", reason: `cert_box: ${code}`, peer_fp: fp, ...this.host.sessionRef() });
	}

	// --- publication ----------------------------------------------------------------------------------------

	private publishEndpoint(endpoint: string): void {
		for (const m of this.all()) {
			if (m.endpoint === endpoint) void this.publishAndReport(m);
		}
	}

	private async publishAndReport(m: Membership): Promise<void> {
		const result = await this.publish(m);
		if (this.settleFirst(m.xshellId, result)) return;
		if (!result.ok) this.host.notify(`xshell « ${m.name} » : publication impossible : ${result.error}`, "error");
	}

	/** Signs a certificate with the current X25519 key and `join`s (§6.3), then refreshes the member list. */
	async publish(m: Membership): Promise<PublishResult> {
		const identity = this.identity;
		if (!identity || m.suspended || this.memberships.get(m.xshellId) !== m) return { ok: false, error: "membre inactif" };
		try {
			const cert = issueCert(m, identity, this.kem(m.endpoint).pub, this.clock.now());
			m.cert = cert;
			this.store.updateShell(m.xshellId, f => {
				const rec = f.members[m.fp];
				if (!rec) return false;
				rec.cert = cert;
			});
			await this.transport.join(m.endpoint, m.xshellId, m.fp, sealCertBox(membershipGroupKey(m), m.xshellId, cert));
		} catch (error) {
			return { ok: false, error: errorText(error) };
		}
		await this.refreshMembers(m);
		return { ok: true };
	}

	/** Asks the relay who is connected and updates certificates and presence. Best effort. */
	async refreshMembers(m: Membership): Promise<void> {
		try {
			const frames = await this.transport.list(m.endpoint, m.xshellId);
			const online = new Set<string>();
			for (const frame of frames) {
				if (frame.fp === m.fp) continue;
				try {
					m.peers.accept(readCertBox(m, frame.fp, frame.cert_box, new Date(this.clock.now())));
					online.add(frame.fp);
				} catch (error) {
					this.rejectedCertBox(m, frame.fp, error);
				}
			}
			m.peers.resetOnline(online);
		} catch {
			// Relay unreachable: keep what we know.
		}
	}

	async refreshAll(): Promise<void> {
		await Promise.all(this.all().filter(m => !m.suspended).map(m => this.refreshMembers(m)));
	}

	// --- building memberships --------------------------------------------------------------------------------

	private savePeers(xshellId: string, peers: PeerBook): void {
		this.store.updateShell(xshellId, file => {
			let changed = false;
			for (const [fp, cert] of Object.entries(peers.snapshot())) {
				const known = file.peers[fp];
				if (!known || known.body.issued_at < cert.body.issued_at) {
					file.peers[fp] = cert;
					changed = true;
				}
			}
			return changed;
		});
	}

	private build(file: ShellFile, fp: string): Membership {
		const record = file.members[fp];
		if (!record) throw new UserError("membre inconnu dans le fichier xshell");
		const key = parseShellKey(record.key);
		const peers = new PeerBook(file.peers, () => this.savePeers(file.xshell_id, peers));
		const m: Membership = {
			xshellId: file.xshell_id,
			name: file.name,
			relay: file.relay,
			endpoint: relayUrl(file.relay, !file.notls),
			fp,
			key,
			alias: record.alias,
			autoAlias: record.autoAlias === true,
			role: record.role,
			policy: record.policy,
			peers,
			suspended: false,
		};
		if (record.cert) m.cert = record.cert;
		return m;
	}

	/** Registers the membership and publishes it as soon as the relay connection is up. */
	private attach(m: Membership): void {
		const previous = this.memberships.get(m.xshellId);
		this.memberships.set(m.xshellId, m);
		this.transport.acquire(m.endpoint);
		// Release after acquiring: the connection must survive a replacement on the same endpoint.
		if (previous) this.transport.release(previous.endpoint);
		if (this.transport.isUp(m.endpoint)) void this.publishAndReport(m);
		this.startPruning();
		this.host.toolsChanged();
	}

	/** Routes the next publication result for `xshellId` (or a relay problem) to the caller instead of a notification. */
	private expectFirst(xshellId: string): Promise<PublishResult> {
		const { promise, resolve } = Promise.withResolvers<PublishResult>();
		this.firstPublish.set(xshellId, { promise, resolve });
		return promise;
	}

	private startPruning(): void {
		if (this.pruneTimer !== undefined) return;
		const tick = () => {
			this.inbox.pruneExpired();
			this.pruneTimer = this.clock.setTimeout(tick, PRUNE_INTERVAL_MS);
		};
		this.pruneTimer = this.clock.setTimeout(tick, PRUNE_INTERVAL_MS);
	}

	/**
	 * create/join/rotate are atomic: unless the relay accepts the first publication within the wait, the membership
	 * and the xshell file go back to `rollback` (nothing, for a creation) and the command fails.
	 */
	private async publishOrRollback(
		m: Membership,
		first: Promise<PublishResult>,
		rollback: { previous: Membership | undefined; file: ShellFile | undefined },
	): Promise<void> {
		const timer = this.clock.setTimeout(
			() => this.settleFirst(m.xshellId, { ok: false, error: `relai ${m.relay} injoignable (aucune réponse en ${FIRST_PUBLISH_WAIT_MS / 1000} s)` }),
			FIRST_PUBLISH_WAIT_MS,
		);
		const result = await first;
		this.clock.clearTimeout(timer);
		if (result.ok) return;
		if (this.transport.isUp(m.endpoint)) await this.transport.leave(m.endpoint, m.xshellId).catch(() => undefined);
		const { previous, file } = rollback;
		if (previous) {
			this.attach(previous); // swaps back and releases m's endpoint
		} else {
			this.memberships.delete(m.xshellId);
			this.inbox.reset(m.xshellId);
			this.transport.release(m.endpoint);
			this.host.toolsChanged();
		}
		this.dropKemIfUnused(m.endpoint);
		if (file) this.store.writeShell(file);
		else this.store.removeShell(m.xshellId);
		this.persist();
		throw new UserError(result.error);
	}

	private ensureIdentity(): Identity {
		this.identity ??= createIdentity(this.store);
		return this.identity;
	}

	/** Default alias (§3): the omp session name made alias-safe, else the start of the fingerprint. */
	private sessionAlias(fp: string): string {
		return aliasFromSessionName(this.host.sessionName()) ?? defaultAlias(fp);
	}

	/**
	 * The omp session was renamed (or may have been): memberships whose alias follows the session name take the
	 * new one and republish their certificate, so the other members see it (§3). No-op when nothing changed.
	 */
	syncSessionName(): void {
		const changed: Membership[] = [];
		for (const m of this.all()) {
			if (!m.autoAlias) continue;
			const alias = this.sessionAlias(m.fp);
			if (alias === m.alias) continue;
			m.alias = alias;
			this.store.updateShell(m.xshellId, f => {
				const rec = f.members[m.fp];
				if (!rec) return false;
				rec.alias = alias;
			});
			changed.push(m);
		}
		if (changed.length === 0) return;
		// A membership whose relay is down republishes with the new alias when it reconnects (onUp).
		for (const m of changed) if (!m.suspended && this.transport.isUp(m.endpoint)) void this.publishAndReport(m);
		this.host.notify(`xshell : alias « ${changed[0]!.alias} » dans ${changed.map(m => `« ${m.name} »`).join(", ")}`, "info");
	}

	private checkFormats(name: string | undefined, alias: string | undefined): void {
		if (name !== undefined && !NAME_RE.test(name)) throw new UserError("nom invalide : 1 à 32 caractères parmi A-Z a-z 0-9 _ -");
		if (alias !== undefined && !NAME_RE.test(alias)) throw new UserError("alias invalide : 1 à 32 caractères parmi A-Z a-z 0-9 _ -");
	}

	/** `xshellId` absent: a creation; present: a join of that xshell, which may keep its own name. */
	private checkNames(name: string, alias: string, xshellId?: string): void {
		this.checkFormats(name, alias);
		const other = this.store.listShells().find(s => s.name === name && s.xshell_id !== xshellId);
		if (!other) return;
		const owner = this.byName(name) ? "à laquelle cette session appartient" : "tenue par une autre session de cette machine";
		if (xshellId === undefined) {
			throw new UserError(
				`le nom « ${name} » est déjà pris sur cette machine par la xshell ${other.xshell_id} (${owner}) : ` +
					`${this.byName(name) ? "" : `/xshell join ${name} pour la rejoindre, ou `}choisis un autre nom`,
			);
		}
		throw new UserError(
			`le nom « ${name} » désigne déjà une autre xshell sur cette machine (${other.xshell_id}, ${owner}) : rejoins avec --name <autre-nom>`,
		);
	}

	// --- commands -------------------------------------------------------------------------------------------

	async createShell(options: {
		name: string;
		relay: string;
		notls?: boolean;
		alias?: string;
		role: string;
		policy: Policy;
	}): Promise<JoinOutcome & { keys: ShellKeys }> {
		const identity = this.ensureIdentity();
		const alias = options.alias ?? this.sessionAlias(identity.fp);
		this.checkNames(options.name, alias);
		let generated: { ask: ShellKey; answer: ShellKey };
		try {
			generated = generateShell(options.relay, options.name);
		} catch (error) {
			throw new UserError(errorText(error));
		}
		const keys: ShellKeys = { ask: formatShellKey(generated.ask), answer: formatShellKey(generated.answer) };
		const file: ShellFile = {
			v: 1,
			xshell_id: generated.ask.xshellId,
			name: options.name,
			relay: options.relay,
			...(options.notls ? { notls: true as const } : {}),
			members: {
				[identity.fp]: {
					key: keys.ask,
					alias,
					...(options.alias ? {} : { autoAlias: true as const }),
					role: sanitizeRole(options.role),
					policy: options.policy,
				},
			},
			peers: {},
		};
		this.store.writeShell(file);
		const m = this.build(file, identity.fp);
		const first = this.expectFirst(m.xshellId);
		this.attach(m);
		this.persist();
		await this.publishOrRollback(m, first, { previous: undefined, file: undefined });
		return { membership: m, keys };
	}

	async joinShell(options: {
		key: string;
		name?: string;
		alias?: string;
		role: string;
		policy: Policy;
		notls?: boolean;
	}): Promise<JoinOutcome> {
		let key: ShellKey;
		try {
			key = parseShellKey(options.key);
		} catch (error) {
			throw new UserError(error instanceof XshellCryptoError ? error.message : "clé xshell invalide");
		}
		const identity = this.ensureIdentity();
		const existing = this.store.readShell(key.xshellId);
		const before = existing ? structuredClone(existing) : undefined;
		const name = options.name ?? existing?.name ?? key.name;
		const alias = options.alias ?? this.sessionAlias(identity.fp);
		this.checkNames(name, alias, key.xshellId);
		const previousKey = existing?.members[identity.fp]?.key;
		const keyChanged = previousKey !== undefined && previousKey !== formatShellKey(key);
		const file: ShellFile = existing ?? { v: 1, xshell_id: key.xshellId, name, relay: key.relay, members: {}, peers: {} };
		file.name = name;
		file.relay = key.relay;
		// The latest join decides how this machine reaches the relay, for every local member of the xshell.
		if (options.notls) file.notls = true;
		else delete file.notls;
		// A different key for the same xshell (after `rotate`) invalidates every cached certificate.
		if (existing && (keyChanged || existing.relay !== key.relay)) file.peers = {};
		const record: MemberRecord = {
			key: formatShellKey(key),
			alias,
			...(options.alias ? {} : { autoAlias: true as const }),
			role: sanitizeRole(options.role),
			policy: options.policy,
		};
		file.members[identity.fp] = record;
		this.store.writeShell(file);
		const m = this.build(file, identity.fp);
		const previous = this.memberships.get(key.xshellId);
		const first = this.expectFirst(m.xshellId);
		this.attach(m);
		this.persist();
		await this.publishOrRollback(m, first, { previous, file: before });
		return { membership: m };
	}

	/**
	 * `join <uuid>`: asks the master for the xs2 key through the relay (temporary connection) with a fresh X25519
	 * pair, declaring alias and role; the master confirms before answering. Then runs the regular, atomic
	 * `joinShell` with the key and the same alias. The invitation is single use: once confirmed or refused it is gone.
	 */
	async joinWithInvite(options: {
		code: string;
		relay: string;
		name?: string;
		alias?: string;
		role: string;
		policy: Policy;
		notls?: boolean;
	}): Promise<JoinOutcome> {
		let secrets: { inviteId: string; key: Uint8Array };
		try {
			secrets = inviteSecrets(options.code);
		} catch {
			throw new UserError("UUID d'invitation invalide");
		}
		const identity = this.ensureIdentity();
		const alias = options.alias ?? this.sessionAlias(identity.fp);
		const role = sanitizeRole(options.role);
		// Do not burn the invitation on a mistake the options already reveal.
		this.checkFormats(options.name, alias);
		let endpoint: string;
		try {
			endpoint = relayUrl(options.relay, !options.notls);
		} catch (error) {
			throw new UserError(errorText(error));
		}
		// The claim connection stays referenced until `joinShell` holds its own: no needless reconnection.
		this.transport.acquire(endpoint);
		try {
			await this.waitConnected(endpoint, options.relay);
			const ephemeral = generateKemPair();
			let shellKey: string;
			try {
				let box: string;
				try {
					box = await this.transport.claim(
						endpoint,
						secrets.inviteId,
						b64uEncode(ephemeral.pub),
						sealInviteRequest(secrets.key, secrets.inviteId, ephemeral.pub, { alias, role }),
					);
				} catch (error) {
					if (error instanceof RelayError && error.code === "no_invite") {
						throw new UserError("invitation inconnue, expirée, déjà utilisée, refusée par le master, ou master hors ligne");
					}
					if (error instanceof RelayError && error.code === "timeout") {
						throw new UserError("le master n'a pas confirmé l'invitation à temps");
					}
					throw new UserError(`invitation impossible : ${errorText(error)}`);
				}
				try {
					shellKey = openInvite(secrets.key, secrets.inviteId, ephemeral.priv, box);
				} catch {
					throw new UserError("invitation illisible : réponse invalide du master");
				}
			} finally {
				ephemeral.priv.fill(0);
			}
			try {
				return await this.joinShell({
					key: shellKey,
					role,
					policy: options.policy,
					// Without --as, joinShell derives the same alias and keeps it following the session name.
					...(options.alias ? { alias: options.alias } : {}),
					...(options.notls ? { notls: true } : {}),
					...(options.name ? { name: options.name } : {}),
				});
			} catch (error) {
				if (error instanceof UserError) {
					throw new UserError(`${error.message} (l'invitation est consommée : demande-en une nouvelle au master)`);
				}
				throw error;
			}
		} finally {
			this.transport.release(endpoint);
			this.dropKemIfUnused(endpoint);
		}
	}

	/** Waits until the (already acquired) connection to `endpoint` is up; a relay problem or 10 s without one is an error. */
	private async waitConnected(endpoint: string, relay: string): Promise<void> {
		if (this.transport.isUp(endpoint)) return;
		const { promise, resolve } = Promise.withResolvers<PublishResult>();
		const waiters = this.connectWaiters.get(endpoint) ?? new Set();
		waiters.add(resolve);
		this.connectWaiters.set(endpoint, waiters);
		const timer = this.clock.setTimeout(
			() => resolve({ ok: false, error: `relai ${relay} injoignable (aucune réponse en ${INVITE_CONNECT_WAIT_MS / 1000} s)` }),
			INVITE_CONNECT_WAIT_MS,
		);
		const result = await promise;
		this.clock.clearTimeout(timer);
		waiters.delete(resolve);
		if (waiters.size === 0) this.connectWaiters.delete(endpoint);
		if (!result.ok) throw new UserError(result.error);
	}

	/** Hands `result` to every `join <uuid>` waiting on `endpoint`; true if there was any. */
	private settleConnectWaiters(endpoint: string, result: PublishResult): boolean {
		const waiters = this.connectWaiters.get(endpoint);
		if (!waiters || waiters.size === 0) return false;
		for (const resolve of [...waiters]) resolve(result);
		return true;
	}

	/**
	 * Any master: tells every member online that the xshell is destroyed (signed `destroy` envelope), then
	 * leaves it and deletes the local file for every session of this machine. Members offline keep their copy.
	 */
	async destroyShell(name: string): Promise<{ notified: number; failed: number; offline: number }> {
		const m = this.requireMember(name);
		if (m.key.rank !== "A") throw new UserError("seul un master peut détruire la xshell");
		await this.refreshMembers(m);
		const peers = m.peers.views(m.fp, this.clock.now());
		const online = peers.filter(p => p.online);
		if (this.host.hasUI()) {
			const confirmed = await this.host.confirm(
				`Détruire la xshell « ${name} » ?`,
				[
					`${online.length} membre(s) en ligne la quitteront et supprimeront leur copie${online.length > 0 ? ` : ${online.map(p => p.alias).join(", ")}` : ""}.`,
					`${peers.length - online.length} membre(s) hors ligne garderont la leur (pas de boîte aux lettres).`,
					"Le fichier local est supprimé pour toutes les sessions de cette machine. Irréversible.",
				].join("\n"),
			);
			if (!confirmed) throw new UserError("destruction annulée");
		}
		let notified = 0;
		for (const peer of online) {
			try {
				await this.inbox.sendDestroy(m, peer.fp);
				notified++;
			} catch {
				// Gone meanwhile: counted as not notified.
			}
		}
		this.audit.log(m.xshellId, { event: "destroy_sent", status: `${notified}/${online.length}`, ...this.host.sessionRef() });
		await this.leaveShell(name);
		this.store.removeShell(m.xshellId);
		return { notified, failed: online.length - notified, offline: peers.length - online.length };
	}

	/** A verified master destroyed the xshell: leave it (this session's record; the file goes with the last one). */
	private onDestroyed(m: Membership, byAlias: string, byFp: string): void {
		if (this.memberships.get(m.xshellId) !== m) return;
		this.host.notify(`xshell « ${m.name} » détruite par le master ${byAlias} (${byFp}) : quittée et supprimée de cette session`, "warning");
		void this.leaveShell(m.name).catch(() => undefined);
	}

	async leaveShell(name: string): Promise<void> {
		const m = this.byName(name);
		if (!m) {
			this.leaveUnloaded(name);
			return;
		}
		// No grant may slip out while the relay answers the leave.
		this.forgetInvitesOf(m.xshellId);
		try {
			if (this.transport.isUp(m.endpoint) && !m.suspended) await this.transport.leave(m.endpoint, m.xshellId);
		} catch {
			// The relay forgets us when the connection closes anyway.
		}
		this.inbox.reset(m.xshellId);
		this.memberships.delete(m.xshellId);
		this.firstPublish.delete(m.xshellId);
		this.transport.release(m.endpoint);
		this.dropKemIfUnused(m.endpoint);
		const file = this.store.readShell(m.xshellId);
		if (file) {
			delete file.members[m.fp];
			if (Object.keys(file.members).length === 0) this.store.removeShell(m.xshellId);
			else this.store.writeShell(file);
		}
		this.persist();
		this.host.toolsChanged();
	}

	/**
	 * `leave` for a xshell this session could not load, e.g. a key in an obsolete format (`xs1`): the file is
	 * removed when no member key in it can be read any more. A readable file belongs to other local sessions.
	 */
	private leaveUnloaded(name: string): void {
		const file = this.store.listShells().find(s => s.name === name);
		if (!file) throw new UserError(`xshell inconnue : ${name}`);
		const readable = Object.values(file.members).some(rec => {
			try {
				parseShellKey(rec.key);
				return true;
			} catch {
				return false;
			}
		});
		if (readable) throw new UserError(`cette session n'est pas membre de « ${name} » (/xshell join ${name} pour la rejoindre)`);
		this.store.removeShell(file.xshell_id);
		this.persist();
	}

	private dropKemIfUnused(endpoint: string): void {
		if (this.all().some(m => m.endpoint === endpoint)) return;
		const entry = this.kems.get(endpoint);
		if (!entry) return;
		this.clock.clearTimeout(entry.timer);
		entry.keeper.wipe();
		this.kems.delete(endpoint);
	}

	/**
	 * The membership `name` of this session. A xshell this session has not joined, but that another local session
	 * holds (its file is on disk), gets a hint: membership is per omp session (§7.5).
	 */
	requireMember(name: string): Membership {
		const m = this.byName(name);
		if (m) return m;
		if (this.localFile(name)) {
			throw new UserError(`cette session n'est pas membre de « ${name} », qui existe sur cette machine : /xshell join ${name} pour la rejoindre`);
		}
		throw new UserError(`xshell inconnue : ${name}`);
	}

	private localFile(name: string): ShellFile | undefined {
		return this.store.listShells().find(s => s.name === name);
	}

	/** Names of the xshells of this machine this session has not joined (`join <nom>` candidates). */
	localNames(): string[] {
		return this.store
			.listShells()
			.map(s => s.name)
			.filter(name => !this.byName(name));
	}

	/**
	 * `join <nom>`: joins, with this session's own identity, a xshell another local session already belongs to,
	 * using the best key found in its file (ask if any, else answer). The key never leaves the machine.
	 */
	async joinLocal(options: { name: string; alias?: string; role: string; policy: Policy; notls?: boolean }): Promise<JoinOutcome> {
		if (this.byName(options.name)) throw new UserError(`cette session est déjà membre de « ${options.name} »`);
		const file = this.localFile(options.name);
		if (!file) throw new UserError(`xshell inconnue : ${options.name} (ni clé xs2:, ni UUID d'invitation, ni xshell de cette machine)`);
		let best: ShellKey | undefined;
		for (const rec of Object.values(file.members)) {
			try {
				const key = parseShellKey(rec.key);
				if (!best || (key.rank === "A" && best.rank === "S")) best = key;
			} catch {
				// Obsolete or corrupt key: try the next member.
			}
		}
		if (!best) throw new UserError(`« ${options.name} » n'a aucune clé lisible (format xs1 ?) : /xshell leave ${options.name} puis recréer la xshell`);
		return this.joinShell({
			key: formatShellKey(best),
			name: file.name,
			role: options.role,
			policy: options.policy,
			notls: options.notls === true || file.notls === true,
			...(options.alias ? { alias: options.alias } : {}),
		});
	}

	setPolicy(name: string, policy: Policy): void {
		const m = this.requireMember(name);
		m.policy = policy;
		this.store.updateShell(m.xshellId, f => {
			const rec = f.members[m.fp];
			if (!rec) return false;
			rec.policy = policy;
		});
	}

	/** Any master: new rank seeds, same xshell_id (§4.3). Other local memberships are dropped (their key is void). */
	async rotateShell(name: string): Promise<{ keys: ShellKeys; dropped: number }> {
		const m = this.requireMember(name);
		if (m.key.rank !== "A") throw new UserError("seul un master peut régénérer les clés de la xshell");
		// The invitations carry the keys about to be replaced.
		this.forgetInvitesOf(m.xshellId);
		const fresh = generateShell(m.relay, m.name);
		const ask = { ...fresh.ask, xshellId: m.xshellId };
		const keys: ShellKeys = { ask: formatShellKey(ask), answer: formatShellKey(answerKey(ask)) };
		let dropped = 0;
		const file = this.store.readShell(m.xshellId);
		if (!file) throw new UserError("fichier xshell introuvable");
		const before = structuredClone(file);
		const own = file.members[m.fp];
		if (!own) throw new UserError("membre introuvable dans le fichier xshell");
		dropped = Object.keys(file.members).length - 1;
		file.members = { [m.fp]: { ...own, key: keys.ask } };
		file.peers = {};
		this.store.writeShell(file);
		const rebuilt = this.build(file, m.fp);
		const first = this.expectFirst(rebuilt.xshellId);
		this.attach(rebuilt);
		this.persist();
		await this.publishOrRollback(rebuilt, first, { previous: m, file: before });
		return { keys, dropped };
	}

	/** Keys the user may re-display (§7.1): a master both (its key holds both seeds), a slave its answer key. */
	keysOf(m: Membership): { label: string; key: string }[] {
		if (m.key.rank === "S") return [{ label: "clé answer (slave)", key: formatShellKey(m.key) }];
		return [
			{ label: "clé ask (master)", key: formatShellKey(m.key) },
			{ label: "clé answer (slave)", key: formatShellKey(answerKey(m.key)) },
		];
	}

	// --- invitations (master side) ---------------------------------------------------------------------------

	/**
	 * Two single-use invitations for xshell `name` (one per rank), valid 5 minutes, offered to the relay. The relay
	 * never sees the UUIDs: it routes by `invite_id` and relays opaque, UUID-sealed requests and boxes. Each claim
	 * is confirmed by the user before the key leaves.
	 */
	async createInvites(name: string): Promise<{ membership: Membership; master: string; slave: string }> {
		const m = this.requireMember(name);
		if (m.key.rank !== "A") throw new UserError("seul un master peut inviter");
		if (m.suspended) throw new UserError(`xshell « ${name} » suspendue : /xshell join <clé> pour la reprendre avant d'inviter`);
		if (!this.transport.isUp(m.endpoint)) throw new UserError(`relai ${m.relay} non connecté : invitation impossible pour le moment`);
		const codes: Record<Rank, string> = { A: newInviteCode(), S: newInviteCode() };
		const ids: string[] = [];
		for (const rank of ["A", "S"] as const) {
			const { inviteId, key } = inviteSecrets(codes[rank]);
			ids.push(inviteId);
			this.invites.set(inviteId, {
				xshellId: m.xshellId,
				rank,
				key,
				endpoint: m.endpoint,
				expiresAt: this.clock.now() + INVITE_TTL_MS,
				timer: this.clock.setTimeout(() => this.forgetInvite(inviteId, true), INVITE_TTL_MS),
				confirming: false,
			});
		}
		try {
			for (const id of ids) await this.transport.offer(m.endpoint, id);
		} catch (error) {
			for (const id of ids) this.forgetInvite(id, true);
			throw new UserError(`invitation impossible : ${errorText(error)}`);
		}
		if (ids.some(id => !this.invites.has(id))) {
			// leave/rotate ran while the relay was answering.
			for (const id of ids) this.forgetInvite(id, true);
			throw new UserError(`xshell « ${name} » modifiée pendant la création des invitations : recommence`);
		}
		for (const rank of ["A", "S"] as const) {
			this.audit.log(m.xshellId, { event: "invite_created", rank: rankLabel(rank), ...this.host.sessionRef() });
		}
		return { membership: m, master: codes.A, slave: codes.S };
	}

	/** Forgets an invitation (single use, expiry, leave, rotate); `withdraw` also removes the relay's offer, best effort. */
	private forgetInvite(inviteId: string, withdraw: boolean): void {
		const entry = this.invites.get(inviteId);
		if (!entry) return;
		this.invites.delete(inviteId);
		this.clock.clearTimeout(entry.timer);
		if (withdraw) void this.transport.withdraw(entry.endpoint, inviteId).catch(() => undefined);
	}

	private forgetInvitesOf(xshellId: string): void {
		for (const [id, entry] of [...this.invites]) if (entry.xshellId === xshellId) this.forgetInvite(id, true);
	}

	/** The relay forgets offers with the connection: after a reconnection, offer the still valid ones again. */
	private reofferInvites(endpoint: string): void {
		for (const [id, entry] of this.invites) {
			if (entry.endpoint === endpoint) void this.transport.offer(endpoint, id).catch(() => undefined);
		}
	}

	private async refuseClaim(endpoint: string, claim: string): Promise<void> {
		await this.transport.refuse(endpoint, claim).catch(() => undefined);
	}

	/** The ask key of the xshell an invitation belongs to, if this session can still hand it out. */
	private issuerKey(entry: InviteEntry, endpoint: string): AskKey | undefined {
		const m = this.memberships.get(entry.xshellId);
		if (!m || m.endpoint !== endpoint || m.key.rank !== "A" || m.suspended) return undefined;
		return m.key;
	}

	private confirmInvite(title: string, message: string): Promise<boolean> {
		// Any failure of the dialog counts as a refusal.
		const decision = this.inviteConfirmChain.then(() => this.host.confirm(title, message)).catch(() => false);
		this.inviteConfirmChain = decision;
		return decision;
	}

	/**
	 * A joiner claims one of our offers. Only a request sealed with the UUID is considered; the user then decides
	 * on the declared alias and role. Granting consumes the invitation (single use), and so does a refusal.
	 */
	private async onClaimRequest(endpoint: string, inviteId: string, claim: string, epk: string, req: string): Promise<void> {
		const entry = this.invites.get(inviteId);
		// Unknown, expired, or already being confirmed: refuse without touching the invitation in progress.
		if (!entry || entry.endpoint !== endpoint || entry.confirming) {
			await this.refuseClaim(endpoint, claim);
			return;
		}
		const rank = rankLabel(entry.rank);
		const refused = async (reason: string, declared?: string, status = "refused"): Promise<void> => {
			this.audit.log(entry.xshellId, {
				event: "invite_refused",
				rank,
				status,
				reason,
				...(declared ? { peer_alias: declared } : {}),
				...this.host.sessionRef(),
			});
			await this.refuseClaim(endpoint, claim);
		};
		if (this.clock.now() >= entry.expiresAt) {
			this.forgetInvite(inviteId, true);
			await refused("expirée");
			return;
		}
		let epkJ: Uint8Array;
		let hello: { alias: string; role: string };
		try {
			epkJ = b64uDecode(epk, 32);
			hello = openInviteRequest(entry.key, inviteId, epkJ, req);
		} catch {
			// Not sealed with the UUID (a forged or corrupted request): the invitation stays valid.
			await refused("demande illisible");
			return;
		}
		if (!this.issuerKey(entry, endpoint)) {
			this.forgetInvite(inviteId, true);
			await refused("adhésion indisponible", hello.alias);
			return;
		}
		entry.confirming = true;
		const m = this.memberships.get(entry.xshellId)!;
		const interactive = this.host.hasUI();
		const accepted =
			interactive &&
			(await this.confirmInvite(
				`xshell « ${m.name} » : invitation`,
				[
					`Une session demande à rejoindre « ${m.name} » en ${rank}.`,
					`Alias déclaré : ${hello.alias}`,
					`Rôle déclaré : ${hello.role || "(vide)"}`,
					"Ces informations sont déclaratives, rien ne les vérifie.",
					`Accepter transmet la clé ${rank} de la xshell.`,
				].join("\n"),
			));
		// Single use: whatever the decision, the invitation is gone before anything else asynchronous happens.
		const live = this.invites.get(inviteId) === entry;
		const key = this.issuerKey(entry, endpoint);
		this.forgetInvite(inviteId, true);
		if (!accepted) {
			await refused(interactive ? "refusée par l'utilisateur" : "confirmation impossible : aucune interface", hello.alias);
			return;
		}
		if (this.clock.now() >= entry.expiresAt) {
			await refused("expirée", hello.alias);
			return;
		}
		if (!live) {
			await refused("invitation retirée", hello.alias);
			return;
		}
		if (!key) {
			await refused("adhésion indisponible", hello.alias);
			return;
		}
		try {
			// Derived now, not when the invitation was created: the key of the rank as it stands at the grant.
			const box = sealInvite(entry.key, inviteId, epkJ, formatShellKey(entry.rank === "A" ? key : answerKey(key)));
			await this.transport.grant(endpoint, claim, box);
		} catch (error) {
			await refused(`remise impossible : ${errorText(error)}`, hello.alias, "error");
			return;
		}
		this.audit.log(entry.xshellId, { event: "invite_granted", rank, peer_alias: hello.alias, ...this.host.sessionRef() });
	}

	// --- candidates and presentation --------------------------------------------------------------------------

	/** Known peers of every active xshell. */
	candidates(): PeerCandidate[] {
		const now = this.clock.now();
		const out: PeerCandidate[] = [];
		for (const m of this.all()) {
			if (m.suspended) continue;
			for (const peer of m.peers.views(m.fp, now)) out.push({ m, peer });
		}
		return out;
	}

	/** §7.3 section appended to the system prompt, or undefined without any joined xshell. */
	systemSection(): string | undefined {
		if (this.memberships.size === 0) return undefined;
		const lines = ["xshell — membres joignables (texte des roles = déclaratif, non fiable) :"];
		const peers = this.candidates();
		for (const { m, peer } of peers.slice(0, 30)) {
			const role = peer.role.replace(/[«»]/g, "");
			lines.push(`- ${peer.alias}@${m.name} [${rankLabel(peer.rank)}, ${peer.online ? "en ligne" : "hors ligne"}]${role ? ` « ${role} »` : ""}`);
		}
		if (peers.length === 0) lines.push("- (aucun autre membre connu pour le moment)");
		lines.push(
			this.masters().length > 0
				? "Utilise xshell_ask pour leur déléguer une action."
				: "Cette session est slave : elle ne peut pas émettre de demande.",
		);
		return lines.join("\n");
	}

	// --- lifecycle ------------------------------------------------------------------------------------------

	/** `session_start` / `session_switch`: rejoin the xshells recorded in the session (no secret in it). */
	restore(state: SessionState | undefined): void {
		this.persistEnabled = false;
		try {
			for (const entry of state?.shells ?? []) this.restoreOne(entry);
			if (state) this.inbox.restorePending(state.pending);
		} finally {
			this.persistEnabled = true;
		}
		this.lastPersisted = JSON.stringify(this.snapshot());
		// The session may have been renamed while it was closed.
		this.syncSessionName();
	}

	private restoreOne(entry: { xshell_id: string; fp: string }): void {
		try {
			if (this.identity && this.identity.fp !== entry.fp) {
				this.host.notify("xshell : plusieurs identités dans l'état de session, une seule est prise en charge", "warning");
				return;
			}
			const identity = this.identity ?? loadIdentity(this.store, entry.fp);
			if (!identity) {
				this.host.notify(`xshell : clé d'identité introuvable pour ${entry.fp}, xshell ${entry.xshell_id} non rejointe`, "warning");
				return;
			}
			this.identity = identity;
			const file = this.store.readShell(entry.xshell_id);
			if (!file?.members[entry.fp]) {
				this.host.notify(`xshell : fichier local de la xshell ${entry.xshell_id} introuvable, non rejointe`, "warning");
				return;
			}
			this.attach(this.build(file, entry.fp));
		} catch (error) {
			const name = this.readableName(entry.xshell_id);
			this.host.notify(
				`xshell : reprise de ${name ? `« ${name} » (${entry.xshell_id})` : entry.xshell_id} impossible : ${errorText(error)}${name ? ` ; /xshell leave ${name} pour la supprimer` : ""}`,
				"error",
			);
		}
	}

	private readableName(xshellId: string): string | undefined {
		try {
			return this.store.readShell(xshellId)?.name;
		} catch {
			return undefined;
		}
	}

	/** Disconnects everything and forgets the in-memory state (session switch, shutdown). Never blocks. */
	detachAll(): void {
		this.transport.closeAll();
		for (const entry of this.kems.values()) {
			this.clock.clearTimeout(entry.timer);
			entry.keeper.wipe();
		}
		for (const entry of this.invites.values()) this.clock.clearTimeout(entry.timer);
		this.invites.clear();
		for (const waiters of this.connectWaiters.values()) for (const resolve of [...waiters]) resolve({ ok: false, error: "session fermée" });
		this.kems.clear();
		if (this.pruneTimer !== undefined) this.clock.clearTimeout(this.pruneTimer);
		this.pruneTimer = undefined;
		this.persistEnabled = false;
		this.inbox.reset();
		this.persistEnabled = true;
		this.memberships.clear();
		this.firstPublish.clear();
		this.everUp.clear();
		this.identity = undefined;
		this.lastPersisted = "";
		this.host.toolsChanged();
	}
}
