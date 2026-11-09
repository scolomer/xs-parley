/**
 * Test support (not shipped logic): fake clock, in-memory relay, fake omp host and a node factory wiring
 * several `XshellSession`s over the fake relay. Real crypto, no network, no omp.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Audit } from "./audit.ts";
import { type Envelope, type Kind, type Status, formatTimestamp, newMsgId, sealEnvelope, b64uDecode } from "./crypto.ts";
import type { InjectedMessage, InjectOptions } from "./inbox.ts";
import { loadIdentity, type Membership } from "./keys.ts";
import { type SessionHost, type SessionState, XshellSession } from "./session.ts";
import { Store } from "./store.ts";
import {
	type Clock,
	type MemberFrame,
	type PresenceFrame,
	RelayError,
	type Transport,
	type TransportHandlers,
	relayUrl,
} from "./transport.ts";

/** Endpoint of the `relay.test` relay every fake node uses. */
export const TEST_ENDPOINT = relayUrl("relay.test", true);

export class FakeClock implements Clock {
	private t: number;
	private nextId = 1;
	private readonly timers = new Map<number, { at: number; fn: () => void }>();

	constructor(start: number = Date.now()) {
		this.t = start;
	}

	now(): number {
		return this.t;
	}

	setTimeout(fn: () => void, ms: number): unknown {
		const id = this.nextId++;
		this.timers.set(id, { at: this.t + ms, fn });
		return id;
	}

	clearTimeout(handle: unknown): void {
		this.timers.delete(handle as number);
	}

	/** Moves time forward, firing due timers in order. */
	advance(ms: number): void {
		const target = this.t + ms;
		for (;;) {
			let nextId: number | undefined;
			let nextAt = Number.POSITIVE_INFINITY;
			for (const [id, timer] of this.timers) {
				if (timer.at <= target && timer.at < nextAt) {
					nextAt = timer.at;
					nextId = id;
				}
			}
			if (nextId === undefined) break;
			const timer = this.timers.get(nextId);
			this.timers.delete(nextId);
			this.t = Math.max(this.t, nextAt);
			timer?.fn();
		}
		this.t = target;
	}
}

export async function waitFor(condition: () => boolean, what = "condition", timeoutMs = 3000): Promise<void> {
	const start = Date.now();
	while (!condition()) {
		if (Date.now() - start > timeoutMs) throw new Error(`timeout waiting for ${what}`);
		await Bun.sleep(2);
	}
}

/** Lets in-flight async work (crypto, fake network hops) settle. */
export async function settle(ms = 60): Promise<void> {
	await Bun.sleep(ms);
}

// --- fake relay -------------------------------------------------------------------------------------------

export interface SentFrame {
	from: string;
	xshellId: string;
	to: string;
	env: Envelope;
}

/** The relay's per-connection offer limit (§6.3). */
const MAX_OFFERS = 16;

export class FakeNetwork {
	readonly members = new Map<string, Map<string, { transport: FakeTransport; certBox: string }>>();
	readonly sent: SentFrame[] = [];
	/** `invite_id` → connection that offers it. */
	readonly offers = new Map<string, FakeTransport>();
	/** Pending claims: `claim` → who asked and who holds the offer. */
	readonly claims = new Map<string, { holder: FakeTransport; requester: FakeTransport; resolve(box: string): void; reject(error: Error): void }>();
	private claimCounter = 0;

	group(xshellId: string): Map<string, { transport: FakeTransport; certBox: string }> {
		let g = this.members.get(xshellId);
		if (!g) {
			g = new Map();
			this.members.set(xshellId, g);
		}
		return g;
	}

	nextClaim(): string {
		return `claim${++this.claimCounter}`;
	}

	/** A connection closed: its offers vanish, claims addressed to it fail `no_invite`, claims it made are forgotten. */
	dropConnection(transport: FakeTransport): void {
		for (const [id, holder] of this.offers) if (holder === transport) this.offers.delete(id);
		for (const [claim, entry] of this.claims) {
			if (entry.holder === transport) entry.reject(new RelayError("no_invite", "détenteur parti"));
			if (entry.holder === transport || entry.requester === transport) this.claims.delete(claim);
		}
	}

	offerCount(transport: FakeTransport): number {
		return [...this.offers.values()].filter(t => t === transport).length;
	}
}

export class FakeTransport implements Transport {
	handlers: TransportHandlers | undefined;
	private readonly refs = new Map<string, number>();
	private readonly upRelays = new Set<string>();
	private readonly joined = new Map<string, string>();
	/** When set, connections never come up: the relay refuses them with this message (`unavailable`). */
	refuseConnections: string | undefined;

	constructor(private readonly net: FakeNetwork) {}

	setHandlers(handlers: TransportHandlers): void {
		this.handlers = handlers;
	}

	acquire(relay: string): void {
		const n = (this.refs.get(relay) ?? 0) + 1;
		this.refs.set(relay, n);
		if (n === 1) {
			setTimeout(() => {
				if (!this.refs.has(relay)) return;
				if (this.refuseConnections !== undefined) {
					this.handlers?.problem(relay, "unavailable", this.refuseConnections);
					return;
				}
				this.upRelays.add(relay);
				this.handlers?.up(relay);
			}, 0);
		}
	}

	release(relay: string): void {
		const n = (this.refs.get(relay) ?? 0) - 1;
		if (n > 0) {
			this.refs.set(relay, n);
			return;
		}
		this.refs.delete(relay);
		this.upRelays.delete(relay);
		this.net.dropConnection(this);
	}

	isUp(relay: string): boolean {
		return this.upRelays.has(relay);
	}

	private broadcast(xshellId: string, frame: Omit<PresenceFrame, "xshell_id">, exceptFp: string): void {
		for (const [fp, entry] of this.net.group(xshellId)) {
			if (fp === exceptFp) continue;
			setTimeout(() => entry.transport.handlers?.presence(TEST_ENDPOINT, { xshell_id: xshellId, ...frame }), 0);
		}
	}

	async join(_relay: string, xshellId: string, fp: string, certBox: string): Promise<void> {
		this.net.group(xshellId).set(fp, { transport: this, certBox });
		this.joined.set(xshellId, fp);
		this.broadcast(xshellId, { fp, online: true, cert_box: certBox }, fp);
	}

	async leave(_relay: string, xshellId: string): Promise<void> {
		const fp = this.joined.get(xshellId);
		if (!fp) throw new RelayError("not_joined");
		this.net.group(xshellId).delete(fp);
		this.joined.delete(xshellId);
		this.broadcast(xshellId, { fp, online: false }, fp);
	}

	async list(_relay: string, xshellId: string): Promise<MemberFrame[]> {
		return [...this.net.group(xshellId)].map(([fp, e]) => ({ fp, cert_box: e.certBox }));
	}

	async send(_relay: string, xshellId: string, to: string, env: unknown): Promise<void> {
		const from = this.joined.get(xshellId);
		if (!from) throw new RelayError("not_joined");
		const target = this.net.group(xshellId).get(to);
		if (!target) throw new RelayError("offline", "offline");
		this.net.sent.push({ from, xshellId, to, env: env as Envelope });
		const copy = structuredClone(env);
		setTimeout(() => target.transport.handlers?.deliver(TEST_ENDPOINT, xshellId, copy), 0);
	}

	private requireUp(relay: string): void {
		if (!this.upRelays.has(relay)) throw new RelayError("unavailable", "relai non connecté");
	}

	async offer(relay: string, inviteId: string): Promise<void> {
		this.requireUp(relay);
		const holder = this.net.offers.get(inviteId);
		if (holder && holder !== this) throw new RelayError("bad_frame", "invitation déjà proposée");
		if (!holder && this.net.offerCount(this) >= MAX_OFFERS) throw new RelayError("bad_frame", "trop d'offres");
		this.net.offers.set(inviteId, this);
	}

	async withdraw(relay: string, inviteId: string): Promise<void> {
		this.requireUp(relay);
		if (this.net.offers.get(inviteId) === this) this.net.offers.delete(inviteId);
	}

	async claim(relay: string, inviteId: string, epk: string, req: string): Promise<string> {
		this.requireUp(relay);
		const holder = this.net.offers.get(inviteId);
		if (!holder) throw new RelayError("no_invite", "aucune invitation");
		const claim = this.net.nextClaim();
		const { promise, resolve, reject } = Promise.withResolvers<string>();
		this.net.claims.set(claim, { holder, requester: this, resolve, reject });
		setTimeout(() => holder.handlers?.claimRequest(TEST_ENDPOINT, inviteId, claim, epk, req), 0);
		return promise;
	}

	private takeClaim(relay: string, claim: string) {
		this.requireUp(relay);
		const entry = this.net.claims.get(claim);
		if (!entry || entry.holder !== this) throw new RelayError("no_invite", "demande inconnue");
		this.net.claims.delete(claim);
		return entry;
	}

	async grant(relay: string, claim: string, box: string): Promise<void> {
		this.takeClaim(relay, claim).resolve(box);
	}

	async refuse(relay: string, claim: string): Promise<void> {
		this.takeClaim(relay, claim).reject(new RelayError("no_invite", "refusé"));
	}

	closeAll(): void {
		for (const [xshellId, fp] of this.joined) {
			this.net.group(xshellId).delete(fp);
			this.broadcast(xshellId, { fp, online: false }, fp);
		}
		this.joined.clear();
		this.refs.clear();
		this.upRelays.clear();
		this.net.dropConnection(this);
	}

	/** Simulates a relay restart: connection down (the relay forgets its offers), then up again (new X25519 pair, republication). */
	reconnect(relay: string): void {
		this.net.dropConnection(this);
		this.handlers?.down(relay, "test");
		this.handlers?.up(relay);
	}
}

// --- fake omp host ------------------------------------------------------------------------------------------

export class FakeHost implements SessionHost {
	ui = true;
	idle = true;
	confirmAnswer: boolean | ((message: string) => Promise<boolean>) = true;
	readonly confirms: string[] = [];
	readonly injected: { message: InjectedMessage; options: InjectOptions }[] = [];
	readonly notes: { message: string; level: string }[] = [];
	readonly states: SessionState[] = [];
	toolChanges = 0;
	/** omp session name; tests rename by assigning it. */
	name: string | undefined;

	hasUI(): boolean {
		return this.ui;
	}

	sessionName(): string | undefined {
		return this.name;
	}

	async confirm(_title: string, message: string): Promise<boolean> {
		this.confirms.push(message);
		return typeof this.confirmAnswer === "function" ? this.confirmAnswer(message) : this.confirmAnswer;
	}

	isIdle(): boolean {
		return this.idle;
	}

	inject(message: InjectedMessage, options: InjectOptions): void {
		this.injected.push({ message, options });
	}

	notify(message: string, level: "info" | "warning" | "error"): void {
		this.notes.push({ message, level });
	}

	sessionRef(): { sessionId?: string; entryId?: string } {
		return { sessionId: "session-test" };
	}

	persistState(state: SessionState): void {
		this.states.push(state);
	}

	toolsChanged(): void {
		this.toolChanges++;
	}

	injectedOfType(customType: string): InjectedMessage[] {
		return this.injected.filter(i => i.message.customType === customType).map(i => i.message);
	}
}

// --- node factory ---------------------------------------------------------------------------------------------

export interface Node {
	label: string;
	root: string;
	store: Store;
	audit: Audit;
	transport: FakeTransport;
	host: FakeHost;
	session: XshellSession;
}

export function makeNode(net: FakeNetwork, clock: FakeClock, label: string): Node {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), `xshell-${label}-`));
	const store = new Store(root);
	const audit = new Audit(store, () => clock.now());
	const transport = new FakeTransport(net);
	const host = new FakeHost();
	const session = new XshellSession({ store, audit, transport, clock, host });
	return { label, root, store, audit, transport, host, session };
}

export function cleanup(nodes: Node[]): void {
	for (const n of nodes) {
		n.session.detachAll();
		fs.rmSync(n.root, { recursive: true, force: true });
	}
}

/** A creator (master), plus joiners with the ask or answer key, all online and aware of each other. */
export async function makeShell(
	nodes: { creator: Node; masters?: Node[]; slaves?: Node[] },
	options: { name?: string; policy?: "ask" | "auto" } = {},
): Promise<{ xshellId: string; keys: { ask: string; answer: string } }> {
	const name = options.name ?? "infra";
	const created = await nodes.creator.session.createShell({
		name,
		relay: "relay.test",
		alias: "boss",
		role: "creator",
		policy: options.policy ?? "auto",
	});
	let i = 0;
	for (const n of nodes.masters ?? []) {
		await n.session.joinShell({ key: created.keys.ask, alias: `master${++i}`, role: "second master", policy: options.policy ?? "auto" });
	}
	i = 0;
	for (const n of nodes.slaves ?? []) {
		await n.session.joinShell({ key: created.keys.answer, alias: `slave${++i}`, role: "does things", policy: options.policy ?? "auto" });
	}
	const all = [nodes.creator, ...(nodes.masters ?? []), ...(nodes.slaves ?? [])];
	for (const n of all) await n.session.refreshAll();
	await settle();
	return { xshellId: created.membership.xshellId, keys: created.keys };
}

/** Builds an envelope signed by `sender`'s real identity, bypassing the extension's own sending rules. */
export async function craftEnvelope(
	sender: Node,
	membership: Membership,
	options: {
		kind: Kind;
		to: string;
		replyTo?: string | null;
		text?: string;
		status?: Status;
		msgId?: string;
		now?: number;
	},
): Promise<Envelope> {
	const identity = loadIdentity(sender.store, membership.fp);
	if (!identity || !membership.cert) throw new Error("sender not ready");
	const peer = membership.peers.known(options.to);
	if (!peer) throw new Error("recipient unknown to sender");
	const now = options.now ?? Date.now();
	const plain = { cert: membership.cert, text: options.text ?? "hello", ...(options.status ? { status: options.status } : {}) };
	return sealEnvelope(
		{
			v: 1,
			xshell_id: membership.xshellId,
			msg_id: options.msgId ?? newMsgId(),
			kind: options.kind,
			from: membership.fp,
			to: options.to,
			reply_to: options.replyTo ?? null,
			ts: formatTimestamp(new Date(now)),
		},
		plain,
		b64uDecode(peer.body.kem_pub, 32),
		identity.pair.seed,
	);
}

export function deliverTo(recipient: Node, xshellId: string, env: Envelope): void {
	recipient.transport.handlers?.deliver(TEST_ENDPOINT, xshellId, structuredClone(env));
}
