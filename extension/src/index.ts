/**
 * xs-parley — omp extension (see doc/SPEC.md): delegate actions to other omp sessions through an end-to-end encrypted
 * relay. This file only wires omp events to `ParleySession`.
 *
 * Process-level state: extension factories are re-bound to every subagent session, module variables are shared.
 * Only the main session (`ctx.agent.kind === "main"`) has an identity and the xs-parley tools.
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { Audit } from "./audit.ts";
import { completeArguments, executeCommand, parseCommand } from "./commands.ts";
import type { InjectedMessage, InjectOptions } from "./inbox.ts";
import { STATE_ENTRY, type SessionHost, type SessionState, UserError, ParleySession } from "./session.ts";
import { Store } from "./store.ts";
import { realClock, RelayTransport } from "./transport.ts";
import { registerTools, TOOL_NAMES } from "./tools.ts";

/** Bridge to the main session's `pi` and latest `ctx` (both rebound on every main-session event). */
class OmpHost implements SessionHost {
	pi: ExtensionAPI | undefined;
	ctx: ExtensionContext | undefined;
	private toolSync: Promise<void> = Promise.resolve();
	session: ParleySession | undefined;
	/** Session manager whose renames we follow, and how to stop following it. */
	private watched: { manager: object; stop: () => void } | undefined;

	bind(pi: ExtensionAPI, ctx: ExtensionContext): void {
		this.pi = pi;
		this.ctx = ctx;
		this.watchRenames(ctx.sessionManager);
	}

	sessionName(): string | undefined {
		return this.ctx?.sessionManager.getSessionName();
	}

	/**
	 * Renames (`/name`, generated title) republish the alias at once. The hook is not part of the extension
	 * typings: without it, `before_agent_start` and every `/xsp` command still pick up the new name.
	 */
	private watchRenames(manager: ExtensionContext["sessionManager"]): void {
		if (this.watched?.manager === manager) return;
		this.watched?.stop();
		this.watched = undefined;
		if (!("onSessionNameChanged" in manager) || typeof manager.onSessionNameChanged !== "function") return;
		const unsubscribe: unknown = manager.onSessionNameChanged(() => this.session?.syncSessionName());
		if (typeof unsubscribe === "function") this.watched = { manager, stop: () => unsubscribe() };
	}

	hasUI(): boolean {
		return this.ctx?.hasUI === true;
	}

	async confirm(title: string, message: string): Promise<boolean> {
		if (!this.ctx) return false;
		try {
			return await this.ctx.ui.confirm(title, message);
		} catch {
			return false;
		}
	}

	isIdle(): boolean {
		return this.ctx?.isIdle() ?? false;
	}

	inject(message: InjectedMessage, options: InjectOptions): void {
		this.pi?.sendMessage(message, options);
	}

	notify(message: string, level: "info" | "warning" | "error"): void {
		try {
			this.ctx?.ui.notify(message, level);
		} catch {
			// The UI may be gone (shutdown).
		}
	}

	sessionRef(): { sessionId?: string; entryId?: string } {
		const manager = this.ctx?.sessionManager;
		if (!manager) return {};
		const ref: { sessionId?: string; entryId?: string } = {};
		try {
			ref.sessionId = manager.getSessionId();
			const leaf = manager.getLeafId();
			if (leaf) ref.entryId = leaf;
		} catch {
			// Best effort: audit context only.
		}
		return ref;
	}

	persistState(state: SessionState): void {
		this.pi?.appendEntry(STATE_ENTRY, state);
	}

	/** Shows the model only the xs-parley tools that apply right now (§7.2). Serialized: setActiveTools is async. */
	toolsChanged(): void {
		this.toolSync = this.toolSync.then(() => this.syncTools()).catch(() => undefined);
	}

	private async syncTools(): Promise<void> {
		const { pi, session } = this;
		if (!pi || !session) return;
		const desired = new Set(session.activeToolNames());
		const ours = new Set<string>(TOOL_NAMES);
		const current = pi.getActiveTools();
		const next = current.filter(name => !ours.has(name));
		for (const name of TOOL_NAMES) if (desired.has(name)) next.push(name);
		const same = next.length === current.length && next.every(name => current.includes(name));
		if (!same) await pi.setActiveTools(next);
	}
}

interface Runtime {
	host: OmpHost;
	session: ParleySession;
	audit: Audit;
}

let runtime: Runtime | undefined;

function getRuntime(): Runtime {
	if (runtime) return runtime;
	const store = new Store();
	const audit = new Audit(store);
	const host = new OmpHost();
	const transport = new RelayTransport();
	const session = new ParleySession({ store, audit, transport, clock: realClock, host });
	host.session = session;
	runtime = { host, session, audit };
	return runtime;
}

/** Last `xsp-state` entry of the current branch (§7.5). */
function readState(ctx: ExtensionContext): SessionState | undefined {
	try {
		const entries = ctx.sessionManager.getBranch();
		for (let i = entries.length - 1; i >= 0; i--) {
			const entry = entries[i];
			if (entry?.type !== "custom" || entry.customType !== STATE_ENTRY) continue;
			const data = entry.data as Partial<SessionState> | undefined;
			if (!data || !Array.isArray(data.parleys)) return undefined;
			return { parleys: data.parleys, pending: Array.isArray(data.pending) ? data.pending : [] };
		}
	} catch {
		// Unreadable session: start without parleys.
	}
	return undefined;
}

function errorMessage(error: unknown): string {
	if (error instanceof UserError) return error.message;
	return `erreur interne : ${error instanceof Error ? error.message : String(error)}`;
}

export default function xsParley(pi: ExtensionAPI): void {
	pi.setLabel("xs-parley");
	registerTools(pi, () => runtime?.session);

	pi.registerCommand("xsp", {
		description: "xs-parley : demander une action à une autre session omp (create|join|invite|leave|list|keys|rotate|policy|pending|log)",
		getArgumentCompletions: prefix => {
			const session = runtime?.session;
			return completeArguments(prefix, session?.all() ?? [], session?.localNames() ?? []);
		},
		handler: async (args, ctx) => {
			if (ctx.agent.kind !== "main") return;
			const rt = getRuntime();
			rt.host.bind(pi, ctx);
			rt.session.syncSessionName();
			const parsed = parseCommand(args);
			if (!parsed.ok) {
				ctx.ui.notify(parsed.error, "error");
				return;
			}
			try {
				const out = await executeCommand(parsed.command, {
					session: rt.session,
					audit: rt.audit,
					env: process.env,
					now: () => Date.now(),
				});
				ctx.ui.notify(out.text, out.level);
			} catch (error) {
				ctx.ui.notify(errorMessage(error), "error");
			}
		},
	});

	pi.on("session_start", async (_event, ctx) => {
		if (ctx.agent.kind !== "main") return;
		const rt = getRuntime();
		rt.host.bind(pi, ctx);
		rt.session.restore(readState(ctx));
		rt.host.toolsChanged();
	});

	// `/new`, `/resume`, fork within the same process: leave the old session's parleys, join the new one's.
	pi.on("session_switch", async (_event, ctx) => {
		if (ctx.agent.kind !== "main") return;
		const rt = getRuntime();
		rt.session.detachAll();
		rt.host.bind(pi, ctx);
		rt.session.restore(readState(ctx));
		rt.host.toolsChanged();
	});

	// Must not block (omp allows 2 s): closing sockets and wiping keys is synchronous.
	pi.on("session_shutdown", async (_event, ctx) => {
		if (ctx.agent.kind !== "main" || !runtime) return;
		runtime.session.detachAll();
	});

	pi.on("before_agent_start", (event, ctx) => {
		if (ctx.agent.kind !== "main" || event.reason !== "prompt" || !runtime) return;
		runtime.session.syncSessionName();
		const section = runtime.session.systemSection();
		if (!section) return;
		return { systemPrompt: [...event.systemPrompt, section] };
	});

	pi.on("agent_start", (_event, ctx) => {
		if (ctx.agent.kind !== "main") return;
		runtime?.session.inbox.onAgentStart();
	});

	pi.on("agent_end", (event, ctx) => {
		if (ctx.agent.kind !== "main" || !runtime) return;
		runtime.host.bind(pi, ctx);
		void runtime.session.inbox.onAgentEnd(event.messages, event.willContinue).catch(() => undefined);
	});
}
