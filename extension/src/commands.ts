/**
 * `/xsp create|join|invite|leave|list|keys|rotate|policy|pending|log` (§7.1).
 *
 * `parseCommand` and `completeArguments` are pure; `executeCommand` returns the text to show the user (French, as
 * the spec's messages).
 */
import type { AutocompleteItem } from "@oh-my-pi/pi-tui";
import type { Audit } from "./audit.ts";
import { formatAuditLine } from "./audit.ts";
import { INVITE_RE, NAME_RE, type Rank } from "./crypto.ts";
import type { Membership } from "./keys.ts";
import { rankLabel, type ParleySession, UserError } from "./session.ts";
import type { Policy } from "./store.ts";

export type Command =
	| { name: "create"; parley: string; alias?: string; policy: Policy; relay?: string; notls?: true; role: string }
	| { name: "join"; key: string; relay?: string; parleyName?: string; alias?: string; policy: Policy; notls?: true; role: string }
	| { name: "invite"; parley: string }
	| { name: "leave"; parley: string }
	| { name: "list"; parley?: string }
	| { name: "keys"; parley?: string }
	| { name: "rotate"; parley: string }
	| { name: "destroy"; parley: string }
	| { name: "policy"; parley: string; policy: Policy }
	| { name: "pending" }
	| { name: "log"; parley?: string; count: number };

export type ParseResult = { ok: true; command: Command } | { ok: false; error: string };

/** Subcommands in the order the usage and the completion list them. */
const SUBCOMMANDS = [
	{ name: "create", usage: "<nom> [--as alias] [--relay hôte[:port]] [--notls] [--approve=ask|auto] [role…]", description: "créer une parley (tu en es master)" },
	{ name: "join", usage: "<clé|uuid|nom> [--relay hôte[:port]] [--name nom] [--as alias] [--notls] [--approve=ask|auto] [role…]", description: "rejoindre avec une clé ask/answer, un UUID d'invitation ou le nom d'une parley de cette machine" },
	{ name: "invite", usage: "<nom>", description: "invitations à usage unique (master et slave, 5 min)" },
	{ name: "leave", usage: "<nom>", description: "quitter une parley" },
	{ name: "destroy", usage: "<nom>", description: "détruire une parley pour tous ses membres en ligne (master)" },
	{ name: "list", usage: "[nom]", description: "membres connus et leur présence" },
	{ name: "keys", usage: "[nom]", description: "réafficher les clés que tu détiens" },
	{ name: "rotate", usage: "<nom>", description: "régénérer les clés (créateur)" },
	{ name: "policy", usage: "<nom> ask|auto", description: "politique de réception des demandes" },
	{ name: "pending", usage: "", description: "demandes émises en attente de réponse" },
	{ name: "log", usage: "[nom] [-n 20]", description: "derniers événements de l'audit local" },
] as const;

export const USAGE = SUBCOMMANDS.map(s => `/xsp ${s.name}${s.usage ? ` ${s.usage}` : ""}`).join("\n");

const OPTIONS = ["--as", "--name", "--relay", "--approve", "--notls"] as const;
type OptionName = (typeof OPTIONS)[number];
/** Options without a value. */
const FLAGS: readonly OptionName[] = ["--notls"];

const ALLOWED: Record<string, readonly OptionName[]> = {
	create: ["--as", "--relay", "--notls", "--approve"],
	join: ["--as", "--name", "--relay", "--notls", "--approve"],
};

const RELAY_NEEDS_INVITE = "--relay ne s'utilise qu'avec un UUID d'invitation";

function fail(error: string): ParseResult {
	return { ok: false, error };
}

function parsePolicy(value: string): Policy | undefined {
	return value === "ask" || value === "auto" ? value : undefined;
}

interface Split {
	positional: string[];
	options: Partial<Record<OptionName, string>>;
	flags: Set<OptionName>;
}

/** Extracts the options the subcommand knows; any other token (even `--foo`) stays in the positional text. */
function splitOptions(tokens: string[], sub: string): Split | string {
	const allowed = ALLOWED[sub] ?? [];
	const positional: string[] = [];
	const options: Partial<Record<OptionName, string>> = {};
	const flags = new Set<OptionName>();
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i] as string;
		const eq = token.indexOf("=");
		const flag = eq < 0 ? token : token.slice(0, eq);
		if (!(OPTIONS as readonly string[]).includes(flag)) {
			positional.push(token);
			continue;
		}
		if (!(allowed as readonly string[]).includes(flag)) return `option ${flag} non valable pour « ${sub} »`;
		if (FLAGS.includes(flag as OptionName)) {
			if (eq >= 0) return `option ${flag} : sans valeur`;
			flags.add(flag as OptionName);
			continue;
		}
		let value: string | undefined = eq < 0 ? undefined : token.slice(eq + 1);
		if (value === undefined) {
			value = tokens[i + 1];
			i++;
		}
		if (!value) return `option ${flag} : valeur manquante`;
		options[flag as OptionName] = value;
	}
	return { positional, options, flags };
}

export function parseCommand(args: string): ParseResult {
	const tokens = args.trim().split(/\s+/).filter(Boolean);
	const [sub, ...rest] = tokens;
	if (!sub) return fail(`sous-commande manquante\n${USAGE}`);

	switch (sub) {
		case "create":
		case "join": {
			const split = splitOptions(rest, sub);
			if (typeof split === "string") return fail(split);
			const [first, ...roleWords] = split.positional;
			if (!first) return fail(sub === "create" ? "usage : /xsp create <nom> …" : "usage : /xsp join <clé|uuid|nom> …");
			let policy: Policy = "auto";
			if (split.options["--approve"] !== undefined) {
				const parsed = parsePolicy(split.options["--approve"]);
				if (!parsed) return fail("--approve : ask ou auto");
				policy = parsed;
			}
			const role = roleWords.join(" ");
			const alias = split.options["--as"];
			const notls = split.flags.has("--notls") ? { notls: true as const } : {};
			if (sub === "create") {
				const relay = split.options["--relay"];
				return {
					ok: true,
					command: { name: "create", parley: first, policy, role, ...notls, ...(alias ? { alias } : {}), ...(relay ? { relay } : {}) },
				};
			}
			const parleyName = split.options["--name"];
			const relay = split.options["--relay"];
			if (relay && !INVITE_RE.test(first)) return fail(RELAY_NEEDS_INVITE);
			// A local parley name never contains ':', a key always does.
			if (parleyName && NAME_RE.test(first)) return fail("--name ne s'utilise pas pour rejoindre une parley de cette machine par son nom");
			return {
				ok: true,
				command: {
					name: "join",
					key: first,
					policy,
					role,
					...notls,
					...(alias ? { alias } : {}),
					...(parleyName ? { parleyName } : {}),
					...(relay ? { relay } : {}),
				},
			};
		}
		case "leave":
		case "invite":
		case "rotate":
		case "destroy": {
			const [parley, ...extra] = rest;
			if (!parley || extra.length > 0) return fail(`usage : /xsp ${sub} <nom>`);
			return { ok: true, command: { name: sub, parley } };
		}
		case "list":
		case "keys": {
			const [parley, ...extra] = rest;
			if (extra.length > 0) return fail(`usage : /xsp ${sub} [nom]`);
			return { ok: true, command: parley ? { name: sub, parley } : { name: sub } };
		}
		case "policy": {
			const [parley, value, ...extra] = rest;
			const policy = value === undefined ? undefined : parsePolicy(value);
			if (!parley || !policy || extra.length > 0) return fail("usage : /xsp policy <nom> ask|auto");
			return { ok: true, command: { name: "policy", parley, policy } };
		}
		case "pending":
			return rest.length > 0 ? fail("usage : /xsp pending") : { ok: true, command: { name: "pending" } };
		case "log": {
			let count = 20;
			let parley: string | undefined;
			for (let i = 0; i < rest.length; i++) {
				const token = rest[i] as string;
				if (token === "-n" || token.startsWith("-n=") || /^-n\d+$/.test(token)) {
					const raw = token === "-n" ? rest[++i] : token.replace(/^-n=?/, "");
					const parsed = raw !== undefined && /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
					if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1000) return fail("-n : entier entre 1 et 1000");
					count = parsed;
				} else if (!parley) {
					parley = token;
				} else {
					return fail("usage : /xsp log [nom] [-n 20]");
				}
			}
			return { ok: true, command: parley ? { name: "log", parley, count } : { name: "log", count } };
		}
		default:
			return fail(`sous-commande inconnue : ${sub}\n${USAGE}`);
	}
}

// --- completion --------------------------------------------------------------------------------------------

const OPTION_DESCRIPTIONS: Record<OptionName, string> = {
	"--as": "alias de ce membre",
	"--name": "nom local de la parley",
	"--relay": "hôte[:port] du relai",
	"--approve": "politique de réception",
	"--notls": "connexion ws:// sans TLS",
};

/** Subcommands whose first argument is the name of a joined parley. */
const NAMED: Readonly<Record<string, true>> = { invite: true, leave: true, destroy: true, rotate: true, list: true, keys: true, policy: true, log: true };
/** Subcommands reserved to masters: completion offers only the parleys where this session is master. */
const MASTER_ONLY: Readonly<Record<string, true>> = { invite: true, destroy: true, rotate: true };

/**
 * Argument completion for `/xsp` (omp `getArgumentCompletions`). Each item's `value` is the whole argument
 * text with the current word completed. `parleys`: parleys this session has joined (master ones for `rotate`);
 * `localNames`: parleys of this machine the session has not joined (for `join <nom>`).
 */
export function completeArguments(
	prefix: string,
	parleys: readonly { name: string; key: { rank: Rank } }[],
	localNames: readonly string[] = [],
): AutocompleteItem[] | null {
	const tokens = prefix.split(" ");
	const current = tokens.at(-1) ?? "";
	const before = prefix.slice(0, prefix.length - current.length);
	const [sub = "", ...args] = tokens;
	const complete = (candidates: { word: string; description?: string; space?: boolean }[]): AutocompleteItem[] | null => {
		const items = candidates
			.filter(c => c.word.startsWith(current))
			.map(c => ({
				value: `${before}${c.word}${c.space === false ? "" : " "}`,
				label: c.word,
				...(c.description ? { description: c.description } : {}),
			}));
		return items.length > 0 ? items : null;
	};

	if (tokens.length === 1) {
		return complete(SUBCOMMANDS.map(s => ({ word: s.name, description: s.description })));
	}
	const position = args.length; // 1 = first argument
	if ((sub === "create" || sub === "join") && current.startsWith("-")) {
		const used = new Set(args.slice(0, -1).map(a => a.split("=")[0]));
		return complete(
			(ALLOWED[sub] ?? [])
				.filter(o => !used.has(o))
				// `join --relay` only makes sense for an invitation UUID.
				.filter(o => !(sub === "join" && o === "--relay") || INVITE_RE.test(args[0] ?? ""))
				.flatMap(o =>
					o === "--approve"
						? [
								{ word: "--approve=ask", description: "confirmer chaque demande reçue" },
								{ word: "--approve=auto", description: "exécuter sans confirmation" },
							]
						: [{ word: o, description: OPTION_DESCRIPTIONS[o] }],
				),
		);
	}
	if (NAMED[sub] && position === 1 && !current.startsWith("-")) {
		const names = parleys.filter(s => !MASTER_ONLY[sub] || s.key.rank === "A").map(s => ({ word: s.name }));
		return complete(names);
	}
	if (sub === "join" && position === 1 && !current.startsWith("-")) {
		return complete(localNames.map(word => ({ word, description: "parley de cette machine" })));
	}
	if (sub === "policy" && position === 2) {
		return complete([
			{ word: "ask", description: "confirmer chaque demande reçue" },
			{ word: "auto", description: "exécuter sans confirmation" },
		]);
	}
	return null;
}

// --- execution ---------------------------------------------------------------------------------------------

export interface CommandDeps {
	session: ParleySession;
	audit: Audit;
	env: Record<string, string | undefined>;
	now(): number;
}

export interface CommandOutput {
	text: string;
	level: "info" | "warning" | "error";
}

function selected(session: ParleySession, name: string | undefined): Membership[] {
	return name === undefined ? session.all() : [session.requireMember(name)];
}

function keyLines(session: ParleySession, m: Membership): string {
	return session
		.keysOf(m)
		.map(k => `  ${k.label} : ${k.key}`)
		.join("\n");
}

function age(ms: number): string {
	const minutes = Math.floor(ms / 60_000);
	if (minutes < 1) return "à l'instant";
	if (minutes < 60) return `il y a ${minutes} min`;
	return `il y a ${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

async function listText(session: ParleySession, name: string | undefined, now: number): Promise<string> {
	const parleys = selected(session, name);
	if (parleys.length === 0) return "Aucune parley rejointe.";
	await session.refreshAll();
	const blocks: string[] = [];
	for (const m of parleys) {
		const header = `« ${m.name} » (${m.parleyId}) relai ${m.endpoint} — toi : ${m.alias} [${rankLabel(m.key.rank)}] ${m.fp} politique ${m.policy}${m.suspended ? " — SUSPENDU" : ""}`;
		const peers = m.peers.views(m.fp, now).sort((a, b) => Number(b.online) - Number(a.online) || a.alias.localeCompare(b.alias));
		const rows = peers.map(p => `  ${p.alias} [${rankLabel(p.rank)}] ${p.online ? "en ligne" : "hors ligne"} ${p.fp}${p.role ? ` « ${p.role} »` : ""}`);
		blocks.push([header, ...(rows.length > 0 ? rows : ["  (aucun autre membre connu)"])].join("\n"));
	}
	return blocks.join("\n\n");
}

/** Runs a parsed command. Throws `UserError` for expected failures. */
export async function executeCommand(command: Command, deps: CommandDeps): Promise<CommandOutput> {
	const { session } = deps;
	switch (command.name) {
		case "create": {
			const relay = command.relay ?? deps.env.XSP_RELAY;
			if (!relay) throw new UserError("relai inconnu : --relay ou XSP_RELAY");
			const out = await session.createParley({
				name: command.parley,
				relay,
				notls: command.notls,
				role: command.role,
				policy: command.policy,
				...(command.alias ? { alias: command.alias } : {}),
			});
			const m = out.membership;
			return {
				level: "info",
				text: [
					`✓ parley « ${m.name} » créée`,
					`  relai     ${m.endpoint}${command.notls ? " (sans TLS)" : ""}`,
					`  toi       ${m.alias} [master] ${m.fp}`,
					`  politique ${m.policy}`,
					`  id        ${m.parleyId}`,
					"",
					"Pour faire entrer d'autres sessions :",
					`  • sur cette machine : /xsp join ${m.name}`,
					`  • ailleurs          : /xsp invite ${m.name} (UUID à usage unique), ou /xsp keys ${m.name}`,
				].join("\n"),
			};
		}
		case "join": {
			let out: { membership: Membership };
			if (INVITE_RE.test(command.key)) {
				const relay = command.relay ?? deps.env.XSP_RELAY;
				if (!relay) throw new UserError("relai inconnu : --relay ou XSP_RELAY");
				out = await session.joinWithInvite({
					code: command.key,
					relay,
					role: command.role,
					policy: command.policy,
					notls: command.notls,
					...(command.parleyName ? { name: command.parleyName } : {}),
					...(command.alias ? { alias: command.alias } : {}),
				});
			} else if (NAME_RE.test(command.key)) {
				if (command.relay) throw new UserError(RELAY_NEEDS_INVITE);
				out = await session.joinLocal({
					name: command.key,
					role: command.role,
					policy: command.policy,
					notls: command.notls,
					...(command.alias ? { alias: command.alias } : {}),
				});
			} else {
				if (command.relay) throw new UserError(RELAY_NEEDS_INVITE);
				out = await session.joinParley({
					key: command.key,
					role: command.role,
					policy: command.policy,
					notls: command.notls,
					...(command.parleyName ? { name: command.parleyName } : {}),
					...(command.alias ? { alias: command.alias } : {}),
				});
			}
			const m = out.membership;
			return {
				level: "info",
				text: `parley « ${m.name} » rejointe en ${rankLabel(m.key.rank)} sous l'alias ${m.alias} (${m.fp}) ; politique ${m.policy}. Connecté au relai.`,
			};
		}
		case "invite": {
			const out = await session.createInvites(command.parley);
			const m = out.membership;
			const join = (uuid: string) => `/xsp join ${uuid} --relay ${m.relay}${m.endpoint.startsWith("ws:") ? " --notls" : ""}`;
			// Shown by the caller through `notify` only, like `keys`: the UUIDs must not reach the model or the session log.
			return {
				level: "info",
				text: [
					`Invitations pour « ${m.name} » (usage unique, valables 5 min ; cette session doit rester ouverte) :`,
					`  master : ${join(out.master)}`,
					`  slave  : ${join(out.slave)}`,
					"Chaque demande te sera soumise pour confirmation (alias et rôle déclarés).",
				].join("\n"),
			};
		}
		case "leave":
			await session.leaveParley(command.parley);
			return { level: "info", text: `parley « ${command.parley} » quittée ; fichier local supprimé.` };
		case "list":
			return { level: "info", text: await listText(session, command.parley, deps.now()) };
		case "keys": {
			const parleys = selected(session, command.parley);
			if (parleys.length === 0) return { level: "info", text: "Aucune parley rejointe." };
			return { level: "info", text: parleys.map(m => `« ${m.name} » :\n${keyLines(session, m)}`).join("\n\n") };
		}
		case "destroy": {
			const out = await session.destroyParley(command.parley);
			const lines = [`parley « ${command.parley} » détruite et supprimée de cette machine.`];
			lines.push(`  ${out.notified} membre(s) en ligne prévenu(s)${out.failed > 0 ? `, ${out.failed} injoignable(s) au moment de l'envoi` : ""}.`);
			if (out.offline > 0) lines.push(`  ${out.offline} membre(s) hors ligne garde(nt) leur copie : la clé reste valable entre eux.`);
			return { level: out.failed + out.offline > 0 ? "warning" : "info", text: lines.join("\n") };
		}
		case "rotate": {
			const out = await session.rotateParley(command.parley);
			return {
				level: "warning",
				text: [
					`parley « ${command.parley} » : graines régénérées ; tous les certificats sont invalidés. Chaque membre doit refaire /xsp join avec la nouvelle clé.`,
					`  clé ask (master)   : ${out.keys.ask}`,
					`  clé answer (slave) : ${out.keys.answer}`,
					...(out.dropped > 0 ? [`${out.dropped} autre(s) adhésion(s) locale(s) à cette parley supprimée(s) : leur clé n'est plus valable.`] : []),
				].join("\n"),
			};
		}
		case "policy":
			session.setPolicy(command.parley, command.policy);
			return { level: "info", text: `parley « ${command.parley} » : politique de réception = ${command.policy}.` };
		case "pending": {
			const views = session.inbox.pendingViews();
			if (views.length === 0) return { level: "info", text: "Aucune demande en attente de réponse." };
			const now = deps.now();
			const rows = views.map(v => {
				const text = v.text.replace(/\s+/g, " ");
				return `- ${v.request_id} → ${v.alias}@${v.parley_name}, ${age(now - v.sent_at)}, ${v.accepted ? "acceptée" : "non acceptée"}${v.questions > 0 ? `, ${v.questions} question(s)` : ""} « ${text.length > 120 ? `${text.slice(0, 120)}…` : text} »`;
			});
			return { level: "info", text: `${views.length} demande(s) en attente :\n${rows.join("\n")}` };
		}
		case "log": {
			const parleys = selected(session, command.parley);
			const lines = parleys.flatMap(m => deps.audit.tail(m.parleyId, command.count).map(l => ({ line: l, name: m.name })));
			lines.sort((a, b) => a.line.ts.localeCompare(b.line.ts));
			const last = lines.slice(-command.count);
			if (last.length === 0) return { level: "info", text: "Audit vide." };
			return { level: "info", text: last.map(l => formatAuditLine(l.line, l.name)).join("\n") };
		}
	}
}
