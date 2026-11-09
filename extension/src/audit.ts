/**
 * Local audit trail (§7.6): `audit/<xshell_id>.jsonl`, append-only, 0600, rotated at 10 MB.
 * Rotation keeps at most 3 files per xshell: the current one plus `.1` and `.2` (10 MB × 3).
 */
import * as fs from "node:fs";
import type { Store } from "./store.ts";

export type AuditEvent =
	| "received"
	| "refused"
	| "accepted"
	| "answered"
	| "rejected"
	| "sent"
	| "response_received"
	| "question_sent"
	| "question_received"
	| "answer_sent"
	| "answer_received"
	/** Invitations: the rank is recorded, never the UUID or anything derived from it. */
	| "invite_created"
	| "invite_granted"
	| "invite_refused"
	| "destroy_sent"
	| "destroyed";

export interface AuditRecord {
	event: AuditEvent;
	/** Message the event is about. */
	msg_id?: string;
	reply_to?: string | null;
	/** Alias and fingerprint of the sender (received events) or of the peer (sent events); for `invite_*`, the alias the claimant declared (unverified). */
	peer_alias?: string;
	peer_fp?: string;
	/** Policy applied to a received request. */
	policy?: string;
	status?: string;
	reason?: string;
	/** Full text, as sent or received (request, question, answer or response). */
	text?: string;
	session_id?: string;
	entry_id?: string;
	/** Rank an invitation grants ("master" or "slave"). */
	rank?: string;
}

export interface AuditLine extends AuditRecord {
	ts: string;
	xshell_id: string;
}

export const AUDIT_MAX_BYTES = 10 * 1024 * 1024;
export const AUDIT_FILES = 3;

export class Audit {
	constructor(
		private readonly store: Store,
		private readonly now: () => number = Date.now,
		private readonly maxBytes: number = AUDIT_MAX_BYTES,
	) {}

	/** Never throws: a full disk must not break the protocol. */
	log(xshellId: string, record: AuditRecord): void {
		try {
			const file = this.store.auditPath(xshellId);
			this.rotateIfNeeded(file);
			const line: AuditLine = { ts: new Date(this.now()).toISOString(), xshell_id: xshellId, ...record };
			fs.appendFileSync(file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
			fs.chmodSync(file, 0o600);
		} catch {
			// Best effort.
		}
	}

	private rotateIfNeeded(file: string): void {
		let size = 0;
		try {
			size = fs.statSync(file).size;
		} catch {
			return;
		}
		if (size < this.maxBytes) return;
		fs.rmSync(`${file}.${AUDIT_FILES - 1}`, { force: true });
		for (let i = AUDIT_FILES - 2; i >= 1; i--) {
			if (fs.existsSync(`${file}.${i}`)) fs.renameSync(`${file}.${i}`, `${file}.${i + 1}`);
		}
		fs.renameSync(file, `${file}.1`);
	}

	/** Last `count` events of one xshell, oldest first. */
	tail(xshellId: string, count: number): AuditLine[] {
		const file = this.store.auditPath(xshellId);
		const lines: AuditLine[] = [];
		// Newest generation last: read `.2`, `.1`, then the current file, and keep the end.
		for (let i = AUDIT_FILES - 1; i >= 0; i--) {
			const name = i === 0 ? file : `${file}.${i}`;
			let text: string;
			try {
				text = fs.readFileSync(name, "utf8");
			} catch {
				continue;
			}
			for (const raw of text.split("\n")) {
				if (!raw) continue;
				try {
					lines.push(JSON.parse(raw) as AuditLine);
				} catch {
					// Skip a torn line.
				}
			}
		}
		return lines.slice(-count);
	}
}

export function formatAuditLine(line: AuditLine, shellName?: string): string {
	const peer = line.peer_alias ? ` ${line.peer_alias}${line.peer_fp ? `(${line.peer_fp.slice(0, 11)}…)` : ""}` : "";
	const status = line.status ? ` [${line.status}${line.reason ? `: ${line.reason}` : ""}]` : "";
	const policy = line.policy ? ` policy=${line.policy}` : "";
	const rank = line.rank ? ` rank=${line.rank}` : "";
	const text = line.text ? ` « ${line.text.length > 200 ? `${line.text.slice(0, 200)}…` : line.text} »` : "";
	return `${line.ts} ${shellName ?? line.xshell_id} ${line.event}${peer}${policy}${rank}${status}${text}`.replace(/\s*\n\s*/g, " ");
}
