import { afterEach, describe, expect, test } from "bun:test";
import { FakeClock, settle, waitFor } from "./testkit.ts";
import { RelayError, RelayTransport, relayUrl, type TransportHandlers, type WebSocketLike } from "./transport.ts";

interface TestServer {
	port: number;
	stop(): void;
	frames: Record<string, unknown>[];
	sockets: Set<{ send(data: string): void; close(): void }>;
}

const cleanups: (() => void)[] = [];
afterEach(() => {
	for (const c of cleanups.splice(0)) c();
});

/** Minimal relay: accepts every connection, join/list/send answers; `send` replies are held until two arrived (to test id correlation). */
function startServer(): TestServer {
	const frames: Record<string, unknown>[] = [];
	const sockets = new Set<{ send(data: string): void; close(): void }>();
	const heldSends: { id: string }[] = [];
	const server = Bun.serve({
		port: 0,
		hostname: "127.0.0.1",
		fetch(req, srv) {
			if (srv.upgrade(req)) return undefined;
			return new Response("no", { status: 400 });
		},
		websocket: {
			open(ws) {
				sockets.add(ws);
			},
			close(ws) {
				sockets.delete(ws);
			},
			message(ws, raw) {
				const f = JSON.parse(String(raw)) as Record<string, unknown>;
				frames.push(f);
				if (f.t === "join" || f.t === "offer" || f.t === "withdraw" || f.t === "grant" || f.t === "refuse") ws.send(JSON.stringify({ v: 1, t: "ok", id: f.id }));
				else if (f.t === "claim") {
					if (f.invite_id === "gone") ws.send(JSON.stringify({ v: 1, t: "error", id: f.id, code: "no_invite", message: "no such invite" }));
					else if (f.invite_id !== "slow") ws.send(JSON.stringify({ v: 1, t: "granted", id: f.id, box: `box-for-${f.invite_id}` }));
				}
				else if (f.t === "list") ws.send(JSON.stringify({ v: 1, t: "members", id: f.id, xshell_id: f.xshell_id, members: [{ fp: "xs:a", cert_box: "box" }, { bogus: true }] }));
				else if (f.t === "send") {
					heldSends.push({ id: String(f.id) });
					if (heldSends.length === 2) {
						// Answer out of order.
						ws.send(JSON.stringify({ v: 1, t: "error", id: heldSends[1]!.id, code: "offline", message: "gone" }));
						ws.send(JSON.stringify({ v: 1, t: "sent", id: heldSends[0]!.id }));
					}
				}
			},
		},
	});
	const stop = () => server.stop(true);
	cleanups.push(stop);
	return { port: server.port as number, stop, frames, sockets };
}

function recorder() {
	const events: string[] = [];
	const delivered: { xshellId: string; env: unknown }[] = [];
	const problems: { code: string; message: string }[] = [];
	const claims: { inviteId: string; claim: string; epk: string; req: string }[] = [];
	const handlers: TransportHandlers = {
		up: relay => events.push(`up:${relay}`),
		down: relay => events.push(`down:${relay}`),
		deliver: (_relay, xshellId, env) => void delivered.push({ xshellId, env }),
		presence: (_r, f) => events.push(`presence:${f.fp}:${f.online}`),
		replaced: (_r, id) => events.push(`replaced:${id}`),
		problem: (_r, code, message) => void problems.push({ code, message }),
		claimRequest: (_r, inviteId, claim, epk, req) => void claims.push({ inviteId, claim, epk, req }),
	};
	return { events, delivered, problems, claims, handlers };
}

describe("relayUrl", () => {
	test("wss by default, ws without TLS (--notls) whatever the host; a malformed relay is rejected", () => {
		expect(relayUrl("relay.example.com", true)).toBe("wss://relay.example.com/ws");
		expect(relayUrl("relay.example.com:8443", false)).toBe("ws://relay.example.com:8443/ws");
		expect(relayUrl("127.0.0.1:8080", true)).toBe("wss://127.0.0.1:8080/ws");
		expect(() => relayUrl("bad host", true)).toThrow(RelayError);
	});
});

describe("RelayTransport against a real WebSocket server", () => {
	test("requests are correlated by id", async () => {
		const server = startServer();
		const rec = recorder();
		const transport = new RelayTransport();
		transport.setHandlers(rec.handlers);
		cleanups.push(() => transport.closeAll());
		const relay = relayUrl(`127.0.0.1:${server.port}`, false);
		transport.acquire(relay);
		await waitFor(() => transport.isUp(relay), "connection");
		expect(rec.events).toEqual([`up:${relay}`]);

		await transport.join(relay, "X".repeat(22), `xs:${"A".repeat(43)}`, "box");
		expect(await transport.list(relay, "X".repeat(22))).toEqual([{ fp: "xs:a", cert_box: "box" }]);

		const first = transport.send(relay, "X".repeat(22), "xs:b", { any: "thing" });
		const second = transport.send(relay, "X".repeat(22), "xs:c", { other: 1 });
		const results = await Promise.allSettled([first, second]);
		expect(results[0]?.status).toBe("fulfilled");
		expect(results[1]?.status).toBe("rejected");
		expect((results[1] as PromiseRejectedResult).reason).toBeInstanceOf(RelayError);
		expect(((results[1] as PromiseRejectedResult).reason as RelayError).code).toBe("offline");

		const join = server.frames.find(f => f.t === "join")!;
		expect(join).toMatchObject({ v: 1, xshell_id: "X".repeat(22), fp: `xs:${"A".repeat(43)}`, cert_box: "box" });
		expect(typeof join.id).toBe("string");
	});

	test("pushes: deliver, presence, replaced and unknown frames", async () => {
		const server = startServer();
		const rec = recorder();
		const transport = new RelayTransport();
		transport.setHandlers(rec.handlers);
		cleanups.push(() => transport.closeAll());
		const relay = relayUrl(`127.0.0.1:${server.port}`, false);
		transport.acquire(relay);
		await waitFor(() => transport.isUp(relay), "connection");
		const [socket] = [...server.sockets];
		socket!.send(JSON.stringify({ v: 1, t: "deliver", xshell_id: "X", env: { h: 1 } }));
		socket!.send(JSON.stringify({ v: 1, t: "presence", xshell_id: "X", fp: "xs:p", online: true, cert_box: "b" }));
		socket!.send(JSON.stringify({ v: 1, t: "error", code: "replaced", xshell_id: "X", message: "m" }));
		socket!.send(JSON.stringify({ v: 1, t: "frobnicate" }));
		socket!.send("not json");
		await waitFor(() => rec.delivered.length === 1 && rec.events.includes("replaced:X"), "pushes");
		expect(rec.delivered[0]).toEqual({ xshellId: "X", env: { h: 1 } });
		expect(rec.events).toContain("presence:xs:p:true");
	});

	test("an unreachable relay is reported as `unavailable`, and the backoff retries", async () => {
		const server = startServer();
		const port = server.port;
		server.stop();
		const rec = recorder();
		const clock = new FakeClock();
		let attempts = 0;
		const transport = new RelayTransport({
			clock,
			random: () => 0,
			webSocket: url => {
				attempts++;
				return new WebSocket(url) as unknown as WebSocketLike;
			},
		});
		transport.setHandlers(rec.handlers);
		cleanups.push(() => transport.closeAll());
		const relay = relayUrl(`127.0.0.1:${port}`, false);
		transport.acquire(relay);
		await waitFor(() => rec.problems.length === 1, "unavailable problem");
		expect(rec.problems[0]?.code).toBe("unavailable");
		expect(rec.events).toEqual([]);
		expect(transport.isUp(relay)).toBe(false);
		// Backoff 1 s: a second attempt happens.
		clock.advance(1_000);
		await waitFor(() => attempts === 2, "retry");
	});

	test("reconnects with backoff after the server drops the connection", async () => {
		const server = startServer();
		const rec = recorder();
		const clock = new FakeClock();
		const transport = new RelayTransport({ clock, random: () => 0 });
		transport.setHandlers(rec.handlers);
		cleanups.push(() => transport.closeAll());
		const relay = relayUrl(`127.0.0.1:${server.port}`, false);
		transport.acquire(relay);
		await waitFor(() => transport.isUp(relay), "first connection");
		for (const s of server.sockets) s.close();
		await waitFor(() => rec.events.includes(`down:${relay}`), "down event");
		expect(transport.isUp(relay)).toBe(false);
		await expect(transport.send(relay, "X", "xs:a", {})).rejects.toBeInstanceOf(RelayError);
		clock.advance(1_000);
		await waitFor(() => transport.isUp(relay), "reconnection");
		expect(rec.events.filter(e => e.startsWith("up:"))).toHaveLength(2);
	});

	test("reference counting: the connection closes with the last release", async () => {
		const server = startServer();
		const transport = new RelayTransport();
		transport.setHandlers(recorder().handlers);
		cleanups.push(() => transport.closeAll());
		const relay = relayUrl(`127.0.0.1:${server.port}`, false);
		transport.acquire(relay);
		transport.acquire(relay);
		await waitFor(() => transport.isUp(relay), "connection");
		transport.release(relay);
		expect(transport.isUp(relay)).toBe(true);
		transport.release(relay);
		expect(transport.isUp(relay)).toBe(false);
		await waitFor(() => server.sockets.size === 0, "socket closed");
	});

	test("invitations: offer/withdraw/grant/refuse are acknowledged, claim carries epk and req and resolves with the box or rejects no_invite, claim_request is pushed", async () => {
		const server = startServer();
		const rec = recorder();
		const transport = new RelayTransport();
		transport.setHandlers(rec.handlers);
		cleanups.push(() => transport.closeAll());
		const relay = relayUrl(`127.0.0.1:${server.port}`, false);
		transport.acquire(relay);
		await waitFor(() => transport.isUp(relay), "connection");

		await transport.offer(relay, "inv-1");
		await transport.withdraw(relay, "inv-1");
		await transport.grant(relay, "claim-1", "box");
		await transport.refuse(relay, "claim-2");
		expect(await transport.claim(relay, "inv-2", "epk-2", "req-2")).toBe("box-for-inv-2");
		const refused = await transport.claim(relay, "gone", "epk-g", "req-g").catch(e => e);
		expect(refused).toBeInstanceOf(RelayError);
		expect((refused as RelayError).code).toBe("no_invite");
		expect(server.frames.filter(f => ["offer", "withdraw", "grant", "refuse", "claim"].includes(String(f.t))).map(f => f.t)).toEqual([
			"offer",
			"withdraw",
			"grant",
			"refuse",
			"claim",
			"claim",
		]);
		expect(server.frames.find(f => f.t === "grant")).toMatchObject({ v: 1, claim: "claim-1", box: "box" });
		expect(server.frames.find(f => f.t === "claim")).toMatchObject({ v: 1, invite_id: "inv-2", epk: "epk-2", req: "req-2" });

		for (const s of server.sockets) {
			s.send(JSON.stringify({ v: 1, t: "claim_request", invite_id: "inv-3", claim: "c-9", epk: "epk-3", req: "req-3" }));
			// Without epk and req, the frame is ignored.
			s.send(JSON.stringify({ v: 1, t: "claim_request", invite_id: "inv-4", claim: "c-10" }));
		}
		await waitFor(() => rec.claims.length === 1, "claim_request");
		await settle();
		expect(rec.claims).toEqual([{ inviteId: "inv-3", claim: "c-9", epk: "epk-3", req: "req-3" }]);
	});

	test("a claim outlives the 15 s of ordinary requests (the relay may wait 120 s for the holder's confirmation)", async () => {
		const server = startServer();
		const clock = new FakeClock();
		const transport = new RelayTransport({ clock });
		transport.setHandlers(recorder().handlers);
		cleanups.push(() => transport.closeAll());
		const relay = relayUrl(`127.0.0.1:${server.port}`, false);
		transport.acquire(relay);
		await waitFor(() => transport.isUp(relay), "connection");
		const claim = transport.claim(relay, "slow", "epk", "req"); // the server never answers a "slow" claim by itself
		const outcome = claim.then(
			box => `box:${box}`,
			(error: RelayError) => `error:${error.code}`,
		);
		await waitFor(() => server.frames.some(f => f.t === "claim"), "claim frame");
		clock.advance(16_000); // an ordinary request would have timed out
		const id = server.frames.find(f => f.t === "claim")!.id;
		for (const s of server.sockets) s.send(JSON.stringify({ v: 1, t: "granted", id, box: "late-box" }));
		expect(await outcome).toBe("box:late-box");

		const stuck = transport.claim(relay, "slow", "epk", "req").catch((error: RelayError) => error.code);
		await waitFor(() => server.frames.filter(f => f.t === "claim").length === 2, "second claim frame");
		clock.advance(129_000);
		await settle();
		clock.advance(1_000);
		expect(await stuck).toBe("timeout");
	});
});
