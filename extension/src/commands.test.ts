import { describe, expect, test } from "bun:test";
import { type Command, completeArguments, parseCommand } from "./commands.ts";

function parsed(line: string): Command {
	const r = parseCommand(line);
	if (!r.ok) throw new Error(`parse failed: ${r.error}`);
	return r.command;
}

function error(line: string): string {
	const r = parseCommand(line);
	if (r.ok) throw new Error("expected a parse error");
	return r.error;
}

describe("parseCommand", () => {
	test("create: name, options anywhere, remaining words form the role", () => {
		expect(parsed("create infra")).toEqual({ name: "create", shell: "infra", policy: "auto", role: "" });
		expect(parsed("create infra --as prod-box --approve=auto accès prod k8s, kubectl lecture")).toEqual({
			name: "create",
			shell: "infra",
			alias: "prod-box",
			policy: "auto",
			role: "accès prod k8s, kubectl lecture",
		});
		expect(parsed("create infra accès --relay relay.example.com:8443 prod --as=x")).toEqual({
			name: "create",
			shell: "infra",
			alias: "x",
			relay: "relay.example.com:8443",
			policy: "auto",
			role: "accès prod",
		});
	});

	test("join: key, --name, --as, --approve, role", () => {
		const key = "xs2:relay.example.com:8443:LyihzYI7iObLA1IzyE-YJw:prod-k8s:A:seed:seed";
		expect(parsed(`join ${key} --name local --as me --approve ask do things`)).toEqual({
			name: "join",
			key,
			shellName: "local",
			alias: "me",
			policy: "ask",
			role: "do things",
		});
		expect(parsed(`join ${key}`)).toEqual({ name: "join", key, policy: "auto", role: "" });
		expect(parsed(`join ${key} --approve=ask`)).toEqual({ name: "join", key, policy: "ask", role: "" });
	});

	test("join with an invitation UUID accepts --relay (and --notls); the UUID is not a shell key", () => {
		const uuid = "3f2b8c4e-1a5d-4e7f-9b2a-6c8d0e1f2a3b";
		expect(parsed(`join ${uuid} --relay relay.example.com:8443 --notls --name local --as me lecture seule`)).toEqual({
			name: "join",
			key: uuid,
			relay: "relay.example.com:8443",
			notls: true,
			shellName: "local",
			alias: "me",
			policy: "auto",
			role: "lecture seule",
		});
		expect(parsed(`join ${uuid}`)).toEqual({ name: "join", key: uuid, policy: "auto", role: "" });
		expect(parsed(`join ${uuid.toUpperCase()} --relay=r.example`)).toMatchObject({ key: uuid.toUpperCase(), relay: "r.example" });
		expect(error(`join ${uuid} --relay`)).toContain("valeur manquante");
	});

	test("--relay with a key (or anything that is not a v4 UUID) is refused", () => {
		const key = "xs2:relay.example.com:8443:LyihzYI7iObLA1IzyE-YJw:prod-k8s:A:seed:seed";
		expect(error(`join ${key} --relay relay.example.com`)).toBe("--relay ne s'utilise qu'avec un UUID d'invitation");
		expect(error("join 3f2b8c4e-1a5d-1e7f-9b2a-6c8d0e1f2a3b --relay r.example")).toContain("UUID d'invitation");
		expect(error("join --relay r.example")).toContain("usage");
	});

	test("invite takes exactly one xshell name", () => {
		expect(parsed("invite infra")).toEqual({ name: "invite", shell: "infra" });
		expect(error("invite")).toBe("usage : /xshell invite <nom>");
		expect(error("invite a b")).toBe("usage : /xshell invite <nom>");
		expect(error("invite infra --relay x")).toContain("usage"); // options are not parsed: an extra word
	});

	test("--notls takes no value: the next word stays in the role", () => {
		expect(parsed("create infra --notls --relay r.example accès prod")).toEqual({
			name: "create",
			shell: "infra",
			relay: "r.example",
			notls: true,
			policy: "auto",
			role: "accès prod",
		});
		expect(parsed("join xs2:k --notls lecture")).toEqual({ name: "join", key: "xs2:k", notls: true, policy: "auto", role: "lecture" });
		expect(error("create infra --notls=yes")).toContain("sans valeur");
		expect(parsed("leave infra")).not.toHaveProperty("notls");
	});

	test("unknown flags stay in the role; options of another subcommand are errors", () => {
		expect(parsed("create infra uses --verbose mode")).toMatchObject({ role: "uses --verbose mode" });
		expect(error("create infra --name other")).toContain("--name");
		expect(error("join xs2:k --relay x")).toContain("--relay");
	});

	test("invalid values and missing arguments", () => {
		expect(error("create infra --approve=maybe")).toContain("--approve");
		expect(error("create infra --as")).toContain("valeur manquante");
		expect(error("create")).toContain("usage");
		expect(error("")).toContain("sous-commande manquante");
		expect(error("frobnicate")).toContain("inconnue");
	});

	test("leave, rotate, list, keys, policy, pending", () => {
		expect(parsed("leave infra")).toEqual({ name: "leave", shell: "infra" });
		expect(parsed("rotate infra")).toEqual({ name: "rotate", shell: "infra" });
		expect(parsed("list")).toEqual({ name: "list" });
		expect(parsed("list infra")).toEqual({ name: "list", shell: "infra" });
		expect(parsed("keys infra")).toEqual({ name: "keys", shell: "infra" });
		expect(parsed("policy infra auto")).toEqual({ name: "policy", shell: "infra", policy: "auto" });
		expect(parsed("pending")).toEqual({ name: "pending" });
		expect(error("leave")).toContain("usage");
		expect(error("policy infra sometimes")).toContain("usage");
		expect(error("pending now")).toContain("usage");
	});

	test("log: optional name, -n count", () => {
		expect(parsed("log")).toEqual({ name: "log", count: 20 });
		expect(parsed("log infra -n 5")).toEqual({ name: "log", shell: "infra", count: 5 });
		expect(parsed("log -n 7 infra")).toEqual({ name: "log", shell: "infra", count: 7 });
		expect(parsed("log -n=3")).toEqual({ name: "log", count: 3 });
		expect(error("log -n zero")).toContain("-n");
		expect(error("log -n 0")).toContain("-n");
		expect(error("log a b")).toContain("usage");
	});
});

describe("completeArguments", () => {
	const shells = [
		{ name: "infra", key: { rank: "A" as const } },
		{ name: "integ", key: { rank: "S" as const } },
	];
	const values = (prefix: string) => completeArguments(prefix, shells)?.map(i => i.value) ?? null;

	test("subcommands, then the joined xshells for the commands that take a name", () => {
		expect(values("")).toHaveLength(11);
		expect(values("l")).toEqual(["leave ", "list ", "log "]);
		expect(values("leave ")).toEqual(["leave infra ", "leave integ "]);
		expect(values("keys inf")).toEqual(["keys infra "]);
		expect(values("rotate ")).toEqual(["rotate infra "]); // masters only
		expect(values("destroy ")).toEqual(["destroy infra "]);
		expect(values("policy infra ")).toEqual(["policy infra ask ", "policy infra auto "]);
		expect(values("pending ")).toBeNull();
		expect(values("frob")).toBeNull();
		expect(values("inv")).toEqual(["invite "]);
		expect(values("invite ")).toEqual(["invite infra "]); // masters only
		expect(values("invite infra ")).toBeNull();
	});

	test("create/join options: only the subcommand's, not those already given", () => {
		expect(values("create lan --")).toEqual([
			"create lan --as ",
			"create lan --relay ",
			"create lan --notls ",
			"create lan --approve=ask ",
			"create lan --approve=auto ",
		]);
		expect(values("join xs2:k --notls --approve=auto --")).toEqual(["join xs2:k --notls --approve=auto --as ", "join xs2:k --notls --approve=auto --name "]);
		expect(values("create lan ")).toBeNull(); // the role is free text
	});

	test("join offers --relay only after an invitation UUID", () => {
		const uuid = "3f2b8c4e-1a5d-4e7f-9b2a-6c8d0e1f2a3b";
		expect(values(`join ${uuid} --`)).toEqual([`join ${uuid} --as `, `join ${uuid} --name `, `join ${uuid} --relay `, `join ${uuid} --notls `, `join ${uuid} --approve=ask `, `join ${uuid} --approve=auto `]);
		expect(values(`join ${uuid} --notls --re`)).toEqual([`join ${uuid} --notls --relay `]);
		expect(values(`join ${uuid} --relay r.example --re`)).toBeNull();
		expect(values("join xs2:k --re")).toBeNull();
	});
});
