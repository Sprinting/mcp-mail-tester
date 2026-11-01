// The owner's GitHub Actions deploy path (.github/workflows/deploy.yml) edits
// wrangler.jsonc for one deploy only, in the runner's checkout, with two
// scripts. Neither runs in a Deploy-button deploy, which uses wrangler.jsonc
// as committed (workers.dev, OAUTH_KV without an id; see repo.test.ts).
//
// Both scripts edit the wrangler.jsonc next to their own directory
// (`new URL("../wrangler.jsonc", import.meta.url)`), so these tests copy each
// script into a temporary `scripts/` beside a temporary wrangler.jsonc and
// never touch the repository's file. Edits keep the file valid JSONC and
// leave every other setting as it was.
//
// scripts/set-domain.mjs (no secrets, no wrangler call):
// * WORKER_DOMAIN unset or empty -> exit 0, file byte-for-byte unchanged
//   (the deploy stays on workers.dev).
// * WORKER_DOMAIN a hostname (lowercase labels of [a-z0-9-], not starting or
//   ending with "-", at least one dot; no scheme, path, port, wildcard,
//   space) -> exit 0, `routes: [{ pattern: <host>, custom_domain: true }]`
//   and `workers_dev: false`.
// * Anything else -> exit 1 (before deploy), file unchanged, and the error
//   names WORKER_DOMAIN.
//
// scripts/ensure-kv.mjs (Cloudflare credentials, `wrangler kv namespace`):
// * Finds the namespace titled "mcp-mail-oauth" (`kv namespace list`), or
//   creates it (`kv namespace create mcp-mail-oauth`) and looks it up again,
//   so the owner's existing namespace and grants are kept.
// * Writes its id into the OAUTH_KV binding, which has none as committed.
//   Idempotent: a binding already holding that id is left as is, and a
//   second run changes nothing.
// * No OAUTH_KV binding in wrangler.jsonc -> exit 1, file unchanged.
// * No OAUTH_KV binding in wrangler.jsonc -> the error names OAUTH_KV.
// * The wrangler command defaults to `npx wrangler`; WRANGLER_CMD overrides
//   it (split on spaces), as for rotate-token and clients. (These tests also
//   put a failing `npx` first on PATH, so a script that ignores WRANGLER_CMD
//   fails at once instead of reaching a real wrangler.)

import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..", "..");
const fake = join(__dirname, "fixtures", "fake-wrangler-kv.mjs");
const NS = "0123456789abcdef0123456789abcdef";

/** wrangler.jsonc as committed after this change: comments, no routes, KV without id. */
const COMMITTED = `// Cloudflare Worker configuration.
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "mcp-mail",
  "main": "src/index.ts",
  "compatibility_date": "2026-10-01",
  "compatibility_flags": ["nodejs_compat", "global_fetch_strictly_public"],
  // workers.dev unless the deploy workflow sets WORKER_DOMAIN.
  "workers_dev": true,
  "keep_vars": true,
  "observability": { "enabled": true },
  "kv_namespaces": [
    // OAuth grants and tokens.
    { "binding": "OAUTH_KV" }
  ],
  "durable_objects": {
    "bindings": [{ "name": "RATE_LIMITER", "class_name": "RateLimiter" }]
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["RateLimiter"] }]
}
`;

function parse(text: string): any {
  const r = ts.parseConfigFileTextToJson("wrangler.jsonc", text);
  if (r.error) throw new Error(`wrangler.jsonc no longer parses: ${ts.flattenDiagnosticMessageText(r.error.messageText, "\n")}`);
  return r.config;
}

/** Everything but the keys a script may change. */
function rest(config: any, ...changed: string[]) {
  const copy = { ...config };
  for (const k of changed) delete copy[k];
  return copy;
}

function sandbox(script: string, config = COMMITTED) {
  const dir = mkdtempSync(join(tmpdir(), "deploy-scripts-"));
  mkdirSync(join(dir, "scripts"));
  const source = join(root, "scripts", script);
  expect(existsSync(source), `scripts/${script} exists`).toBe(true);
  copyFileSync(source, join(dir, "scripts", script));
  // A stand-in `npx` that always fails: the real one must never run here.
  mkdirSync(join(dir, "bin"));
  writeFileSync(join(dir, "bin", "npx"), "#!/bin/sh\necho 'npx is not available in this test; use WRANGLER_CMD' >&2\nexit 127\n");
  chmodSync(join(dir, "bin", "npx"), 0o755);
  const file = join(dir, "wrangler.jsonc");
  writeFileSync(file, config);
  const PATH = `${join(dir, "bin")}:${process.env.PATH ?? ""}`;
  return { dir, file, PATH, now: () => readFileSync(file, "utf8") };
}

describe("set-domain", () => {
  const run = (domain: string | undefined, config = COMMITTED) => {
    const box = sandbox("set-domain.mjs", config);
    const env: Record<string, string> = { PATH: box.PATH };
    if (domain !== undefined) env.WORKER_DOMAIN = domain;
    const r = spawnSync(process.execPath, ["scripts/set-domain.mjs"], { cwd: box.dir, env, encoding: "utf8", timeout: 30_000 });
    return { code: r.status, out: `${r.stdout}${r.stderr}`, text: box.now() };
  };

  it("leaves wrangler.jsonc untouched without WORKER_DOMAIN", () => {
    for (const domain of [undefined, ""]) {
      const r = run(domain);
      expect(r.code, r.out).toBe(0);
      expect(r.text).toBe(COMMITTED);
    }
  });

  it("serves a valid hostname as a custom domain instead of workers.dev", () => {
    for (const host of ["example.aroundand.in", "mail.example.com", "a-b.c1.example"]) {
      const r = run(host);
      expect(r.code, r.out).toBe(0);
      const c = parse(r.text);
      expect(c.routes, host).toEqual([{ pattern: host, custom_domain: true }]);
      expect(c.workers_dev, host).toBe(false);
      expect(rest(c, "routes", "workers_dev"), host).toEqual(rest(parse(COMMITTED), "routes", "workers_dev"));
    }
  });

  it("refuses anything that is not a bare hostname, before deploy", () => {
    for (const bad of ["https://example.com", "example.com/mcp", "example.com:8443", "localhost", "*.example.com", "exa mple.com", "-bad.example.com", "bad-.example.com", "example..com", "Example.com"]) {
      const r = run(bad);
      expect(r.code, bad).toBe(1);
      expect(r.text, bad).toBe(COMMITTED);
      expect(r.out, bad).toContain("WORKER_DOMAIN");
    }
  });
});

describe("ensure-kv", () => {
  const run = (namespaces: { id: string; title: string }[], config = COMMITTED) => {
    const box = sandbox("ensure-kv.mjs", config);
    const state = join(box.dir, "state.json");
    const log = join(box.dir, "log.jsonl");
    writeFileSync(state, JSON.stringify({ namespaces, keys: [] }));
    writeFileSync(log, "");
    const go = () => {
      const r = spawnSync(process.execPath, ["scripts/ensure-kv.mjs"], {
        cwd: box.dir,
        env: { PATH: box.PATH, WRANGLER_CMD: `${process.execPath} ${fake}`, FAKE_KV_STATE: state, FAKE_WRANGLER_LOG: log },
        encoding: "utf8",
        timeout: 30_000,
      });
      return { code: r.status, out: `${r.stdout}${r.stderr}` };
    };
    const calls = () => readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as string[]);
    const namespacesNow = () => JSON.parse(readFileSync(state, "utf8")).namespaces as { id: string; title: string }[];
    return { go, calls, namespacesNow, now: box.now };
  };
  const kvOf = (text: string) => parse(text).kv_namespaces;

  it("writes the existing mcp-mail-oauth id into the id-less OAUTH_KV binding", () => {
    const s = run([{ id: "f".repeat(32), title: "mcp-mail-oauth-kv" }, { id: NS, title: "mcp-mail-oauth" }]);
    const r = s.go();
    expect(r.code, r.out).toBe(0);
    expect(kvOf(s.now())).toEqual([{ binding: "OAUTH_KV", id: NS }]);
    expect(rest(parse(s.now()), "kv_namespaces")).toEqual(rest(parse(COMMITTED), "kv_namespaces"));
    expect(s.calls().some((c) => c.slice(0, 3).join(" ") === "kv namespace create"), "nothing created").toBe(false);
  });

  it("creates mcp-mail-oauth when it does not exist", () => {
    const s = run([{ id: "f".repeat(32), title: "other" }]);
    const r = s.go();
    expect(r.code, r.out).toBe(0);
    const created = s.namespacesNow().find((n) => n.title === "mcp-mail-oauth");
    expect(created, "namespace created").toBeTruthy();
    expect(created!.id).toMatch(/^[0-9a-f]{32}$/);
    expect(kvOf(s.now())).toEqual([{ binding: "OAUTH_KV", id: created!.id }]);
  });

  it("is idempotent", () => {
    const s = run([{ id: NS, title: "mcp-mail-oauth" }]);
    expect(s.go().code).toBe(0);
    const once = s.now();
    const again = s.go();
    expect(again.code, again.out).toBe(0);
    expect(s.now()).toBe(once);
    expect(kvOf(once)).toEqual([{ binding: "OAUTH_KV", id: NS }]);
  });

  it("refuses a wrangler.jsonc without an OAUTH_KV binding", () => {
    const config = COMMITTED.replace(`{ "binding": "OAUTH_KV" }`, `{ "binding": "OTHER_KV" }`);
    const s = run([{ id: NS, title: "mcp-mail-oauth" }], config);
    const r = s.go();
    expect(r.code).toBe(1);
    expect(r.out).toContain("OAUTH_KV");
    expect(s.now()).toBe(config);
    expect(s.calls().some((c) => c.slice(0, 3).join(" ") === "kv namespace create"), "nothing created").toBe(false);
  });
});
