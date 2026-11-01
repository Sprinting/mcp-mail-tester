// Find (or create) the KV namespace that stores OAuth grants, and write its
// id into the OAUTH_KV binding of wrangler.jsonc (committed without one) for
// this deploy. Idempotent; run by deploy.yml.
// WRANGLER_CMD overrides the wrangler command (default "npx wrangler").
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const TITLE = "mcp-mail-oauth";
const [cmd, ...pre] = (process.env.WRANGLER_CMD || "npx wrangler").split(" ").filter(Boolean);
const wrangler = (...args) => execFileSync(cmd, [...pre, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });

// The OAUTH_KV binding object, with or without an id.
const BINDING = /\{\s*"binding"\s*:\s*"OAUTH_KV"\s*(?:,\s*"id"\s*:\s*"([^"]*)"\s*)?\}/;

const path = new URL("../wrangler.jsonc", import.meta.url);
const config = readFileSync(path, "utf8");
const binding = BINDING.exec(config);
if (!binding) {
  console.error("wrangler.jsonc has no OAUTH_KV binding.");
  process.exit(1);
}

function findId() {
  const out = wrangler("kv", "namespace", "list");
  const list = JSON.parse(out.slice(out.indexOf("[")));
  return list.find((ns) => ns.title === TITLE)?.id;
}

let id = findId();
if (!id) {
  wrangler("kv", "namespace", "create", TITLE);
  id = findId();
}
if (!/^[0-9a-f]{32}$/.test(id ?? "")) {
  console.error(`Could not resolve KV namespace ${TITLE}.`);
  process.exit(1);
}

if (binding[1] !== id) writeFileSync(path, config.replace(BINDING, `{ "binding": "OAUTH_KV", "id": "${id}" }`));
console.log(`OAUTH_KV -> ${TITLE}`);
