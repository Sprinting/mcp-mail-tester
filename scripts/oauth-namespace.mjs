// The OAuth KV namespace, picked from `wrangler kv namespace list` output by
// title: "mcp-mail-oauth" (made by the deploy workflow) if it exists, else
// `<name in wrangler.jsonc>-oauth-kv` (what wrangler provisions for a Deploy
// button deploy). Shared by clients.mjs and rotate-token.mjs.
import { readFileSync } from "node:fs";

export const TITLE = "mcp-mail-oauth";

/** The Worker's top-level `name` in wrangler.jsonc (comments ignored), or undefined. */
function workerName() {
  try {
    const text = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8").replace(/^\s*\/\/.*$/gm, "");
    return /"name"\s*:\s*"([^"]+)"/.exec(text)?.[1];
  } catch {
    return undefined;
  }
}

/** Namespace id for the OAuth store from a parsed namespace list, or undefined. */
export function oauthNamespaceId(list) {
  const name = workerName();
  const titles = [TITLE, ...(name ? [`${name}-oauth-kv`] : [])];
  for (const title of titles) {
    const id = list.find((ns) => ns.title === title)?.id;
    if (id) return id;
  }
  return undefined;
}
