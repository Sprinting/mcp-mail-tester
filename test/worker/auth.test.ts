// Authentication contract.
//
// The Worker is an OAuth 2.1 authorization server + protected resource,
// built on @cloudflare/workers-oauth-provider, with the MCP endpoint at
// `/mcp` as the only protected route.
//
// There is NO static bearer path. The operator token is used in exactly one
// place: the sign-in form on `/authorize`. `Authorization: Bearer <anything>`
// on `/mcp` is unauthenticated, so the old token (even the correct one) gets
// 401, an EMPTY body and a `WWW-Authenticate` header naming the resource
// metadata URL. The only way to call `/mcp` is an OAuth grant.
//
// The operator token is never stored server-side. The Worker holds only
// MCP_AUTH_TOKEN_SHA256 (from `npm run rotate-token` or the /setup page,
// pasted into the Cloudflare dashboard); a presented token is
// hashed with SHA-256 and compared to it in constant time
// (crypto.subtle.timingSafeEqual). Presenting the hash itself must fail.
//
// OAuth: discovery -> dynamic client registration -> /authorize -> /token,
// authorization code + PKCE S256. The `/authorize` page is ours: an HTML form
// where the operator types the token once. Right token ->
// provider.completeAuthorization -> 302 back to the client. Wrong token -> 401
// page, no redirect.
//
// Rules:
//   * `/mcp` without valid credentials -> 401, EMPTY body, with a
//     `WWW-Authenticate` header naming the resource metadata URL. No tool
//     logic runs (nothing sent, no rate-limit token spent).
//   * `/authorize` serves only redirect URIs the redirect rule allows
//     (`redirectAllowed`, src/index.ts): loopback http (localhost /
//     127.0.0.1, any port and path), allowlisted full https URLs, and
//     allowlisted bare hostnames matched exactly. Any other redirect_uri
//     (even for a registered client, even an https look-alike of an
//     allowlisted host) -> 400 page and NEVER a redirect. Malformed
//     requests -> 400, no redirect.
//   * The sign-in page: `X-Frame-Options: DENY`, CSP with
//     `frame-ancestors 'none'`, a password field named `token`, method POST,
//     no configured values in it. No `form-action 'self'` (browsers apply it
//     to the post-submit redirect and it would block the hop to the client).
//   * Client labels. Every connection has a label, so mail and limits can be
//     attributed to it:
//       - The sign-in page also asks for a label (text input name="label"),
//         pre-filled with `prefillLabel(clientName)` in its `value`
//         attribute: the suggestion is sanitised to the label grammar, but
//         the input is editable, required, and the POST handler still
//         validates the submitted value. An empty pre-fill (unknown client
//         name, or a reserved name like "operator") asks the human to type
//         one.
//       - A label is 1-32 chars of [a-z0-9-], starting with a letter or
//         digit (no uppercase, spaces, underscores). Only "operator" is
//         reserved: it names grants made before labels existed, so a human
//         may not claim it. "bearer" is an ordinary label now that the
//         static token is gone. A missing or invalid label with the RIGHT
//         token -> 400 page, no redirect, no code.
//       - The grant is created with `userId` = the label, so the OAuth KV
//         keys are `grant:<label>:...` / `token:<label>:...` and
//         `npm run clients` can list and revoke by label (test/node).
//         The label is also in the grant props, next to the fingerprint.
//       - Every email carries `X-MCP-Client: <label>` (mail.test.ts,
//         tools.test.ts) and ping reports the label as `client`.
//       - CLIENT_EMAIL_PER_MIN (optional): each label also gets its own
//         flat window (Durable Object name `${limiterName}:client:<label>`)
//         checked BEFORE the global EMAIL_PER_MIN window. A send must pass
//         both; one refused by its client window does not use the global
//         one. Refusals look exactly like the global limit (same error).
//         Unset -> only the global window applies.
//   * Grants carry a fingerprint of MCP_AUTH_TOKEN_SHA256; rotating the
//     token makes every previously issued OAuth token fail with 401.
//   * Stale grants clean themselves up (no sweep needed after a
//     dashboard-only rotation). A grant whose fingerprint no longer matches
//     the current hash is revoked (grant + its tokens, via the provider's
//     `revokeGrant(grantId, userId)`; userId/grantId come from the token
//     `userId:grantId:secret`) the first time it is used:
//       - `/mcp` with its access token -> exactly the unauthenticated answer:
//         401, EMPTY body, `cache-control: no-store`, the same
//         `WWW-Authenticate` challenge naming the resource metadata. No tool
//         logic, no rate-limit token, nothing sent.
//       - `/token` refresh, or exchanging an authorization code issued under
//         the old hash -> HTTP 400 `{"error":"invalid_grant"}`, no tokens.
//         (Mechanism: `tokenExchangeCallback` throwing the provider's
//         `OAuthError("invalid_grant")`, which also revokes the grant.)
//     Afterwards KV has no `grant:<label>:<grantId>` and no
//     `token:<label>:<grantId>:*` key for it; every other grant (even the
//     same label at the current fingerprint) and every `client:*`
//     registration is untouched.
//   * Claim state. MCP_AUTH_TOKEN_SHA256 is optional (config.test.ts):
//       - Unclaimed (valid config, no hash): `GET /setup` -> 200 setup page;
//         `GET /` -> 302 to `/setup`; EVERY other route (including /mcp, also
//         through the test seam, /authorize, /token, /register, /.well-known/*
//         and unknown paths) -> 503, EMPTY body, `cache-control: no-store`.
//         Nothing anonymous is written before the server is claimed: POST
//         /register creates no client and never reaches the rate limiter
//         (no 429, ever).
//       - Claimed (hash set): everything behaves as described above;
//         `GET /setup` still serves the same page (for rotation) and `GET /`
//         stays a 401/404 class answer without detail.
//   * The setup page (`GET /setup`; any other method -> 404 or 405, never the
//     page) is static: byte-identical whether or not (and to whatever) the
//     hash is set, and contains no configured value. One inline script and
//     nothing else executable: on load and on a "generate another" button it
//     takes 32 bytes from `crypto.getRandomValues`, shows them as 64 lowercase
//     hex (the token) and shows `crypto.subtle.digest("SHA-256", ...)` of the
//     token's UTF-8 bytes as 64 lowercase hex (the value of
//     MCP_AUTH_TOKEN_SHA256, the same derivation as rotate-token). No
//     <form>, no editable input (generate-only: no "hash my own token").
//     Headers: CSP `default-src 'none'`, `script-src` allowing ONLY the
//     inline script by its `'sha256-<base64>'` source (no 'unsafe-inline',
//     'unsafe-eval' or nonce), `style-src 'unsafe-inline'`,
//     `frame-ancestors 'none'`, every other directive 'none';
//     `X-Frame-Options: DENY`, `cache-control: no-store`,
//     `referrer-policy: no-referrer`. The text names MCP_AUTH_TOKEN_SHA256,
//     says to keep the token in a password manager, to paste the hash into
//     the Cloudflare dashboard as a Secret, and that saving a new hash signs
//     out every connected client.
//   * Credit link: the sign-in page and the setup page end with a plain
//     `<a href="https://aroundand.in" rel="noopener">` and load no external
//     resource. Tested in ONE isolated test, so a deployer can delete it.
//   * Public origin. PUBLIC_URL is optional. Set: used as today. Absent: the
//     origin is the request's. A loopback host (localhost, 127.0.0.1) keeps
//     its scheme and port; any other host must be https: a plain-http request
//     to a non-loopback host is answered with an empty 308 to the same URL on
//     https (never served, so OAuth never runs over http and the provider's
//     request-derived issuer always equals the advertised origin). The
//     resolved origin is the one in the resource metadata, the challenge and
//     the authorization server issuer.
//   * Brute-force / spam limits are PER CLIENT IP (`cf-connecting-ip`,
//     falling back to the literal "unknown" when the header is absent), so
//     one anonymous client cannot spend somebody else's budget. Each kind
//     has its own windows, held in the RateLimiter Durable Object:
//       - POST /register: a flat AUTH_ATTEMPTS_PER_MIN (10) per 60 s per IP.
//       - POST /authorize: only FAILED token attempts count, 10 per 60 s
//         per IP. The window is consulted on the wrong-token branch only,
//         so a successful sign-in, a label error (400 page) and a plain GET
//         of the page never consume a slot; a correct token signs in even
//         when that IP has spent its failures (it is not a failure).
//     Over the limit -> 429, never a redirect, no code, no client
//     registered. GET /authorize is not limited. These limits are separate
//     from the email limit.
//     A single GLOBAL window per kind would be an availability attack on
//     the operator: one anonymous client could 429 every sign-in and every
//     registration, locking the operator out of their own server.
//   * Every route (including /setup) answers 500 with an empty body when the
//     configuration is invalid, before doing anything else.
//
// The tool suites drive `/mcp` through the `authenticate` test seam (see
// test/worker/helpers.ts). Tests in this file that need the real OAuth
// provider on `/mcp` build `worker(vars, { oauth: true })`, which leaves the
// seam out.

import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { AUTH_ATTEMPTS_PER_MIN, createHandler } from "../../src/index";
import {
  ALICE, INVALID_REQUEST, PUBLIC, TOKEN, TOKEN_SHA256, baseVars, expectNoSecrets, expectRpcError, expectSent,
  mcpInit, parseRpc, varsWith, varsWithout, worker, type TestWorker, type Vars,
} from "./helpers";

const CALLBACK = "https://client.example.test/callback";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-verifier-xyz";
const LIST = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
const LIMIT = "email rate limit exceeded for this minute";
const RM = `${PUBLIC}/.well-known/oauth-protected-resource`;

/** Header naming the client IP each auth window is keyed on. */
const IP_HEADER = "cf-connecting-ip";
/** Two documentation-range addresses (RFC 5737): distinct client IPs. */
const IP_A = "198.51.100.10";
const IP_B = "203.0.113.20";

/** A second operator token and its hash: the configuration after a rotation. */
const ROTATED_TOKEN = "ffffffffffffffffffffffffffffffff-rotated";
const ROTATED_SHA256 = "50dc2b44f1bc3d28011dfa8705527346f8aab7df9a738a8955a8b51197896ef7";

/** Worker whose /mcp is guarded by the real OAuth provider (no test seam). */
const providerWorker = (vars = baseVars()) => worker(vars, { oauth: true });

async function challenge(v: string) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)));
  return btoa(String.fromCharCode(...d)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** POST /register from client IP `ip`; null sends no header (the "unknown" fallback bucket). */
async function registerFrom(w: TestWorker, ip: string | null, redirectUris: string[], clientName = "Example App") {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (ip !== null) headers[IP_HEADER] = ip;
  return w.fetch("/register", {
    method: "POST",
    headers,
    body: JSON.stringify({ client_name: clientName, redirect_uris: redirectUris, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
  });
}

async function register(w: TestWorker, redirectUris: string[], clientName = "Example App") {
  return registerFrom(w, null, redirectUris, clientName);
}

async function clientId(w: TestWorker, redirect = CALLBACK, clientName = "Example App") {
  const r = await register(w, [redirect], clientName);
  expect(r.status).toBe(201);
  return ((await r.json()) as any).client_id as string;
}

async function authorizeQuery(cid: string, redirect = CALLBACK) {
  return new URLSearchParams({
    response_type: "code", client_id: cid, redirect_uri: redirect, state: "st4te-123",
    code_challenge: await challenge(VERIFIER), code_challenge_method: "S256", resource: `${PUBLIC}/mcp`,
  }).toString();
}

/** POST the sign-in form from client IP `ip`; null sends no header (the "unknown" fallback bucket). */
async function submitFrom(w: TestWorker, ip: string | null, query: string, token: string, label: string | null = "personal") {
  const form = new URLSearchParams({ token });
  if (label !== null) form.set("label", label);
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (ip !== null) headers[IP_HEADER] = ip;
  return w.fetch(`/authorize?${query}`, {
    method: "POST",
    headers,
    body: form.toString(),
    redirect: "manual",
  });
}

async function submit(w: TestWorker, query: string, token: string, label: string | null = "personal") {
  return submitFrom(w, null, query, token, label);
}

async function getCode(w: TestWorker, cid: string, label = "personal", operatorToken = TOKEN) {
  const r = await submit(w, await authorizeQuery(cid), operatorToken, label);
  expect(r.status, await r.clone().text()).toBe(302);
  const loc = new URL(r.headers.get("location")!);
  expect(`${loc.origin}${loc.pathname}`).toBe(CALLBACK);
  expect(loc.searchParams.get("state")).toBe("st4te-123");
  return loc.searchParams.get("code")!;
}

async function token(w: TestWorker, form: Record<string, string>) {
  return w.fetch("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString() });
}

async function fullFlow(w: TestWorker, label = "personal", operatorToken = TOKEN) {
  const cid = await clientId(w);
  const code = await getCode(w, cid, label, operatorToken);
  const r = await token(w, { grant_type: "authorization_code", code, redirect_uri: CALLBACK, client_id: cid, code_verifier: VERIFIER, resource: `${PUBLIC}/mcp` });
  expect(r.status, await r.clone().text()).toBe(200);
  return { cid, tokens: (await r.json()) as any };
}

async function sendAs(w: TestWorker, token: string, subject: string) {
  return parseRpc(await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject, body: "b" } } }, token)));
}

/** A label no other test uses (KV may be shared between tests). */
const freshLabel = (prefix: string) => `${prefix}-${crypto.randomUUID().slice(0, 8)}`;

async function mcpStatus(w: TestWorker, bearer: string | null) {
  return (await w.fetch("/mcp", mcpInit(LIST, bearer))).status;
}

/** Grant id of an issued token (`userId:grantId:secret`). */
const grantOf = (issued: string) => issued.split(":")[1];

/** KV rows left for one grant: the grant record and its token keys. */
async function grantRows(label: string, grantId: string) {
  return {
    grant: await env.OAUTH_KV.get(`grant:${label}:${grantId}`),
    tokens: (await env.OAUTH_KV.list({ prefix: `token:${label}:${grantId}:` })).keys.map((k) => k.name),
  };
}

/** One request to a fresh handler at an arbitrary URL (`worker()` always requests PUBLIC). */
async function fetchAt(url: string, vars: Vars, init?: RequestInit) {
  const handler = createHandler({ limiterName: crypto.randomUUID() });
  const ctx = createExecutionContext();
  const res = await handler.fetch!(new Request(url, init) as any, { ...env, ...vars } as unknown as Env, ctx);
  await waitOnExecutionContext(ctx);
  return res as unknown as Response;
}

/** CSP header as { directive: [sources] }. */
function cspOf(r: Response) {
  const out: Record<string, string[]> = {};
  for (const d of (r.headers.get("content-security-policy") ?? "").split(";").map((s) => s.trim()).filter(Boolean)) {
    const [name, ...sources] = d.split(/\s+/);
    out[name.toLowerCase()] = sources;
  }
  return out;
}

async function sha256Base64(s: string) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return btoa(String.fromCharCode(...d));
}

/** The sign-in page's label input: its whole tag and its value attribute ("" if none). */
function labelInput(html: string) {
  const tag = html.match(/<input\b[^>]*\bname=["']label["'][^>]*>/i)?.[0];
  expect(tag, "sign-in page has a label input").toBeTruthy();
  return { tag: tag!, value: tag!.match(/\bvalue=["']([^"']*)["']/)?.[1] ?? "" };
}

describe("static bearer (removed)", () => {
  it("the correct operator token is not a credential on /mcp", async () => {
    const w = providerWorker();
    const r = await w.fetch("/mcp", mcpInit(LIST, TOKEN));
    expect(r.status).toBe(401);
    expect(await r.text()).toBe("");
    expect(r.headers.get("www-authenticate") ?? "").toContain(`resource_metadata="${RM}`);
  });

  it("rejects every Authorization value with the same empty 401 challenge", async () => {
    const w = providerWorker();
    for (const raw of [null, TOKEN, `Bearer ${TOKEN}`, `Basic ${TOKEN}`, `Bearer  ${TOKEN}`, `Bearer ${TOKEN}x`, "Bearer wrong"]) {
      const init = raw === null ? mcpInit(LIST) : mcpInit(LIST, null, { authorization: raw });
      const r = await w.fetch("/mcp", init);
      expect(r.status, String(raw)).toBe(401);
      expect(await r.text(), String(raw)).toBe("");
      expect(r.headers.get("www-authenticate") ?? "", String(raw)).toContain(`resource_metadata="${RM}`);
    }
  });

  it("the old token runs no tool logic and spends no rate-limit token", async () => {
    const w = providerWorker(varsWith({ EMAIL_PER_MIN: "1" }));
    const call = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } };
    expect((await w.fetch("/mcp", mcpInit(call, TOKEN))).status).toBe(401);
    expect(w.mailer.sent).toHaveLength(0);
    // A real grant still has its full budget: the refused request was not counted.
    const { tokens } = await fullFlow(w);
    expectSent(await sendAs(w, tokens.access_token, "s"));
    expectRpcError(await sendAs(w, tokens.access_token, "again"), INVALID_REQUEST, LIMIT);
    expect(w.mailer.sent).toHaveLength(1);
  });

  it("stateless: no session id, no handshake needed", async () => {
    const w = providerWorker();
    const { tokens } = await fullFlow(w);
    const init = await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } }, tokens.access_token));
    expect(init.status).toBe(200);
    expect(init.headers.get("mcp-session-id")).toBeNull();
    const r = await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } }, tokens.access_token));
    expect(r.headers.get("mcp-session-id")).toBeNull();
    expectSent(await parseRpc(r));
  });
});

describe("broken configuration", () => {
  it("every route answers an empty 500", async () => {
    // A missing hash is not broken any more (unclaimed); a malformed one is.
    for (const vars of [varsWith({ MCP_AUTH_TOKEN_SHA256: "not-a-sha256-hash" }), varsWith({ MAIL_DEFAULT_TO: "mallory@evil.example" })]) {
      const w = worker(vars);
      for (const [path, init] of [["/mcp", mcpInit(LIST, TOKEN)], ["/authorize", {}], ["/.well-known/oauth-authorization-server", {}], ["/", {}], ["/setup", {}]] as const) {
        const r = await w.fetch(path, init as RequestInit);
        expect(r.status, path).toBe(500);
        expect(await r.text()).toBe("");
      }
      expect(w.mailer.sent).toHaveLength(0);
    }
  });
});

describe("discovery", () => {
  it("protected resource metadata", async () => {
    const r = await worker().fetch("/.well-known/oauth-protected-resource/mcp");
    expect(r.status).toBe(200);
    const v = (await r.json()) as any;
    expect(v.resource).toBe(`${PUBLIC}/mcp`);
    expect(v.authorization_servers).toEqual([PUBLIC]);
  });

  it("authorization server metadata", async () => {
    const r = await worker().fetch("/.well-known/oauth-authorization-server");
    expect(r.status).toBe(200);
    const text = await r.text();
    expectNoSecrets(text, "AS metadata");
    const v = JSON.parse(text);
    expect(v.issuer).toBe(PUBLIC);
    expect(v.authorization_endpoint).toBe(`${PUBLIC}/authorize`);
    expect(v.token_endpoint).toBe(`${PUBLIC}/token`);
    expect(v.registration_endpoint).toBe(`${PUBLIC}/register`);
    expect(v.code_challenge_methods_supported).toEqual(["S256"]);
  });
});

describe("authorize page", () => {
  it("is a safe sign-in form", async () => {
    const w = worker();
    const r = await w.fetch(`/authorize?${await authorizeQuery(await clientId(w))}`);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toMatch(/^text\/html/);
    expect(r.headers.get("x-frame-options")).toBe("DENY");
    const csp = r.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    const fa = csp.split(";").map((s) => s.trim()).find((d) => d.startsWith("form-action"));
    if (fa) expect(fa, "form-action would block the redirect").toContain("https://client.example.test");
    const html = await r.text();
    expect(html).toMatch(/type="password"/);
    expect(html).toMatch(/name="token"/);
    expect(html).toMatch(/name="label"/);
    expect(html).toMatch(/method="post"/i);
    expectNoSecrets(html, "sign-in page");
  });

  it("escapes reflected values", async () => {
    const w = worker();
    const q = new URLSearchParams(await authorizeQuery(await clientId(w)));
    q.set("state", '"><script>alert(1)</script>');
    const html = await (await w.fetch(`/authorize?${q}`)).text();
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("pre-fills the label from the client name", async () => {
    const w = worker();
    const cid = await clientId(w, CALLBACK, "Example Desktop");
    const html = await (await w.fetch(`/authorize?${await authorizeQuery(cid)}`)).text();
    expect(labelInput(html).value).toBe("example-desktop");
  });

  it("pre-fills a sanitised value for an awkward client name", async () => {
    const w = worker();
    const cid = await clientId(w, CALLBACK, "Example.ai Connector");
    const html = await (await w.fetch(`/authorize?${await authorizeQuery(cid)}`)).text();
    expect(labelInput(html).value).toBe("example-ai-connector");
  });

  it("the pre-filled label is editable, required, and still validated on POST", async () => {
    const w = worker();
    const cid = await clientId(w, CALLBACK, "Example Desktop");
    const q = await authorizeQuery(cid);
    const { tag, value } = labelInput(await (await w.fetch(`/authorize?${q}`)).text());
    expect(value).toBe("example-desktop");
    expect(tag).toMatch(/\brequired\b/);
    expect(tag).not.toMatch(/\breadonly\b|\bdisabled\b/);
    // The suggestion itself is a valid label...
    expect((await submit(w, q, TOKEN, "example-desktop")).status).toBe(302);
    // ...the human may replace it...
    expect((await submit(w, q, TOKEN, "my-phone")).status).toBe(302);
    // ...and the POST handler still enforces the grammar.
    expect((await submit(w, q, TOKEN, "My Phone")).status).toBe(400);
  });

  it("a reserved client name pre-fills empty, unlike an ordinary one", async () => {
    const w = worker();
    const ordinary = await clientId(w, CALLBACK, "Example Desktop");
    const reserved = await clientId(w, CALLBACK, "operator");
    const ordinaryHtml = await (await w.fetch(`/authorize?${await authorizeQuery(ordinary)}`)).text();
    const reservedHtml = await (await w.fetch(`/authorize?${await authorizeQuery(reserved)}`)).text();
    expect(labelInput(ordinaryHtml).value).toBe("example-desktop");
    expect(labelInput(reservedHtml).value).toBe("");
  });

  it("rejects redirect URIs off the list, even for registered clients", async () => {
    const w = worker();
    for (const evil of ["https://evil.example/callback", "https://evil.vendor.example.attacker.net/cb", "https://vendor.example.evil.net/cb"]) {
      const reg = await register(w, [evil]);
      const cid = reg.status === 201 ? ((await reg.json()) as any).client_id : await clientId(w);
      const q = await authorizeQuery(cid, evil);
      const g = await w.fetch(`/authorize?${q}`, { redirect: "manual" });
      expect(g.status, evil).toBe(400);
      expect(g.headers.get("location"), evil).toBeNull();
      const p = await submit(w, q, TOKEN);
      expect(p.status, evil).toBe(400);
      expect(p.headers.get("location"), evil).toBeNull();
    }
  });

  it("allows the redirects the new rule permits: loopback and allowlisted bare hosts", async () => {
    // Hosted callbacks are opt-in, so the bare host has to be configured.
    const w = worker(varsWith({ OAUTH_REDIRECT_URIS: "https://client.example.test/callback,vendor.example" }));
    for (const redirect of ["http://localhost:33418/callback", "http://127.0.0.1:8976/oauth/done", "https://vendor.example/connector/oauth/callback"]) {
      const cid = await clientId(w, redirect);
      const r = await w.fetch(`/authorize?${await authorizeQuery(cid, redirect)}`);
      expect(r.status, redirect).toBe(200);
      expect(r.headers.get("content-type"), redirect).toMatch(/^text\/html/);
      expect(await r.text(), redirect).toContain('name="token"');
    }
  });

  it("rejects malformed requests without redirecting", async () => {
    const w = worker();
    const base = new URLSearchParams(await authorizeQuery(await clientId(w)));
    const variants = [
      (q: URLSearchParams) => q.delete("redirect_uri"),
      (q: URLSearchParams) => q.set("response_type", "token"),
      (q: URLSearchParams) => q.set("client_id", "no-such-client"),
      (q: URLSearchParams) => q.delete("code_challenge"),
    ];
    for (const mutate of variants) {
      const q = new URLSearchParams(base);
      mutate(q);
      for (const r of [await w.fetch(`/authorize?${q}`, { redirect: "manual" }), await submit(w, q.toString(), TOKEN)]) {
        expect(r.status, q.toString()).toBeGreaterThanOrEqual(400);
        expect(r.status).toBeLessThan(500);
        const loc = r.headers.get("location");
        expect(loc === null || !loc.startsWith(CALLBACK) || !new URL(loc).searchParams.has("code"), "no code issued").toBe(true);
      }
    }
  });

  it("wrong operator token issues no code", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    for (const t of ["", "nope", TOKEN.slice(0, -1), `${TOKEN}x`]) {
      const r = await submit(w, q, t);
      expect(r.status, t).toBe(401);
      expect(r.headers.get("location")).toBeNull();
    }
  });

  it("redirect allowlist is configurable", async () => {
    const w = worker(varsWith({ OAUTH_REDIRECT_URIS: "https://custom.example/cb" }));
    const custom = await clientId(w, "https://custom.example/cb");
    expect((await w.fetch(`/authorize?${await authorizeQuery(custom, "https://custom.example/cb")}`)).status).toBe(200);
    const client = await clientId(w);
    expect((await w.fetch(`/authorize?${await authorizeQuery(client)}`, { redirect: "manual" })).status).toBe(400);
    // A bare-host entry covers any path on that host, still no look-alikes.
    const hosted = worker(varsWith({ OAUTH_REDIRECT_URIS: "custom.example" }));
    const ok = await clientId(hosted, "https://custom.example/any/path");
    expect((await hosted.fetch(`/authorize?${await authorizeQuery(ok, "https://custom.example/any/path")}`)).status).toBe(200);
    const lookalike = await clientId(hosted, "https://custom.example.evil.net/cb");
    expect((await hosted.fetch(`/authorize?${await authorizeQuery(lookalike, "https://custom.example.evil.net/cb")}`, { redirect: "manual" })).status).toBe(400);
  });
});

describe("OAuth flow", () => {
  it("issues tokens that work on /mcp", async () => {
    const w = providerWorker();
    const { tokens } = await fullFlow(w);
    expect(tokens.token_type.toLowerCase()).toBe("bearer");
    expect(tokens.access_token).not.toBe(TOKEN);
    expect(typeof tokens.refresh_token).toBe("string");
    expect(await mcpStatus(w, tokens.access_token)).toBe(200);
    const r = await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } }, tokens.access_token));
    expectSent(await parseRpc(r));
  });

  it("codes are single-use and PKCE-bound", async () => {
    const w = worker();
    const cid = await clientId(w);
    const code = await getCode(w, cid);
    const bad = await token(w, { grant_type: "authorization_code", code, redirect_uri: CALLBACK, client_id: cid, code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-x" });
    expect(bad.status).toBe(400);
    const code2 = await getCode(w, cid);
    const ok = await token(w, { grant_type: "authorization_code", code: code2, redirect_uri: CALLBACK, client_id: cid, code_verifier: VERIFIER });
    expect(ok.status).toBe(200);
    const replay = await token(w, { grant_type: "authorization_code", code: code2, redirect_uri: CALLBACK, client_id: cid, code_verifier: VERIFIER });
    expect(replay.status).toBe(400);
  });

  it("refresh tokens are not bearer tokens", async () => {
    const w = providerWorker();
    const { cid, tokens } = await fullFlow(w);
    expect(await mcpStatus(w, tokens.refresh_token)).toBe(401);
    const r = await token(w, { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: cid });
    expect(r.status).toBe(200);
    expect(await mcpStatus(w, ((await r.json()) as any).access_token)).toBe(200);
  });

  it("rotating the token revokes issued tokens", async () => {
    const w = providerWorker();
    const { tokens } = await fullFlow(w);
    // sha256("ffffffffffffffffffffffffffffffff-rotated")
    const rotated = providerWorker(varsWith({ MCP_AUTH_TOKEN_SHA256: "50dc2b44f1bc3d28011dfa8705527346f8aab7df9a738a8955a8b51197896ef7" }));
    // The original worker first: once the rotated one sees the token it revokes the grant.
    expect(await mcpStatus(w, tokens.access_token)).toBe(200);
    expect(await mcpStatus(rotated, tokens.access_token)).toBe(401);
  });
});

describe("stale grants", () => {
  it("a stale access token gets the unauthenticated 401 and its grant is revoked", async () => {
    const w = providerWorker();
    const label = freshLabel("stale");
    const { cid, tokens } = await fullFlow(w, label);
    const grantId = grantOf(tokens.access_token);
    expect((await grantRows(label, grantId)).grant).not.toBeNull();
    const rotated = providerWorker(varsWith({ MCP_AUTH_TOKEN_SHA256: ROTATED_SHA256 }));
    const r = await rotated.fetch("/mcp", mcpInit(LIST, tokens.access_token));
    expect(r.status).toBe(401);
    expect(await r.text()).toBe("");
    expect(r.headers.get("www-authenticate") ?? "").toContain(`resource_metadata="${RM}`);
    expect(r.headers.get("cache-control") ?? "").toContain("no-store");
    expect(await grantRows(label, grantId)).toEqual({ grant: null, tokens: [] });
    expect(await env.OAUTH_KV.get(`client:${cid}`), "client registration kept").not.toBeNull();
    // Revoked, not merely mismatched: even the old configuration rejects it now.
    expect(await mcpStatus(w, tokens.access_token)).toBe(401);
  });

  it("revokes only the stale grant: same label at the current fingerprint keeps working, nothing sent or counted", async () => {
    const label = freshLabel("both");
    const old = providerWorker();
    const stale = (await fullFlow(old, label)).tokens.access_token;
    const rotated = providerWorker(varsWith({ MCP_AUTH_TOKEN_SHA256: ROTATED_SHA256, EMAIL_PER_MIN: "1" }));
    const current = (await fullFlow(rotated, label, ROTATED_TOKEN)).tokens.access_token;
    expect(grantOf(current)).not.toBe(grantOf(stale));

    const call = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "stale", body: "b" } } };
    expect((await rotated.fetch("/mcp", mcpInit(call, stale))).status).toBe(401);
    expect(rotated.mailer.sent).toHaveLength(0);
    expect(await grantRows(label, grantOf(stale))).toEqual({ grant: null, tokens: [] });

    const kept = await grantRows(label, grantOf(current));
    expect(kept.grant).not.toBeNull();
    expect(kept.tokens.length).toBeGreaterThan(0);
    // The refused call spent nothing: the current grant has the whole budget of one.
    expectSent(await sendAs(rotated, current, "fresh"));
    expectRpcError(await sendAs(rotated, current, "again"), INVALID_REQUEST, LIMIT);
    expect(rotated.mailer.sent.map((m) => m.subject)).toEqual(["fresh"]);
  });

  it("refreshing a stale grant is invalid_grant and revokes it", async () => {
    const w = providerWorker();
    const label = freshLabel("refresh");
    const { cid, tokens } = await fullFlow(w, label);
    const rotated = providerWorker(varsWith({ MCP_AUTH_TOKEN_SHA256: ROTATED_SHA256 }));
    const r = await token(rotated, { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: cid });
    expect(r.status).toBe(400);
    const body = (await r.json()) as any;
    expect(body.error).toBe("invalid_grant");
    expect(body.access_token).toBeUndefined();
    expect(await grantRows(label, grantOf(tokens.refresh_token))).toEqual({ grant: null, tokens: [] });
    expect(await env.OAUTH_KV.get(`client:${cid}`), "client registration kept").not.toBeNull();
    // Gone for good: the old configuration cannot refresh it either.
    expect((await token(w, { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: cid })).status).toBe(400);
  });

  it("a code issued before a rotation does not exchange after it", async () => {
    const w = providerWorker();
    const label = freshLabel("code");
    const cid = await clientId(w);
    const code = await getCode(w, cid, label);
    const rotated = providerWorker(varsWith({ MCP_AUTH_TOKEN_SHA256: ROTATED_SHA256 }));
    const r = await token(rotated, { grant_type: "authorization_code", code, redirect_uri: CALLBACK, client_id: cid, code_verifier: VERIFIER, resource: `${PUBLIC}/mcp` });
    expect(r.status).toBe(400);
    const body = (await r.json()) as any;
    expect(body.error).toBe("invalid_grant");
    expect(body.access_token).toBeUndefined();
    expect((await env.OAUTH_KV.list({ prefix: `grant:${label}:` })).keys).toEqual([]);
  });
});

describe("unclaimed server (no token hash)", () => {
  const unclaimed = () => varsWithout("MCP_AUTH_TOKEN_SHA256");

  it("GET / redirects to /setup, which serves the setup page", async () => {
    const w = worker(unclaimed());
    const root = await w.fetch("/", { redirect: "manual" });
    expect(root.status).toBe(302);
    expect(new URL(root.headers.get("location") ?? "", PUBLIC).pathname).toBe("/setup");
    const setup = await w.fetch("/setup");
    expect(setup.status).toBe(200);
    expect(setup.headers.get("content-type") ?? "").toMatch(/^text\/html/);
  });

  it("every other route is an empty 503, through the provider and through the test seam", async () => {
    const q = new URLSearchParams({ response_type: "code", client_id: "some-client", redirect_uri: CALLBACK, state: "s", code_challenge: await challenge(VERIFIER), code_challenge_method: "S256" });
    const form = { "content-type": "application/x-www-form-urlencoded" };
    const requests: [string, RequestInit][] = [
      ["/mcp", mcpInit(LIST)],
      ["/mcp", mcpInit(LIST, "personal:grant:secret")],
      ["/authorize?" + q, {}],
      ["/authorize?" + q, { method: "POST", headers: form, body: new URLSearchParams({ token: TOKEN, label: "personal" }).toString() }],
      ["/token", { method: "POST", headers: form, body: "grant_type=refresh_token&refresh_token=a:b:c&client_id=x" }],
      ["/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [CALLBACK] }) }],
      ["/.well-known/oauth-authorization-server", {}],
      ["/.well-known/oauth-protected-resource/mcp", {}],
      ["/admin", {}],
      ["/mcp/extra", {}],
    ];
    for (const w of [worker(unclaimed()), providerWorker(unclaimed())]) {
      for (const [path, init] of requests) {
        const r = await w.fetch(path, { ...init, redirect: "manual" });
        const what = `${init.method ?? "GET"} ${path}`;
        expect(r.status, what).toBe(503);
        expect(await r.text(), what).toBe("");
        expect(r.headers.get("cache-control") ?? "", what).toContain("no-store");
        expect(r.headers.get("location"), what).toBeNull();
      }
      // The seam's /mcp would send mail if it were reached.
      expect((await w.fetch("/mcp", mcpInit({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_email", arguments: { to: ALICE, subject: "s", body: "b" } } }))).status).toBe(503);
      expect(w.mailer.sent).toHaveLength(0);
    }
  });

  it("registration writes nothing and never reaches the rate limiter", async () => {
    const w = worker(unclaimed());
    // A name no other test uses, so the KV check below is scoped to this test's attempts.
    const name = `unclaimed-${crypto.randomUUID()}`;
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN + 2; i++) {
      const r = await registerFrom(w, IP_A, [CALLBACK], name);
      expect(r.status, `register ${i}`).toBe(503);
      expect(r.headers.get("retry-after"), `register ${i}`).toBeNull();
    }
    for (const { name: key } of (await env.OAUTH_KV.list({ prefix: "client:" })).keys) {
      expect(await env.OAUTH_KV.get(key), key).not.toContain(name);
    }
  });
});

describe("setup page", () => {
  it("is a static, locked-down page that reveals nothing about the configuration", async () => {
    const pages = [
      await worker(varsWithout("MCP_AUTH_TOKEN_SHA256")).fetch("/setup"),
      await worker().fetch("/setup"),
      await worker(varsWith({ MCP_AUTH_TOKEN_SHA256: ROTATED_SHA256 })).fetch("/setup"),
    ];
    const bodies: string[] = [];
    for (const r of pages) {
      expect(r.status).toBe(200);
      expect(r.headers.get("content-type") ?? "").toMatch(/^text\/html/);
      expect(r.headers.get("x-frame-options")).toBe("DENY");
      expect(r.headers.get("cache-control") ?? "").toContain("no-store");
      expect(r.headers.get("referrer-policy")).toBe("no-referrer");
      bodies.push(await r.text());
    }
    // Same bytes whether unclaimed or claimed, whatever the hash.
    expect(bodies[1]).toBe(bodies[0]);
    expect(bodies[2]).toBe(bodies[0]);
    expect(pages[1].headers.get("content-security-policy")).toBe(pages[0].headers.get("content-security-policy"));
    expectNoSecrets(bodies[0], "setup page");
    expect(bodies[0]).not.toContain(ROTATED_SHA256);
  });

  it("allows only its own inline script, by hash, and nothing else", async () => {
    const r = await worker().fetch("/setup");
    const html = await r.text();
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    expect(scripts, "exactly one script").toHaveLength(1);
    expect(scripts[0][1], "inline, not loaded").not.toMatch(/\bsrc\s*=/i);
    const markup = html.replace(scripts[0][0], "");
    expect(markup, "no inline event handlers").not.toMatch(/<[^>]*\son[a-z]+\s*=/i);
    expect(markup, "no javascript: URLs").not.toMatch(/javascript:/i);
    const csp = cspOf(r);
    expect(csp["default-src"]).toEqual(["'none'"]);
    expect(csp["script-src"]).toEqual([`'sha256-${await sha256Base64(scripts[0][2])}'`]);
    expect(csp["style-src"]).toContain("'unsafe-inline'");
    expect(csp["frame-ancestors"]).toEqual(["'none'"]);
    for (const [name, sources] of Object.entries(csp)) {
      if (name === "script-src" || name === "style-src") continue;
      expect(sources, name).toEqual(["'none'"]);
    }
  });

  it("generates a token and its hash in the browser, with no way to submit anything", async () => {
    const html = await (await worker().fetch("/setup")).text();
    expect(html).not.toMatch(/<form\b/i);
    for (const tag of html.match(/<(input|textarea)\b[^>]*>/gi) ?? []) expect(tag, "inputs are read-only").toMatch(/\breadonly\b/i);
    expect(html).not.toMatch(/\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket/);
    expect(html).toContain("crypto.getRandomValues");
    expect(html).toContain("crypto.subtle.digest");
    expect(html).toContain("SHA-256");
    expect(html).toMatch(/<button\b/i);
  });

  it("tells the operator what to do with the token and the hash", async () => {
    const html = await (await worker().fetch("/setup")).text();
    expect(html).toContain("MCP_AUTH_TOKEN_SHA256");
    const lower = html.toLowerCase();
    expect(lower).toContain("password manager");
    expect(lower).toContain("cloudflare");
    expect(lower).toContain("secret");
    expect(lower).toMatch(/signs? out|sign in again/);
  });

  it("only GET serves the page", async () => {
    for (const vars of [baseVars(), varsWithout("MCP_AUTH_TOKEN_SHA256")]) {
      const w = worker(vars);
      for (const method of ["POST", "PUT", "DELETE"]) {
        const r = await w.fetch("/setup", { method, headers: { "content-type": "application/x-www-form-urlencoded" }, body: "token=x" });
        expect([404, 405], method).toContain(r.status);
        expect(await r.text(), method).not.toMatch(/<script/i);
      }
    }
  });
});

describe("credit link", () => {
  it("the sign-in and setup pages end with a plain link to aroundand.in", async () => {
    const w = worker();
    const signIn = await (await w.fetch(`/authorize?${await authorizeQuery(await clientId(w))}`)).text();
    const setup = await (await w.fetch("/setup")).text();
    for (const [what, html] of [["sign-in page", signIn], ["setup page", setup]]) {
      const a = html.match(/<a\b[^>]*\bhref="https:\/\/aroundand\.in\/?"[^>]*>/i)?.[0];
      expect(a, what).toBeTruthy();
      expect(a!, what).toMatch(/\brel="[^"]*\bnoopener\b[^"]*"/);
      const markup = html.replace(/<script\b[\s\S]*?<\/script>/gi, "");
      expect(markup, `${what}: no external resources`).not.toMatch(/<(img|link|iframe|object|embed)\b|\bsrc\s*=/i);
      expect(html, `${what}: no external script`).not.toMatch(/<script\b[^>]*\bsrc\s*=/i);
    }
  });
});

describe("public origin", () => {
  const noPublicUrl = () => varsWithout("PUBLIC_URL");

  it("without PUBLIC_URL, metadata, issuer and challenge use the request's origin", async () => {
    for (const origin of [PUBLIC, "https://other-host.example.test"]) {
      const as = await fetchAt(`${origin}/.well-known/oauth-authorization-server`, noPublicUrl());
      expect(as.status, origin).toBe(200);
      const meta = (await as.json()) as any;
      expect(meta.issuer).toBe(origin);
      expect(meta.token_endpoint).toBe(`${origin}/token`);
      const pr = await fetchAt(`${origin}/.well-known/oauth-protected-resource/mcp`, noPublicUrl());
      expect(pr.status, origin).toBe(200);
      const v = (await pr.json()) as any;
      expect(v.resource).toBe(`${origin}/mcp`);
      expect(v.authorization_servers).toEqual([origin]);
      const r = await fetchAt(`${origin}/mcp`, noPublicUrl(), mcpInit(LIST));
      expect(r.status).toBe(401);
      expect(r.headers.get("www-authenticate") ?? "").toContain(`resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`);
    }
  });

  it("a loopback host keeps its scheme and port", async () => {
    for (const origin of ["http://localhost:8787", "http://127.0.0.1:8787"]) {
      const as = await fetchAt(`${origin}/.well-known/oauth-authorization-server`, noPublicUrl());
      expect(as.status, origin).toBe(200);
      expect(((await as.json()) as any).issuer).toBe(origin);
      const pr = await fetchAt(`${origin}/.well-known/oauth-protected-resource/mcp`, noPublicUrl());
      expect(((await pr.json()) as any).resource).toBe(`${origin}/mcp`);
    }
  });

  it("plain http on a public host is redirected to https, never served", async () => {
    const http = "http://other-host.example.test";
    const requests: [string, RequestInit][] = [
      ["/.well-known/oauth-authorization-server?x=1", {}],
      ["/mcp", mcpInit(LIST)],
      ["/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "grant_type=refresh_token" }],
      ["/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [CALLBACK] }) }],
    ];
    for (const [path, init] of requests) {
      const r = await fetchAt(`${http}${path}`, noPublicUrl(), { ...init, redirect: "manual" });
      expect(r.status, path).toBe(308);
      expect(r.headers.get("location"), path).toBe(`https://other-host.example.test${path}`);
      expect(await r.text(), path).toBe("");
    }
  });

  it("the full OAuth flow works without PUBLIC_URL", async () => {
    const w = providerWorker(noPublicUrl());
    const { tokens } = await fullFlow(w, freshLabel("derived"));
    expect(await mcpStatus(w, tokens.access_token)).toBe(200);
  });
});

describe("hashed token", () => {
  it("the stored hash is not itself a credential", async () => {
    const w = providerWorker();
    expect(await mcpStatus(w, TOKEN_SHA256)).toBe(401);
    const r = await submit(w, await authorizeQuery(await clientId(w)), TOKEN_SHA256);
    expect(r.status).toBe(401);
    expect(r.headers.get("location")).toBeNull();
  });
});

describe("sign-in and registration limits", () => {
  // A single GLOBAL window per kind would be an availability attack on the
  // operator: one anonymous client could spend it and 429 every sign-in and
  // every registration, locking the operator out of their own server. The
  // budget must therefore be per client IP. A request's IP is the
  // `cf-connecting-ip` header; requests without it all share the literal
  // "unknown" window, because the Worker has nothing else to key on (the
  // connection address is overwritten by Cloudflare's edge).

  it("is 10 per minute", () => {
    expect(AUTH_ATTEMPTS_PER_MIN).toBe(10);
  });

  it("sign-in failure windows are per client IP: one IP exhausting its own does not lock another out", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    // IP_A spends its whole failure budget.
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      expect((await submitFrom(w, IP_A, q, `wrong-a-${i}`)).status, `IP_A failure ${i}`).toBe(401);
    }
    expect((await submitFrom(w, IP_A, q, "wrong-a-10")).status).toBe(429);
    // IP_B never failed: its failed token is still the ordinary 401 page,
    // and its correct token still signs in.
    expect((await submitFrom(w, IP_B, q, "wrong-b")).status).toBe(401);
    const ok = await submitFrom(w, IP_B, q, TOKEN);
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).toContain(CALLBACK);
  });

  it("the 11th failed token from one IP is the 429 page, never a redirect", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    // Ten failed tokens: each is the ordinary 401 page.
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      const r = await submitFrom(w, IP_A, q, `wrong-${i}`);
      expect(r.status, `failure ${i}`).toBe(401);
      expect(r.headers.get("location"), `failure ${i}`).toBeNull();
    }
    // The eleventh failed token is the 429 page: HTML, no Location, no secret.
    const over = await submitFrom(w, IP_A, q, "wrong-10");
    expect(over.status).toBe(429);
    expect(over.headers.get("location")).toBeNull();
    expect(over.headers.get("content-type") ?? "").toMatch(/^text\/html/);
    const html = await over.text();
    expect(html.length).toBeGreaterThan(0);
    expectNoSecrets(html, "429 page");
    // And the limit follows the IP, not the bucket: another IP gets the 401 page.
    expect((await submitFrom(w, IP_B, q, "wrong-b")).status).toBe(401);
  });

  it("successful sign-ins never consume a failure slot: 12 inside a minute all redirect", async () => {
    const w = worker();
    const cid = await clientId(w);
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN + 2; i++) {
      const r = await submitFrom(w, IP_A, await authorizeQuery(cid), TOKEN);
      expect(r.status, `success ${i}`).toBe(302);
      expect(r.headers.get("location"), `success ${i}`).toContain(CALLBACK);
    }
  });

  it("failed token attempts, not successful ones, use up the sign-in window", async () => {
    const w = worker();
    const cid = await clientId(w);
    // Ten valid sign-ins would exhaust an all-attempts window...
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      expect((await submitFrom(w, IP_A, await authorizeQuery(cid), TOKEN)).status, `success ${i}`).toBe(302);
    }
    // ...but the failure window is untouched: ten failures are still allowed.
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      expect((await submitFrom(w, IP_A, await authorizeQuery(cid), `wrong-${i}`)).status, `failure ${i}`).toBe(401);
    }
    expect((await submitFrom(w, IP_A, await authorizeQuery(cid), "wrong-10")).status).toBe(429);
  });

  it("label errors are not failed sign-ins and do not consume the failure window", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    // The token is right, the label is not: 400 page, no redirect, no slot.
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      const r = await submitFrom(w, IP_A, q, TOKEN, "Not A Label");
      expect(r.status, `label error ${i}`).toBe(400);
      expect(r.headers.get("location"), `label error ${i}`).toBeNull();
    }
    // None of that was a failed token: ten wrong tokens are still allowed.
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      expect((await submitFrom(w, IP_A, q, `wrong-${i}`)).status, `failure ${i}`).toBe(401);
    }
    expect((await submitFrom(w, IP_A, q, "wrong-10")).status).toBe(429);
  });

  it("a wrong token followed by the correct token still signs in while under the cap", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    // Nine failures from IP_A: below the ten-failure cap.
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN - 1; i++) {
      expect((await submitFrom(w, IP_A, q, `wrong-${i}`)).status, `failure ${i}`).toBe(401);
    }
    // A failure from another IP does not count against IP_A's window...
    expect((await submitFrom(w, IP_B, q, "wrong-b")).status).toBe(401);
    // ...so IP_A's next attempt, with the right token, still redirects.
    const r = await submitFrom(w, IP_A, q, TOKEN);
    expect(r.status).toBe(302);
    expect(r.headers.get("location")).toContain(CALLBACK);
  });

  it("client registration windows are per IP", async () => {
    const w = worker();
    // IP_A registers its ten clients...
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      expect((await registerFrom(w, IP_A, [CALLBACK])).status, `register ${i}`).toBe(201);
    }
    // ...then gets the empty 429 with a 60 s hint, never a redirect.
    const over = await registerFrom(w, IP_A, [CALLBACK]);
    expect(over.status).toBe(429);
    expect(await over.text()).toBe("");
    expect(over.headers.get("retry-after")).toBe("60");
    expect(over.headers.get("location")).toBeNull();
    // IP_B has its own window: it still registers.
    const fresh = await registerFrom(w, IP_B, [CALLBACK]);
    expect(fresh.status).toBe(201);
    expect(((await fresh.json()) as any).client_id).toBeTruthy();
  });

  it("registration windows are independent of sign-in and of email", async () => {
    const w = worker();
    // Register one client from IP_A, then exhaust IP_A's registration window.
    const reg = await registerFrom(w, IP_A, [CALLBACK]);
    expect(reg.status).toBe(201);
    const cid = ((await reg.json()) as any).client_id as string;
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN - 1; i++) {
      expect((await registerFrom(w, IP_A, [CALLBACK])).status, `register ${i}`).toBe(201);
    }
    expect((await registerFrom(w, IP_A, [CALLBACK])).status).toBe(429);
    // Sign-in is a different window: IP_A still gets the 401 page and a redirect.
    expect((await submitFrom(w, IP_A, await authorizeQuery(cid), "wrong")).status).toBe(401);
    expect((await submitFrom(w, IP_A, await authorizeQuery(cid), TOKEN)).status).toBe(302);
    // Per IP: another IP still registers...
    expect((await registerFrom(w, IP_B, [CALLBACK])).status).toBe(201);
    // ...and the email limit is separate: /mcp still sends.
    expectSent(await w.sendEmail(ALICE, "s", "b"));
  });

  it("requests without cf-connecting-ip share the fallback \"unknown\" window", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    // Ten headerless failures all land in one fallback bucket...
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      expect((await submitFrom(w, null, q, `wrong-${i}`)).status, `failure ${i}`).toBe(401);
    }
    // ...so the next headerless failure is limited...
    expect((await submitFrom(w, null, q, "wrong-10")).status).toBe(429);
    // ...while a request that names its IP has its own window.
    expect((await submitFrom(w, IP_A, q, "wrong-a")).status).toBe(401);
  });

  it("GET /authorize is never limited, and only failures are", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    for (let i = 0; i < AUTH_ATTEMPTS_PER_MIN; i++) {
      expect((await submitFrom(w, IP_A, q, `wrong-${i}`)).status, `failure ${i}`).toBe(401);
    }
    expect((await submitFrom(w, IP_A, q, "wrong-10")).status).toBe(429);
    // Rendering the page is not an attempt, however often it is fetched.
    for (let i = 0; i < 3; i++) {
      const r = await w.fetch(`/authorize?${q}`);
      expect(r.status, `GET ${i}`).toBe(200);
      expect(r.headers.get("content-type") ?? "", `GET ${i}`).toMatch(/^text\/html/);
      expect(await r.text(), `GET ${i}`).toContain('name="token"');
    }
    // The window counts failures only: the correct token still signs in.
    const ok = await submitFrom(w, IP_A, q, TOKEN);
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).toContain(CALLBACK);
  });
});

describe("other routes", () => {
  it("unknown paths 404 without detail", async () => {
    const w = worker();
    for (const p of ["/", "/admin", "/mcp/extra"]) {
      const r = await w.fetch(p);
      expect([401, 404], p).toContain(r.status);
      expectNoSecrets(await r.text(), p);
    }
  });
});

describe("client labels", () => {
  it("sign-in requires a valid label", async () => {
    const w = worker();
    const q = await authorizeQuery(await clientId(w));
    for (const bad of [null, "", "Personal", "my phone", "a_b", "-lead", "a".repeat(33), "operator", "é", "bearer "]) {
      const r = await submit(w, q, TOKEN, bad);
      expect(r.status, String(bad)).toBe(400);
      expect(r.headers.get("location"), String(bad)).toBeNull();
    }
    for (const good of ["a", "work", "phone-2", "9lives", "a".repeat(32), "bearer"]) {
      expect((await submit(worker(), await authorizeQuery(await clientId(w)), TOKEN, good)).status, good).toBe(302);
    }
  });

  it("the grant is stored under the label", async () => {
    const label = freshLabel("kv");
    await fullFlow(worker(), label);
    const { env } = await import("cloudflare:test");
    const keys = (await env.OAUTH_KV.list({ prefix: `grant:${label}:` })).keys;
    expect(keys).toHaveLength(1);
  });

  it("every email names its client", async () => {
    const w = providerWorker();
    const label = freshLabel("tag");
    const { tokens } = await fullFlow(w, label);
    expectSent(await sendAs(w, tokens.access_token, "via oauth"));
    expect(w.mailer.sent.map((m) => [m.subject, m.headers["X-MCP-Client"]])).toEqual([["via oauth", label]]);
    expect(JSON.stringify(w.mailer.sent)).not.toContain('"bearer"');
  });

  it("CLIENT_EMAIL_PER_MIN caps each client, under the global cap", async () => {
    const w = providerWorker(varsWith({ CLIENT_EMAIL_PER_MIN: "2", EMAIL_PER_MIN: "3" }));
    const a = (await fullFlow(w, freshLabel("a"))).tokens.access_token;
    const b = (await fullFlow(w, freshLabel("b"))).tokens.access_token;
    const c = (await fullFlow(w, freshLabel("c"))).tokens.access_token;
    expectSent(await sendAs(w, a, "a1"));
    expectSent(await sendAs(w, a, "a2"));
    expectRpcError(await sendAs(w, a, "a3"), INVALID_REQUEST, LIMIT); // a's own window; global untouched
    expectSent(await sendAs(w, b, "b1")); // global now 3/3
    expectRpcError(await sendAs(w, b, "b2"), INVALID_REQUEST, LIMIT); // global window
    expectRpcError(await sendAs(w, c, "c1"), INVALID_REQUEST, LIMIT); // global window, fresh client window
    expect(w.mailer.sent.map((m) => m.subject)).toEqual(["a1", "a2", "b1"]);
  });

  it("without CLIENT_EMAIL_PER_MIN only the global cap applies", async () => {
    const w = providerWorker(varsWith({ EMAIL_PER_MIN: "3" }));
    const a = (await fullFlow(w, freshLabel("solo"))).tokens.access_token;
    for (const s of ["1", "2", "3"]) expectSent(await sendAs(w, a, s));
    expectRpcError(await sendAs(w, a, "4"), INVALID_REQUEST, LIMIT);
  });
});
