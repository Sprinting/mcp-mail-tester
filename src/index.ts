// Worker entry: OAuth provider in front of a stateless MCP endpoint at /mcp.

import OAuthProvider, { OAuthError, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { isBareHostname, parseConfig, type Config } from "./config";
import { createMcpServer } from "./mcp";
import { smtpMailer, type MailerFactory } from "./smtp";

export { RateLimiter } from "./ratelimit";

export interface HandlerOptions {
  /** Defaults to the SMTP mailer. Tests inject a fake. */
  mailerFactory?: MailerFactory;
  /** Durable Object name of the global rate limiter. Defaults to "global". */
  limiterName?: string;
  /**
   * TEST SEAM: authenticate `/mcp` from the request instead of delegating to
   * the OAuth provider. Only test harnesses supply it — production leaves it
   * unset (see `export default createHandler()` at the bottom), so the
   * provider remains the only way in.
   */
  authenticate?: (request: Request, env: Env) => Promise<{ label: string } | null>;
}

type AppEnv = Env & { OAUTH_PROVIDER: OAuthHelpers };

/** Grant props: a label and a fingerprint of the stored token hash, so rotating the token revokes grants. */
interface Props {
  fp: string;
  /** Connection label; absent on grants made before labels existed. */
  label?: string;
}

const encoder = new TextEncoder();

async function sha256(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(s)));
}

const LABEL_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const RESERVED_LABELS = ["operator"];

/**
 * Sign-in failures / registration attempts allowed per minute, per client IP.
 * The window is keyed on the IP precisely so one anonymous client cannot spend
 * the operator's whole budget: a single global window per kind would itself be
 * an availability attack, 429-ing every sign-in and registration (including
 * the operator's own) for a minute at a time. Only failed tokens count towards
 * the sign-in window, so a correct token still works while an IP is capped.
 * There is deliberately no global backstop instance: it would reintroduce the
 * shared bucket, and floods are absorbed by WAF / plan-level limits anyway.
 */
export const AUTH_ATTEMPTS_PER_MIN = 10;

/**
 * Client address an auth window is keyed on. Cloudflare sets `cf-connecting-ip`
 * at the edge and overwrites any client-supplied value, so it is trustworthy;
 * requests without it (only possible off the edge, e.g. tests) share the
 * literal "unknown" window because the Worker has no other address to key on.
 */
function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "unknown";
}

/** Plain http is only for RFC 8252 native-app loopback callbacks. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1"]);

/**
 * Whether `/authorize` may redirect to `redirectUri`. Loopback http is always
 * allowed (native apps); an https URI must equal an allowlisted full URL or be
 * on an allowlisted bare host (default port only). Matching is exact: no prefix
 * or subdomain matching, so a look-alike host never receives a code.
 */
export function redirectAllowed(redirectUri: string, allowlist: string[]): boolean {
  // A fragment is never part of an OAuth redirect; reject it before parsing
  // (`https://host/cb#` has an empty `hash`, so the raw string has to say).
  if (redirectUri.includes("#")) return false;
  let uri: URL;
  try {
    uri = new URL(redirectUri);
  } catch {
    return false;
  }
  if (uri.username || uri.password) return false;
  if (uri.protocol === "http:") return LOOPBACK_HOSTS.has(uri.hostname);
  if (uri.protocol !== "https:") return false;
  for (const entry of allowlist) {
    if (isBareHostname(entry)) {
      // Default port only: a bare host never vouches for other ports.
      if (uri.hostname === entry.toLowerCase() && uri.port === "") return true;
      continue;
    }
    try {
      if (new URL(entry).href === uri.href) return true;
    } catch {
      // An unparseable entry can never match; config validation prevents it.
    }
  }
  return false;
}

/**
 * Suggested connection label derived from the OAuth client's name. Sanitised
 * to LABEL_RE so the form's suggestion is always submittable; "" when nothing
 * usable remains, or when that would be a reserved label (so the human must
 * pick one).
 */
export function prefillLabel(clientName: string | undefined): string {
  const label = (clientName ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 32)
    .replace(/-+$/, "");
  return RESERVED_LABELS.includes(label) ? "" : label;
}

async function tokenMatches(given: string, expectedHex: string | null): Promise<boolean> {
  if (expectedHex === null) return false;
  const a = await sha256(given);
  const b = Uint8Array.from(expectedHex.match(/../g)!, (x) => parseInt(x, 16));
  return crypto.subtle.timingSafeEqual(a, b);
}

async function fingerprint(cfg: Config): Promise<string> {
  const h = await sha256(`mcp-grant-fingerprint:${cfg.authTokenSha256}`);
  return Array.from(h, (x) => x.toString(16).padStart(2, "0")).join("");
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/**
 * Credit link at the foot of the sign-in and setup pages. Plain anchor, no
 * tracking or external resource; set it to "" to remove it from both.
 */
const CREDIT = `<footer><p><small>Made by <a href="https://aroundand.in" rel="noopener">aroundand.in</a></small></p></footer>`;

const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  "cache-control": "no-store",
};

function page(status: number, title: string, message: string, form = ""): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem}input,button{font:inherit;padding:.5rem;width:100%;box-sizing:border-box;margin-top:.75rem}</style></head><body><h1>${escapeHtml(title)}</h1><p>${message}</p>${form}${CREDIT}</body></html>`;
  return new Response(html, { status, headers: PAGE_HEADERS });
}

/**
 * Setup page script: makes a random operator token and its SHA-256 (the value
 * of MCP_AUTH_TOKEN_SHA256, derived as rotate-token does) in the browser. It
 * never sends anything anywhere; the CSP allows only this script, by hash.
 */
const SETUP_SCRIPT = `
const hex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
async function generate() {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const hash = hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  document.getElementById("token").value = token;
  document.getElementById("hash").value = hash;
}
for (const id of ["token", "hash"]) document.getElementById(id).addEventListener("focus", (e) => e.target.select());
document.getElementById("again").addEventListener("click", generate);
generate();
`;

/** Static setup page: identical bytes whatever the configuration, so it reveals nothing. */
const SETUP_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Set up</title><style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem}input,button{font:inherit;padding:.5rem;width:100%;box-sizing:border-box;margin-top:.25rem}input{font-family:ui-monospace,monospace;font-size:.85rem}label{display:block;margin-top:1rem}</style></head><body><h1>Set up</h1>
<p>This page makes a new operator token in your browser. Nothing is sent to the server.</p>
<label>Token<input id="token" type="text" readonly autocomplete="off" spellcheck="false"></label>
<p>Save the token in a password manager now: it is shown only here, and the server never stores it. You paste it on the sign-in page when a client connects.</p>
<label>MCP_AUTH_TOKEN_SHA256<input id="hash" type="text" readonly autocomplete="off" spellcheck="false"></label>
<p>In the Cloudflare dashboard, open this Worker → Settings → Variables and Secrets, and save this hash as <code>MCP_AUTH_TOKEN_SHA256</code> with the type <em>Secret</em>. Saving a new hash signs out every connected client: each one has to sign in again with the new token.</p>
<button id="again" type="button">Generate another</button>
<script>${SETUP_SCRIPT}</script>
${CREDIT}</body></html>`;

let setupCsp: Promise<string> | undefined;

/** The setup page's CSP: only its own inline script, by hash. Computed once. */
function setupCspHeader(): Promise<string> {
  setupCsp ??= sha256(SETUP_SCRIPT).then(
    (h) =>
      `default-src 'none'; script-src 'sha256-${btoa(String.fromCharCode(...h))}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  );
  return setupCsp;
}

async function setupPage(): Promise<Response> {
  return new Response(SETUP_HTML, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "x-frame-options": "DENY",
      "content-security-policy": await setupCspHeader(),
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
    },
  });
}

/** Sign-in page: the operator types the operator token once to approve a client. */
async function authorize(request: Request, env: AppEnv, cfg: Config, limiterName: string): Promise<Response> {
  let authReq;
  try {
    authReq = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  } catch {
    return page(400, "Invalid request", "This authorization request is not valid.");
  }
  const client = await env.OAUTH_PROVIDER.lookupClient(authReq.clientId);
  if (
    authReq.responseType !== "code" ||
    !client ||
    !authReq.codeChallenge ||
    !redirectAllowed(authReq.redirectUri, cfg.oauthRedirectUris) ||
    !client.redirectUris.includes(authReq.redirectUri)
  ) {
    return page(400, "Invalid request", "This authorization request is not valid.");
  }

  if (request.method === "POST") {
    const form = await request.formData().catch(() => null);
    const given = form?.get("token");
    if (typeof given !== "string" || !(await tokenMatches(given, cfg.authTokenSha256))) {
      // Only a wrong token spends a failure slot; correct tokens, label errors
      // and GETs are free, so the window can never lock out a client that knows
      // the token. Over the cap the caller gets no chance to guess again.
      const limiter = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(`${limiterName}:signin:${clientIp(request)}`));
      if (!(await limiter.take(AUTH_ATTEMPTS_PER_MIN))) return page(429, "Sign in", "Too many failed attempts, try again in a minute.");
      return page(401, "Sign in", "Incorrect token.");
    }
    const label = form?.get("label");
    if (typeof label !== "string" || !LABEL_RE.test(label) || RESERVED_LABELS.includes(label)) {
      return page(400, "Sign in", "Choose a label of 1-32 lowercase letters, digits or hyphens, starting with a letter or digit.");
    }
    const props: Props = { fp: await fingerprint(cfg), label };
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: authReq,
      userId: label,
      metadata: {},
      scope: authReq.scope,
      props,
    });
    return new Response(null, { status: 302, headers: { location: redirectTo, "cache-control": "no-store" } });
  }

  const form = `<form method="post"><label>Access token<input type="password" name="token" autocomplete="off" required autofocus></label><label>Label<input type="text" name="label" autocomplete="off" required maxlength="32" pattern="[a-z0-9][a-z0-9\-]{0,31}" value="${escapeHtml(prefillLabel(client.clientName))}"></label><button type="submit">Authorize</button></form>`;
  return page(200, "Sign in", `Authorize <strong>${escapeHtml(client.clientName ?? "this client")}</strong> to use this server.`, form);
}

/**
 * The public origin: PUBLIC_URL when set, else the request's. Off loopback the
 * origin is always https (plain http is redirected before anything runs).
 */
function originOf(cfg: Config, url: URL): string {
  if (cfg.publicUrl !== null) return cfg.publicUrl;
  return LOOPBACK_HOSTS.has(url.hostname) ? url.origin : `https://${url.host}`;
}

/** 401 for `/mcp` without credentials: empty body, a challenge naming the resource metadata. */
function unauthorized(origin: string): Response {
  return new Response(null, {
    status: 401,
    headers: {
      "www-authenticate": `Bearer realm="OAuth", resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
      "cache-control": "no-store",
    },
  });
}

/** Cached OAuth providers (one per public origin). */
const MAX_PROVIDERS = 8;

export function createHandler(opts: HandlerOptions = {}): ExportedHandler<Env> {
  const mailerFactory = opts.mailerFactory ?? smtpMailer;
  const limiterName = opts.limiterName ?? "global";
  const authenticate = opts.authenticate;

  const apiHandler = {
    async fetch(request: Request, env: AppEnv, ctx: ExecutionContext<Props>): Promise<Response> {
      const cfg = parseConfig(env as unknown as Record<string, unknown>);
      if (ctx.props?.fp !== (await fingerprint(cfg))) {
        // Stale grant (the token hash changed since sign-in): revoke it and its
        // tokens, then answer as if unauthenticated so the client signs in again.
        const bearer = request.headers.get("authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1];
        const parts = bearer?.split(":") ?? [];
        if (parts.length >= 3 && env.OAUTH_PROVIDER) {
          await env.OAUTH_PROVIDER.revokeGrant(parts[parts.length - 2], parts.slice(0, -2).join(":"));
        }
        return unauthorized(originOf(cfg, new URL(request.url)));
      }
      const limiter = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(limiterName));
      const label = ctx.props.label ?? "operator";
      const clientLimiter = cfg.clientEmailPerMin === null ? null : env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(`${limiterName}:client:${label}`));
      const server = createMcpServer({
        cfg,
        mailer: mailerFactory(cfg),
        client: label,
        take: async () => (clientLimiter === null || (await clientLimiter.take(cfg.clientEmailPerMin!))) && (await limiter.take(cfg.emailPerMin)),
        colo: (request as any).cf?.colo ?? null,
      });
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(transport);
      return transport.handleRequest(request);
    },
  };

  const defaultHandler: ExportedHandler<AppEnv> = {
    async fetch(request: Request, env: AppEnv) {
      const { pathname } = new URL(request.url);
      if (pathname === "/authorize") return authorize(request, env, parseConfig(env as unknown as Record<string, unknown>), limiterName);
      return new Response("Not found", { status: 404 });
    },
  };

  // The provider needs the public URL at construction: build lazily, cache per
  // origin. Without PUBLIC_URL the origin comes from the request, so the cache
  // is capped (oldest dropped first); one deployment normally has one or two.
  const providers = new Map<string, OAuthProvider<AppEnv>>();
  function providerFor(origin: string): OAuthProvider<AppEnv> {
    let p = providers.get(origin);
    if (!p) {
      p = new OAuthProvider<AppEnv>({
        apiRoute: "/mcp",
        apiHandler: apiHandler as any,
        defaultHandler,
        authorizeEndpoint: "/authorize",
        tokenEndpoint: "/token",
        clientRegistrationEndpoint: "/register",
        resourceMetadata: { resource: `${origin}/mcp` },
        // A grant signed in under an older token hash can never work again:
        // invalid_grant makes the provider revoke it and answer 400.
        tokenExchangeCallback: async ({ props, env }) => {
          const cfg = parseConfig(env as unknown as Record<string, unknown>);
          if ((props as Props | undefined)?.fp !== (await fingerprint(cfg))) {
            throw new OAuthError("invalid_grant", { description: "The operator token has changed; sign in again." });
          }
        },
        // Auth failures on /mcp carry no body, only the challenge header.
        onError: ({ status, headers }) => (status === 401 ? new Response(null, { status, headers }) : undefined),
      });
      if (providers.size >= MAX_PROVIDERS) providers.delete(providers.keys().next().value!);
      providers.set(origin, p);
    }
    return p;
  }

  return {
    async fetch(request: Request, env: Env, ctx: ExecutionContext) {
      let cfg: Config;
      try {
        cfg = parseConfig(env as unknown as Record<string, unknown>);
      } catch (e) {
        // Visible to the operator in `wrangler tail`; ConfigError messages name the key, never a value.
        console.error(e instanceof Error ? e.message : "invalid configuration");
        return new Response(null, { status: 500 });
      }
      const url = new URL(request.url);
      const { pathname } = url;
      // Without PUBLIC_URL the origin is the request's: never serve it over
      // plain http off loopback, so OAuth only runs on the https origin.
      if (cfg.publicUrl === null && url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) {
        url.protocol = "https:";
        return new Response(null, { status: 308, headers: { location: url.href } });
      }
      const origin = originOf(cfg, url);
      // The setup page is static and served in both states (claiming, rotating).
      if (pathname === "/setup") {
        return request.method === "GET" ? setupPage() : new Response(null, { status: 405, headers: { allow: "GET" } });
      }
      // Unclaimed (no token hash yet): nothing but /setup works, and nothing
      // anonymous (client registrations, rate-limit windows) is written.
      if (cfg.authTokenSha256 === null) {
        if (pathname === "/" && request.method === "GET") return new Response(null, { status: 302, headers: { location: "/setup", "cache-control": "no-store" } });
        return new Response(null, { status: 503, headers: { "cache-control": "no-store" } });
      }
      // TEST SEAM: when a harness supplies `authenticate`, /mcp is guarded here
      // instead of by the OAuth provider. Production never sets it.
      if (authenticate && pathname === "/mcp") {
        const who = await authenticate(request, env);
        if (!who) return unauthorized(origin);
        const props: Props = { fp: await fingerprint(cfg), label: who.label };
        return apiHandler.fetch(request, env as AppEnv, { props } as unknown as ExecutionContext<Props>);
      }
      // Registration is a failure-prone anonymous POST, so its window is per IP
      // and taken before the provider registers anything. Sign-in is limited
      // inside `authorize` instead, after the token check: successful sign-ins
      // and label errors must not spend a slot (see AUTH_ATTEMPTS_PER_MIN).
      if (request.method === "POST" && pathname === "/register") {
        const e = env as AppEnv;
        const limiter = e.RATE_LIMITER.get(e.RATE_LIMITER.idFromName(`${limiterName}:register:${clientIp(request)}`));
        if (!(await limiter.take(AUTH_ATTEMPTS_PER_MIN))) {
          return new Response(null, { status: 429, headers: { "retry-after": "60" } });
        }
      }
      return providerFor(origin).fetch(request, env as AppEnv, ctx);
    },
  };
}

export default createHandler();
