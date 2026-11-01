// Serve this deploy at WORKER_DOMAIN (a GitHub repository variable) instead
// of workers.dev, by editing wrangler.jsonc in the runner's checkout. Unset or
// empty leaves the file alone. Run by deploy.yml before `wrangler deploy`.
import { readFileSync, writeFileSync } from "node:fs";

const domain = process.env.WORKER_DOMAIN ?? "";
if (!domain) {
  console.log("WORKER_DOMAIN not set; deploying to workers.dev.");
  process.exit(0);
}

// Lowercase labels of [a-z0-9-], not starting or ending with "-", at least one dot.
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
if (!HOST.test(domain)) {
  console.error("WORKER_DOMAIN must be a bare lowercase hostname such as example.aroundand.in (no scheme, path, port or wildcard).");
  process.exit(1);
}

const path = new URL("../wrangler.jsonc", import.meta.url);
const config = readFileSync(path, "utf8");
const WORKERS_DEV = /"workers_dev"\s*:\s*(?:true|false)/;
if (!WORKERS_DEV.test(config) || /"routes"\s*:/.test(config)) {
  console.error("wrangler.jsonc must have `workers_dev` and no `routes` to apply WORKER_DOMAIN.");
  process.exit(1);
}
writeFileSync(
  path,
  config.replace(WORKERS_DEV, `"workers_dev": false,\n  "routes": [{ "pattern": ${JSON.stringify(domain)}, "custom_domain": true }]`),
);
console.log(`Serving at ${domain}.`);
