# SecOpsAI Public Sites Security Audit

Generated: 2026-05-12

Scope:

- Main website: `https://secopsai.dev/` and `https://www.secopsai.dev/`
- Docs site: `https://docs.secopsai.dev/`
- Blog site: `https://blog.secopsai.dev/`
- Local code: `www/`, `website/`, `docs/`, `blog/`, `secopsai/blog.py`, `scripts/verify_blog.py`

Branding note:

- The canonical public icon was restored to the previous `www.secopsai.dev` PNG asset. The same hash is now used for website, docs, and blog favicon/apple-touch assets, and the blog header brand mark uses that icon.

## 1. Vulnerability Summary

- Critical: 0
- High: 0
- Medium: 3
- Low: 4

## 2. Detailed Findings

### Blog security headers lagged behind website/docs

- Severity: Medium
- Affected component: `blog/_headers`
- Description: The blog had basic `nosniff`, referrer policy, permissions policy, and CSP, but lacked the stronger header set already used by website/docs: HSTS, `X-Frame-Options`, `base-uri`, `object-src`, `form-action`, and cross-origin isolation hints.
- Exploitation scenario: An attacker attempts clickjacking, plugin/object injection, insecure downgrade paths, or base tag manipulation against the blog. CSP and frame protections reduce those paths, but the blog policy was weaker than the rest of the public surface.
- Impact: Defense-in-depth gap and inconsistent hardening across public properties.
- Recommended fix: Align blog headers with website/docs and keep CSP restrictive.
- Fix status: Fixed now. `blog/_headers` now includes HSTS, `X-Frame-Options`, `base-uri`, `object-src`, `form-action`, `Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy`.

### Blog comments accepted JSON without request-shape guardrails

- Severity: Medium
- Affected component: `blog/_worker.js`, `blog/functions/api/comments.js`
- Description: The comments API validated fields after parsing JSON, but did not reject large request bodies or non-JSON content types before parsing.
- Exploitation scenario: An anonymous user sends oversized request bodies or non-JSON payloads repeatedly to increase worker/Supabase pressure.
- Impact: Low-cost resource abuse against the comments endpoint.
- Recommended fix: Enforce a small content length limit, require `application/json`, keep strict field length checks, and add rate limiting/Turnstile for public scale.
- Fix status: Fixed now. Content length and content type checks were added, and optional Cloudflare Turnstile verification is enforced whenever `TURNSTILE_SECRET_KEY` is configured.

### Main website depends on runtime Tailwind CDN and inline scripts/styles

- Severity: Medium
- Affected component: `www/index.html`, `www/_headers`
- Description: The main website allows `unsafe-inline` and loads Tailwind from `https://cdn.tailwindcss.com`. This is acceptable for a small static marketing page, but it weakens CSP and adds a third-party script trust boundary.
- Exploitation scenario: If the CDN script is compromised, blocked, or maliciously modified upstream, the site trusts it at runtime. Inline script allowance also makes future XSS mistakes more dangerous.
- Impact: Broader script execution surface on the main marketing site.
- Recommended fix: Build Tailwind at deploy time, serve static CSS from `self`, move inline JavaScript to a static file, and replace `unsafe-inline` with nonces or hashes.
- Fix status: Fixed now for runtime script risk. Tailwind is compiled into `www/assets/site-tailwind.css`, the runtime Tailwind CDN script was removed, page JavaScript was moved to `www/assets/site.js`, and `www/_headers` no longer allows CDN script/connect sources or `unsafe-inline` scripts. A small residual `style-src 'unsafe-inline'` allowance remains because the page still carries local inline custom CSS; removing that is a lower-risk follow-up because no inline script execution is allowed.

### Blog comments endpoint returned 405 to HEAD health checks

- Severity: Low
- Affected component: `blog/_worker.js`
- Description: `GET /api/comments?health=1` returned JSON, but `HEAD` requests got `405`. Some uptime and security probes use `HEAD`.
- Exploitation scenario: Monitoring falsely reports the endpoint as down even though GET health works.
- Impact: Operational confusion, not a direct exploit.
- Recommended fix: Return `200` for `HEAD /api/comments`.
- Fix status: Fixed now.

### RSS and JSON feed links were raw-machine-readable in browsers

- Severity: Low
- Affected component: `secopsai/blog.py`, `blog/feed.xml`, `blog/feed.json`, `blog/rss.xsl`, `blog/json-feed.html`
- Description: Clicking RSS or JSON Feed in a browser displayed raw XML/JSON. RSS also had an empty item description because the post summary was empty.
- Exploitation scenario: Not a direct security flaw, but confusing feed UX can cause users to distrust legitimate feed links or miss incident context.
- Impact: Poor operator usability and incomplete feed metadata.
- Recommended fix: Add an RSS stylesheet, provide a human-readable JSON feed landing page, and ensure feed summaries are populated.
- Fix status: Fixed now.

### Static public assets expose `Access-Control-Allow-Origin: *`

- Severity: Low
- Affected component: Cloudflare Pages responses for static pages/assets
- Description: Live responses include `access-control-allow-origin: *` for public static resources. No sensitive authenticated data is exposed by these static pages, so the risk is low.
- Exploitation scenario: Other sites can read public static HTML/feed responses cross-origin. This would become risky if authenticated or private data were served from the same paths.
- Impact: Low for current public-only content.
- Recommended fix: Keep private/API data behind explicit worker routes with restrictive responses. Avoid adding sensitive endpoints to static paths.
- Fix status: Documented.

### Blog comment spam/rate limiting still relies on moderation and honeypot

- Severity: Low
- Affected component: `blog/assets/comments.js`, `blog/_worker.js`, Supabase table moderation workflow
- Description: Comments are pending by default and include a honeypot field, field limits, and IP hashing, but there is no Turnstile or edge rate limit yet.
- Exploitation scenario: A bot submits many pending comments. They are not public, but they can create moderation load and Supabase write volume.
- Impact: Moderation/operational load.
- Recommended fix: Add Cloudflare Turnstile or a Workers KV/Durable Object/IP-rate limit if public comment volume increases.
- Fix status: Fixed now with staged Turnstile. The comments client fetches public Turnstile config, renders the widget when configured, and both Pages handlers verify the token against Cloudflare before writing pending comments when `TURNSTILE_SECRET_KEY` exists. Existing mitigations remain pending-only comments, honeypot, strict validation, and body-size limits.

## 3. Attack Chains

### Comment-spam resource pressure

1. Anonymous attacker discovers `/api/comments`.
2. They submit many syntactically valid comments.
3. Comments stay `pending`, so there is no public XSS or content injection.
4. Without edge rate limiting, the attacker can still create moderation and Supabase write pressure.

Mitigations now in place: content-type checks, payload-size cap, field limits, honeypot, safe text rendering, pending-only writes, approved-only reads, and optional Cloudflare Turnstile enforcement.

### Third-party script trust on main website

1. Anonymous attacker cannot directly write to the website.
2. The website trusts Tailwind CDN script at runtime and allows inline scripts.
3. If an upstream CDN or supply-chain path is compromised, injected JavaScript runs in the page context.
4. Because the site is static and does not store credentials, impact is mainly visitor-side phishing/content manipulation.

Mitigations now in place: CSS is built locally, JavaScript is local, runtime CDN trust was removed, and `script-src` is restricted to `self`.

## 4. Secure Design Recommendations

- Keep the blog comments API server-side only; never expose `SUPABASE_SERVICE_ROLE_KEY` to client code.
- Keep Turnstile configured for public comments, or add a Cloudflare edge rate limit if comment traffic grows.
- Continue moving remaining main-site inline custom CSS into static files when convenient so `style-src 'unsafe-inline'` can also be removed.
- Continue using `textContent` for comments and generated HTML escaping for posts/feeds.
- Keep RSS/JSON feed generation deterministic and source-backed.
- Keep public site headers aligned across `www`, `docs`, and `blog`.
- Add a future CI verifier that checks deployed `/api/comments?health=1` returns JSON and that all public sites use the canonical favicon hash.

## 5. Verification

Commands run:

```bash
shasum -a 256 docs/assets/favicon.svg www/assets/favicon.svg blog/favicon.svg blog/assets/favicon.svg website/favicon.svg
shasum -a 256 docs/assets/favicon-512.png www/assets/favicon-512.png blog/assets/favicon-512.png website/assets/favicon-512.png
python3 -m secopsai.cli blog rebuild-feeds
python3 scripts/verify_docs_examples.py
node --check blog/_worker.js
node --check blog/functions/api/comments.js
node --check blog/assets/blog.js
node --check blog/assets/comments.js
node --check www/assets/site.js
python3 scripts/verify_blog.py
git diff --check
curl -sS 'https://blog.secopsai.dev/api/comments?health=1'
curl -sS -I https://secopsai.dev/
curl -sS -I https://www.secopsai.dev/
curl -sS -I https://docs.secopsai.dev/
curl -sS -I https://blog.secopsai.dev/
curl -sS -I 'https://blog.secopsai.dev/api/comments?health=1'
curl -sS -I https://blog.secopsai.dev/feed.xml
curl -sS -I https://blog.secopsai.dev/feed.json
rg -n "localStorage|sessionStorage|innerHTML|insertAdjacentHTML|eval\\(|new Function|document\\.write|SUPABASE|service_role|api[_-]?key|token=|secret=|password|fetch\\(|Content-Security|Access-Control" -S www website blog docs secopsai scripts mkdocs.yml .github
```

Local checks passed:

- Blog verifier passed.
- Blog worker syntax passed.
- Blog Pages Function syntax passed.
- Canonical previous `www.secopsai.dev` favicon hashes match copied website/docs/blog assets.

Live checks after redeploy:

- Website redeployed to `https://d7eab1e0.website-bks.pages.dev`.
- Docs redeployed to `https://55b40532.secopsai.pages.dev`.
- Blog redeployed to `https://fcda3d4f.secopsai-blog.pages.dev`.
- `https://blog.secopsai.dev/api/comments?health=1` returned JSON with `configured: true`, `turnstile_required: false`, and optional Turnstile keys missing until configured.
- `HEAD /api/comments?health=1` returned `200`.
- `https://blog.secopsai.dev/feed.xml` includes an RSS stylesheet and populated item description.
- Browser-style requests to `https://blog.secopsai.dev/feed.json` return the human-readable JSON feed landing page.
- Feed/API clients requesting JSON still receive the raw JSON feed.
- `https://secopsai.dev/` includes the Blog navigation link, local `site-tailwind.css`, local `site.js`, and the canonical previous `www` favicon reference.
- `https://docs.secopsai.dev/` includes the canonical previous `www` favicon and header mark.
- `https://blog.secopsai.dev/` includes the canonical previous `www` favicon, brand mark, local blog script, and JSON Feed links.

Remaining manual/future steps:

- Configure `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` in the `secopsai-blog` Pages project to activate the widget and server-side challenge enforcement.
- Consider moving the remaining inline custom CSS in `www/index.html` into a static CSS file so `style-src 'unsafe-inline'` can be removed too.
