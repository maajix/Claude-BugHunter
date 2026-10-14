# Serverless and PaaS exposure

Exposed functions and hosted apps on AWS Lambda / API Gateway, Google Cloud Run /
Cloud Functions, Azure Functions / App Service / Static Web Apps, Cloudflare
Workers / Pages, Vercel, Netlify, Render, Fly.io and Heroku. Four questions per
platform: what it is (fingerprint), whether auth is really on (misconfigured
auth), what leaks (previews, stages, debug, source maps) and whether a dangling
hostname is claimable (route that to `hunt-subdomain`).

Owned elsewhere: subdomain takeover method and the main can-i-take-over-xyz
table (`hunt-subdomain`), Next.js middleware and `_next/image` bugs
(`hunt-nextjs`), source-map reconstruction (`hunt-source-leak`), Firebase /
Supabase / Cognito / Appwrite / PocketBase / Auth0 backends
(`hunt-cloud-backends`), GCP and AWS post-credential escalation such as
ConfusedFunction or ImageRunner (`cloud-iam-deep`).

Facts marked "(verify)" could not be confirmed against a primary source on
2026-10-13.

## Fingerprints and default hostnames

| Platform | Default hostnames | Response tells | Not-found tell |
|---|---|---|---|
| Lambda function URL | `<url-id>.lambda-url.<region>.on.aws` | `x-amzn-requestid`, `x-amzn-trace-id` (verify) | `403 Forbidden` when AuthType is `AWS_IAM`, or when the resource policy lacks the invoke grants |
| API Gateway REST | `<api-id>.execute-api.<region>.amazonaws.com/<stage>/` | `x-amzn-requestid`, `x-amz-apigw-id` | `{"message":"Missing Authentication Token"}` on an unknown path, method or stage |
| API Gateway HTTP API | same host; `$default` stage serves the root | `apigw-requestid` (verify) | `{"message":"Not Found"}` (verify) |
| Cloud Run | deterministic `SERVICE-PROJECT_NUMBER.REGION.run.app`; older random `SERVICE_IDENTIFIER.run.app` (`*.a.run.app`); revision tags `TAG---<host>` | `server: Google Frontend` (verify) | Google 403/404 HTML page |
| Cloud Functions gen1 | `REGION-PROJECT_ID.cloudfunctions.net/FUNCTION` (gen2 is Cloud Run, `*.run.app`) | as above | 404 for an unknown function name |
| Azure Functions / App Service | `APP.azurewebsites.net`; since 2024 optional unique default hostnames `APP-<hash>.<region>-01.azurewebsites.net` (verify); Kudu `APP.scm.azurewebsites.net` | `ARRAffinity` cookie, `x-powered-by: ASP.NET` on .NET stacks | `404 Web Site not found` page |
| Azure Static Web Apps | `<name>.<n>.azurestaticapps.net`; PR environments `<SUBDOMAIN>-<PR_ID>.<REGION>.azurestaticapps.net` | `/.auth/me` answers JSON | SWA 404 page |
| Cloudflare Workers | `<worker>.<account-subdomain>.workers.dev`; version preview URLs (verify format) | `server: cloudflare`, `cf-ray` | Workers error page |
| Cloudflare Pages | `<project>.pages.dev`; previews `<hash>.<project>.pages.dev`; branch aliases `<branch>.<project>.pages.dev` (lower-cased, non-alphanumerics become `-`) | `server: cloudflare`, `cf-ray` | Pages 404 |
| Vercel | `<project>.vercel.app`; generated deployment URLs and `-git-<branch>-` branch URLs under `*.vercel.app` (exact pattern (verify)) | `server: Vercel`, `x-vercel-id`, `x-vercel-cache` | `DEPLOYMENT_NOT_FOUND` |
| Netlify | `<site>.netlify.app`; `deploy-preview-NUMBER--SITE.netlify.app`; `BRANCH--SITE.netlify.app`; permalinks `DEPLOY_ID--SITE.netlify.app` | `server: Netlify`, `x-nf-request-id` | `Not Found - Request ID:` |
| Render | `<service>.onrender.com` | `rndr-id`, `x-render-origin-server` (verify) | Render 404 (verify) |
| Fly.io | `<app>.fly.dev` | `server: Fly/...`, `fly-request-id` (verify) | `404 Not Found` |
| Heroku | `APPNAME-IDENTIFIER.herokuapp.com` for apps created on or after 2023-06-14, plain `APPNAME.herokuapp.com` before; DNS target `<haiku>.herokudns.com` | `via: 1.1 vegur` on the legacy router (verify for Router 2.0) | `No such app` |

### Takeover status (can-i-take-over-xyz, last README commit 2025-02-08)

Rows `hunt-subdomain` does not already carry. File only after the method in
`hunt-subdomain`:

| Engine | Status | Fingerprint |
|---|---|---|
| Fly.io | Not vulnerable | `404 Not Found` (issue #101) |
| Firebase | Not vulnerable | (issue #128) |
| Google Cloud Storage | Not vulnerable | `NoSuchBucket` XML |
| Digital Ocean (DNS zones) | Vulnerable | domain delegated to DO nameservers with no records in DO |
| Ngrok | Vulnerable | `Tunnel *.ngrok.io not found` |
| Pantheon | Vulnerable | `404 error unknown site!` |
| Cloudflare Workers / Pages, Render, Lambda URLs, Cloud Run | **not listed** | no status; do not assign one |

Two platform changes cut takeover yield: Heroku's random identifier suffix (from
2023-06-14) and Azure App Service's unique default hostnames (2024, (verify)).
In both, the default hostname can no longer be re-registered by name.

## Stage A checks

### 1. Default hostname vs custom domain (WAF / Access / auth bypass)

A custom domain behind Cloudflare, a WAF, Cloudflare Access or Vercel
Authentication protects that **hostname**. The platform default hostname usually
reaches the same deployment directly. Same request, both hosts, compare:

```bash
for h in app.client.example APP.azurewebsites.net SERVICE-123456789.europe-west1.run.app \
         abc123.execute-api.eu-west-1.amazonaws.com/prod PROJECT.pages.dev SITE.netlify.app; do
  printf '%-60s ' "$h"; curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://$h/admin/"
done
```

Origin-side fixes to cite: API Gateway `disableExecuteApiEndpoint`, Cloud Run
ingress `internal-and-cloud-load-balancing`, App Service access restrictions,
Cloudflare Access on `*.pages.dev` (the Pages "Enable access policy" switch
protects previews only, per Cloudflare docs, not the production `*.pages.dev`
or custom domains).

### 2. Is auth actually on?

```bash
# Lambda function URL: app response = AuthType NONE and public resource policy.
# Since October 2025 new URLs need BOTH lambda:InvokeFunctionUrl and lambda:InvokeFunction granted.
curl -si "https://URL-ID.lambda-url.REGION.on.aws/" | head -15

# API Gateway: the stage, path and method must exist before auth is even evaluated.
#   "Missing Authentication Token" = wrong path/method/stage (NOT an auth prompt)
#   {"message":"Unauthorized"} / {"message":"Forbidden"} = authorizer, API key or resource policy
#   app JSON = method has authorizationType NONE
for s in prod production v1 v2 api dev development test staging stage beta qa uat; do
  printf '%-12s %s\n' "$s" "$(curl -s -o /dev/null -w '%{http_code}' "https://API-ID.execute-api.REGION.amazonaws.com/$s/")"
done
# An x-api-key requirement is throttling/usage plans, not authentication: a key in a JS bundle is the whole lock.

# Cloud Run / gen2 functions: 403 Google page = invoker IAM enforced; app = allUsers invoker or --no-invoker-iam-check
curl -si "https://SERVICE-PROJECT_NUMBER.REGION.run.app/" | head -15

# Azure Functions: authLevel anonymous answers without ?code= / x-functions-key; function and admin levels return 401
curl -si "https://APP.azurewebsites.net/api/FUNCTION" | head -10
curl -s -o /dev/null -w '%{http_code}\n' "https://APP.azurewebsites.net/admin/host/status"   # 401 expected; anything else is a finding

# Static Web Apps: who am I, and does /api enforce the roles the routes claim?
curl -s "https://NAME.N.azurestaticapps.net/.auth/me"
curl -si "https://NAME.N.azurestaticapps.net/api/PATH" | head -10
```

`staticwebapp.config.json` route rules (`allowedRoles`) apply to routes the
platform serves. Look for a backend API that is also reachable on its own
default hostname (Functions or App Service) and so skips them (pattern 1).

### 3. Previews, stages and revisions (the forgotten copies)

| Platform | Where old or unreviewed builds live | Default exposure |
|---|---|---|
| Azure SWA | PR environments `<SUBDOMAIN>-<PR_ID>.<REGION>.azurestaticapps.net` | Microsoft docs: "Anyone can access the staged versions ... even if your GitHub repo is private" |
| Cloudflare Pages | `<hash>.<project>.pages.dev`, `<branch>.<project>.pages.dev` | "By default, these deployment URLs are public" (Cloudflare docs) |
| Vercel | preview and generated deployment URLs | Standard Protection (all plans) protects every deployment except production domains, but teams can set None, and legacy modes leave generated production URLs open |
| Netlify | deploy previews, branch deploys, permalinks | public unless site protection is configured (verify plan specifics) |
| API Gateway | non-prod stages on the same API ID | each stage can carry its own settings |
| Cloud Run | revision tags `TAG---SERVICE...run.app` | an old tagged revision keeps serving old code |

Branch names come from public repos, PR titles and `git-<branch>` hostnames in
CT logs. Pages and Netlify preview hostnames appear in CT logs once they get a
certificate (`crt.sh` query on `%.pages.dev` scoped to the project name).

### 4. Debug and source leaks

- Source maps on previews and production: `hunt-source-leak` owns the method.
  Vercel's "Protected Source Maps" gates `.map` files behind Vercel
  Authentication; seeing `.map` files served publicly on Vercel means the
  feature is off.
- Unhandled errors: Lambda Python tracebacks reveal `/var/task/...` paths and
  handler names; .NET Functions with detailed errors reveal stack frames;
  Express-on-Render/Fly apps with `NODE_ENV` not set to production print stacks.
  Trigger with a malformed JSON body or a wrong content type, never with a
  payload that writes.
- Netlify functions are routed at `/.netlify/functions/<name>`. Names come from
  the JS bundle; list them, do not fuzz at volume.
- Environment dumps behind debug routes (`/env`, `/debug`, `/_debug`,
  `/api/health?verbose=1`) are app bugs, not platform bugs. File them under the
  app and route any secrets to `cloud-iam-deep`.

## Grading

| Proven | Severity |
|---|---|
| Default hostname bypasses WAF/Access/IdP that protects the custom domain, reaching an admin or data endpoint | High |
| Unauthenticated function/API returning another user's or internal data | High to Critical (per data) |
| Public preview/PR environment exposing unreleased features with live backend credentials | Medium to High |
| Public preview of a marketing site | Informational |
| `Missing Authentication Token` or a platform 403 | Not a finding |
| API key in JS that is the only control on a data API | Medium to High (per data); say "API key is not authentication" in the report |

## Incidents and research, 2023-2026

- **Heroku identifier suffix** for new app hostnames from 2023-06-14 (Heroku Dev Center, custom domains).
- **ConfusedFunction** (Tenable, 2024-07-24): deploying a GCP Cloud Function
  attached the default Cloud Build SA, so `cloudfunctions` deploy rights became
  project-level escalation. Post-credential, route to `cloud-iam-deep`.
  <https://www.tenable.com/blog/confusedfunction-a-privilege-escalation-vulnerability-impacting-gcp-cloud-functions>
- **ImageRunner** (Tenable, 2025-04-01): Cloud Run revision updates could pull
  private images the caller had no read access to. Post-credential.
  <https://www.tenable.com/blog/imagerunner-a-privilege-escalation-vulnerability-impacting-gcp-cloud-run>
- **CVE-2025-29927** (2025-03-21), Next.js middleware authorization bypass:
  owned by `hunt-nextjs`. Check which platform serves the
  app before you claim it.
- **Lambda function URL permission change** (AWS docs): from October 2025 new
  function URLs require both `lambda:InvokeFunctionUrl` and
  `lambda:InvokeFunction`. A URL created before then with only the first grant
  is still public. <https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html>

## Stage B boundary

```text
Stage B: written sign-off required, naming endpoint, method, body and count:
  - invoking any function or API route that changes state (POST/PUT/DELETE,
    webhooks, "send", "create", "import"), even if it is unauthenticated
  - using a leaked function key, API key, master key (Azure /admin/*), Vercel
    protection-bypass secret, or identity token
  - claiming a dangling default hostname or app name (method in hunt-subdomain)
  - load beyond a handful of requests against pay-per-invocation endpoints
    (Lambda, Cloud Run, Workers bill the client per call)
```

Sources (checked 2026-10-13): Lambda URL auth
<https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html>, Cloud Run URLs
<https://docs.cloud.google.com/run/docs/triggering/https-request>, SWA PR
environments <https://learn.microsoft.com/en-us/azure/static-web-apps/review-publish-pull-requests>,
Cloudflare Pages previews <https://developers.cloudflare.com/pages/configuration/preview-deployments/>,
Vercel Deployment Protection <https://vercel.com/docs/deployment-protection>,
Netlify deploy URLs <https://docs.netlify.com/site-deploys/overview/>, Heroku
domains <https://devcenter.heroku.com/articles/custom-domains>, can-i-take-over-xyz
<https://github.com/EdOverflow/can-i-take-over-xyz>.
