# Google `AIza` keys: Maps, Places and Gemini

One key format serves every Google Cloud API a project enables. The same
`AIza...` string that loads a map or initialises Firebase also answers any
other enabled API it is not restricted from. That is the whole finding class:
an **unrestricted key on a project with something valuable enabled**. Generic
detection regexes for the key live in `offensive-osint/references/secret-patterns.md`.

## Before the first request

1. **Read the program policy.** Unrestricted Maps keys are excluded or marked
   informative on many programs (example: the Just Eat Takeaway Bugcrowd
   program lists "Google Maps API keys" as out of scope; the gmapsapiscanner
   README warns that most platforms treat the class as informational or low).
2. **Every Maps, Places and Gemini call bills the key owner.** Since 1 Mar 2025
   Maps Platform gives a free monthly threshold per SKU instead of the old
   USD 200 credit (for example 10,000 Geocoding requests a month), so your
   handful of calls is almost certainly free to them. Bulk scanning is not.
3. **One request per API, sequential, no retries in loops.** Do not run
   `gmapsapiscanner` end to end on a target: it walks a long list of APIs,
   several deprecated, and you only need the ones the program cares about.

## Restriction check, Maps and Places

A restricted key fails with `REQUEST_DENIED` / HTTP 403 and a message naming
the restriction (referer, app, IP or API). An unrestricted key returns data.

```bash
K='<AIZA_KEY>'
# Geocoding (Essentials SKU), one request.
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=Berlin&key=$K" | head -c 400
# Static Maps, one tiny image; only the status code matters.
curl -s -o /dev/null -w '%{http_code}\n' "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=64x64&key=$K"
# Places API (New), one text search, minimal field mask (read, POST).
curl -s -X POST https://places.googleapis.com/v1/places:searchText \
  -H "X-Goog-Api-Key: $K" -H 'X-Goog-FieldMask: places.id' -H 'Content-Type: application/json' \
  -d '{"textQuery":"Berlin"}' | head -c 300
```

Reading:

- A key in a web page that answers from your terminal has no HTTP-referrer
  restriction (Maps JavaScript API keys are often referrer-restricted, which
  only stops browsers that send the right `Referer`; that is the intended
  control, not a bypass).
- Answering on an API the page never uses (Places on a site that only shows a
  static map) means no API restriction either.
- Impact is financial: the owner pays for anyone's usage beyond the free
  thresholds. State it as "unrestricted key, these billable APIs answered", with
  the SKU names and the per-request prices from Google's pricing page. Do not
  demonstrate cost.

Grade: Informative to Low on most programs; Medium only where the program
lists billing abuse as in scope.

## Gemini (Generative Language API) on the same key

Truffle Security (Joe Leon, 25 Feb 2026, "Google API Keys Weren't Secrets. But
then Gemini Changed the Rules"): enabling the Generative Language API on a
project silently made the project's existing keys, including ones public in web
pages and apps, valid for Gemini. In the November 2025 Common Crawl they found
2,863 live keys that worked. With such a key an attacker can reach the
project's uploaded files (`/files`) and cached context (`/cachedContents`) and
run generation billed to the owner. Google reclassified it from intended
behaviour to a bug in Dec 2025 and began blocking leaked keys from Gemini and
scoping new AI Studio keys; the root-cause fix was not confirmed at
publication.

```bash
# Stage A: model metadata only, no customer data, not a generation call.
curl -s -o /dev/null -w '%{http_code}\n' "https://generativelanguage.googleapis.com/v1beta/models?key=$K"
```

- 403: the key is restricted from the API, the API is off, or Google's leaked-key
  block applies. Stop.
- 200: the key reaches Gemini. Impact then depends on what the project stores.
  The evidence Truffle used is the file list:
  `GET https://generativelanguage.googleapis.com/v1beta/files?key=<KEY>`. That
  reads customer file metadata; take one page, record the count and one
  redacted name, and stop. Do not download file content.
- Never call `generateContent`, `streamGenerateContent`, embeddings or any
  other generation endpoint: it bills the owner and proves nothing new.

Grade: High when `files` or `cachedContents` hold the client's data; Medium
when only `models` answers (billing exposure on a paid model API). Report to
the program, which owns the key; the platform behaviour itself was already
reported to Google.

## Firebase keys are the same keys

A Firebase `apiKey` is a Google Cloud API key on the Firebase project. If that
project enables Maps, Places or the Generative Language API and the key is not
restricted to the Firebase APIs it needs, the checks above apply to it too.

## Sources (checked October 2026)

- Truffle Security: <https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules>
- Maps pricing change, March 2025: <https://developers.google.com/maps/billing-and-pricing/march-2025>
- gmapsapiscanner: <https://github.com/ozguralp/gmapsapiscanner>
- Program exclusion example: <https://bugcrowd.com/justeattakeaway/updates/ea22ccb1-d00f-41a1-ae3f-f9e4b24912e7>
- Maps API key best practices: <https://developers.google.com/maps/api-security-best-practices>
