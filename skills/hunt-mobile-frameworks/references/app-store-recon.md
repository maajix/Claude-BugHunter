# App-store recon: every app the target ships, and what changed between builds

Owners: package-level acquisition is `apk-redteam-pipeline` Stages 0-1 and
`ios-redteam-pipeline` Stages 0-1 (iTunes `search` / `lookup`, ipatool,
TestFlight, `manifest.plist`). Ownership scoring is `offensive-osint` §21. This
file adds the cross-store sweep, the channels those stages do not cover,
version history, and HarmonyOS NEXT.

Everything here is passive or uses public store pages and APIs. Keep requests
sequential and slow. Apple documents roughly 20 calls per minute for the Search
API, and Play and the mirrors throttle scrapers.

## 1. Seed the sweep

Start from what you already know: brand names, legal entity names (stores show
the legal seller, not the brand), support email domains, and known package or
bundle IDs. Reverse-DNS IDs (`com.<brand>.*`) are the strongest pivot. The
developer's website field on a listing is the second strongest, and it feeds
the §21 score.

## 2. Store by store

| Channel | Find the developer | List their apps | Notes |
|---|---|---|---|
| Google Play | `https://play.google.com/store/apps/developer?id=<Name+With+Plus>` or `https://play.google.com/store/apps/dev?id=<numeric>` (both resolve) | page scrape, or npm `google-play-scraper` `developer({devId})`, which picks `/dev` for numeric IDs and `/developer` otherwise | listings show developer email, website, address and privacy policy; the Data safety section names collected data types |
| Apple App Store | developer URL `https://apps.apple.com/<cc>/developer/<slug>/id<artistId>`; `artistId` comes from any app's `lookup` result | `https://itunes.apple.com/lookup?id=<artistId>&entity=software&limit=200&country=<cc>` returns the artist record then the apps | without `limit=200` the response is capped near 50 apps; run it per storefront (`country=`), because catalogues differ by country |
| Apple unlisted apps | not searchable, not in charts or categories | only reachable by direct `apps.apple.com` link | find links in the target's own pages, support docs, partner portals, and search results; no guessing |
| TestFlight | `https://testflight.apple.com/join/<code>` | only links already published (forums, release notes, social posts, the target's site) | up to 10,000 external testers per app; full betas show "isn't accepting any new testers"; never brute-force join codes |
| Apple enterprise / in-house | `itms-services://?action=download-manifest&url=https://<host>/manifest.plist` | search the target's domains and recon output for `itms-services` and `manifest.plist` | the manifest names a directly downloadable IPA (`ios-redteam-pipeline` Stage 1); never enroll a device in the target's MDM or sign in to an employee portal |
| Apple custom apps (Business Manager) | private to the assigned organisation | not obtainable without being that organisation | note the existence if referenced; do not try to obtain it |
| Huawei AppGallery | `https://appgallery.huawei.com/app/detail?id=<bundleName>` and `C<digits>` app pages (secondary sources, verify) | no documented public developer listing (verify); search the site for the brand | pages render with JavaScript, so a plain `curl` returns a shell; apkeep removed AppGallery support in 1.1.0 as "nonworking" |
| Samsung Galaxy Store | `https://galaxystore.samsung.com/detail/<package>` (resolves) | seller name, address and support email in the app's Overview (secondary); no confirmed seller-page URL shape (verify) | old `galaxy.store/` badge links from before 2024-11-26 no longer work |
| Amazon Appstore | Fire OS devices only | | Amazon ended Appstore support on non-Fire Android devices on 2025-08-20; the Windows Subsystem for Android and its Appstore left the Microsoft Store on 2025-03-05; newer Fire TV devices run Vega OS (secondary, verify) |
| APK mirrors | APKMirror, APKPure, APKCombo, Aptoide, Uptodown; F-Droid for open-source apps | search by package ID | mirrors are a source of old versions, not of truth; see Section 3 |
| Web-hosted APKs and IPAs | `*.apk`, `*.ipa`, `manifest.plist` on the target's own hosts | recon crawl output, Wayback CDX | `apk-redteam-pipeline` "When to use" lists this trigger |

```bash
# App Store: every app for one developer, one storefront. Read-only public API.
ARTIST=<artistId>; CC=us
curl -s "https://itunes.apple.com/lookup?id=$ARTIST&entity=software&limit=200&country=$CC" \
  | python3 -c 'import sys,json;[print(r.get("bundleId"),r.get("version"),r.get("currentVersionReleaseDate"),r.get("sellerUrl")) for r in json.load(sys.stdin)["results"][1:]]'
```

Record per app: store, ID, title, seller, version, last update, developer
website and email, and the §21 score. White-label and agency-built apps
often share a seller name with dozens of unrelated clients, so do not assume
every app under an agency account is in scope.

## 3. Pulling builds, and when not to trust them

| Tool | Version (checked 2026-10-14) | Use |
|---|---|---|
| apkeep | 1.1.0 (2026-10-01) | `-d google-play` (default; needs `-e <email>` and `-t <aas_token>` or `--oauth-token`, `--accept-tos`), `-d apk-pure` (needs `-o acknowledge_dangers=true`), `-d f-droid` (signature-verified); `-a <pkg>@<version>` pins a version for APKPure and F-Droid only; `-l` lists versions |
| ipatool | v2.7.0 (2026-10-09) | `search`, `purchase`, `download -b <bundle> [--external-version-id <id>]`, `list-versions -b <bundle>`, `get-version-metadata -b <bundle> --external-version-id <id>`; `--format json`, `--non-interactive` |

Rules for mirror and third-party builds:

- apkeep's own documentation warns that APKPure has distributed malware-modified
  apps. Treat every mirror build as hostile. Unzip and decompile it inside an
  isolated VM, never install it on your host, and never run it on a device
  that holds real accounts.
- Compare signers before using a mirror build as evidence of anything:
  `apksigner verify --print-certs <apk>`. It must match the Play build's
  certificate SHA-256. A mismatch means it is not the vendor's build: it is
  not evidence of the vendor's code, and it is not reportable as theirs.
  APKMirror says it checks signatures against earlier uploads (secondary,
  verify), but you still compare yourself.
- Use a dedicated store account for apkeep and ipatool. apkeep warns that
  Google may terminate the account. Do not use a personal or client account.
- Google Play only serves the current version to apkeep. Older Android builds
  come from APKPure, F-Droid or APKMirror (manual), with the signer check above.

## 4. Version history sources

| Platform | Source |
|---|---|
| iOS | the App Store page's "Version History" (versions, dates, release notes); `ipatool list-versions` then `download --external-version-id`; the iTunes `lookup` API returns only the current version |
| Android | APKMirror version list; `apkeep -l -d apk-pure` or `-d f-droid`; Play shows only current "What's new" |
| Both | the target's own changelog, blog, status page and support docs; Wayback snapshots of store pages for old release notes |

Release notes are recon: "removed legacy login", "new payment provider",
"migrated to v3 API" each name a backend change worth diffing.

## 5. What-changed diffing

Decompile each build into its own directory under one git repository, one
commit per version, then diff. Framework output diffs far better than raw
binaries do.

```bash
# One commit per version keeps the diffs reviewable. Paths are local analysis output.
git init appdiff && cd appdiff
for v in 4.1.0 4.2.0; do
  rm -rf out && mkdir out
  jadx -d out/jadx "../builds/app-$v.apk" >/dev/null 2>&1
  # Add the framework output too: Blutter pp.txt, hbc-decompiler output, dump.cs, www/ ...
  git add -A && git commit -qm "app $v"
done
git diff HEAD~1 --stat | tail -5
git diff HEAD~1 -- out/jadx/resources/AndroidManifest.xml
```

What to look for, and where it goes:

| Diff | Why it matters | Route |
|---|---|---|
| Hosts and route strings removed from the newer build | removed from the client, maybe still live on the server | `hunt-shadow-api` |
| Keys or secrets rotated | the old key may still validate | owning skill's read-only validator, once |
| New exported components, deep links, permissions, URL schemes | new platform surface | `hunt-mobile-android` / `hunt-mobile-ios` |
| Feature flags added or defaults flipped | gated features the server may already serve | `bundle-to-backend.md` §3b |
| Pins, certificates, pinned hosts changed | new hosts; pinning added or removed | `recon-scope-triage`; platform note |
| Framework switched (native to Flutter, JSC to Hermes, Mono to IL2CPP) | the tooling changes, and old secrets are often left in the old build | the matching framework reference |
| iOS build vs Android build of the same version | backend versions and hosts often differ per platform | `hunt-shadow-api` |

Diff the iOS and Android builds of the same release against each other as
well. Teams ship the platforms on different schedules, and one platform
often still calls the older API.

## 6. HarmonyOS NEXT

| Fact | Status | Source |
|---|---|---|
| HarmonyOS NEXT, sold as HarmonyOS 5, opened its public beta on 2024-10-22 | secondary (Huawei news snippet) | <https://www.huawei.com/cn/news/2024/10/harmonyos5> |
| HarmonyOS 6 was released in 2025, with public beta from 22 October | primary | <https://consumer.huawei.com/cn/press/news/2025/huawei-releases-harmonyos6/> |
| HarmonyOS 6.1.1 (API 24) is listed as released 2026-05-26 | secondary (verify) | <https://developer.huawei.com/consumer/en/doc/harmonyos-releases/overview-allversion> |
| No native AOSP or APK compatibility; Android apps are not installable directly | secondary | <https://en.wikipedia.org/wiki/HarmonyOS_5> |
| Containerised Android runtimes exist (出境易 / Chujingyi, reportedly 卓易通 / Zhuoyitong) | secondary (verify) | <https://www.osnews.com/story/141273/harmonyos-next-gets-container-tool-to-run-android-applications/> |
| Packages: ability modules build to `.hap`, libraries to `.har` (static) or `.hsp` (shared); the `.app` pack is for store upload and is not installable | secondary (OpenHarmony docs) | <https://gitcode.com/openharmony/docs/blob/OpenHarmony-5.0.2-Release/en/application-dev/quick-start/application-package-structure-stage.md> |
| ArkTS compiles to Ark bytecode; unzipping a `.hap` yields `modules.abc` | primary (tool README) | <https://github.com/ohos-decompiler/abc-decompiler> |
| Distribution is through AppGallery, plus enterprise internal distribution and AppGallery Connect small-scale distribution | secondary (verify) | <https://www.gizmochina.com/?p=626283> |

Why it matters: a target with a large China user base may ship a **separate
HarmonyOS NEXT app** that is not the Android APK. It has its own codebase in
ArkTS or a ported framework, and it may call a different backend version.
Find it on AppGallery (Section 2), then treat it as its own platform build in
the Section 5 diff.

Reverse-engineering tools for `.abc`, all research-grade:

| Tool | State (2026-10-14) | Link |
|---|---|---|
| abc-decompiler (jadx plus abcde based) | last push 2024-12 | <https://github.com/ohos-decompiler/abc-decompiler> |
| arkdecompiler (abc to ArkTS; Black Hat Arsenal) | last push 2026-07 | <https://github.com/jd-opensource/arkdecompiler> |
| abcde (Kotlin toolkit) | last push 2025-11 | <https://github.com/Yricky/abcde> |
| `ark_disasm` (SDK disassembler) | ships with the SDK toolchains (secondary) | <https://gitcode.com/openharmony/docs/blob/master/en/application-dev/arkts-utils/tool-disassembler.md> |

On your own test device, `hdc` (HarmonyOS Device Connector) lists targets,
installs and shells into it. `hdc file recv <device path> <local path>` pulls
files; the doc's usage line and its example disagree on argument order, so
check `hdc -h`. Locate an installed package with
`bm dump -n <bundle> | grep hapPath` (secondary, verify).

Cross-platform frameworks with HarmonyOS NEXT ports, so the framework
references partly apply (all secondary, verify before relying on them):
Flutter OHOS (`gitcode.com/openharmony-tpc/flutter_flutter`), React Native for
OpenHarmony (`@rnoh/react-native-openharmony`), ArkUI-X, Taro
(`taro-platform-harmony*` packages) and uni-app (from HBuilderX 4.27, Vue 3).
Interception and pinning bypass on HarmonyOS NEXT have no mature public
tooling equivalent to Frida on Android (verify). Plan on backend testing
from the Android or iOS build, and use the HarmonyOS build for its inventory
and diff.

## 7. Related platform change: Android developer verification

Google's developer verification applies to apps installed on certified Android
devices from any source, including mirrors. Google's guide schedules
enforcement from 2026-09-30 in Brazil, Indonesia, Singapore and Thailand, with
global rollout in 2027. The guide says the adb install workflow is unchanged
(<https://developer.android.com/developer-verification/guides>, rollout status
unconfirmed, verify). Installing a mirror build on a certified test phone may
start to fail in those regions. Analyse it statically instead.
