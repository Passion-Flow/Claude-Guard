# User-supplied sites: keyless automatic risk evidence (2026-11-12)

## What does Net.Coffee actually call, and what are its response contracts?

### Takeaway
The current page is technically keyless, but its risk score comes from Net.Coffee's own undocumented backend, after discovering the browser's exit to `claude.ai`. Treat this as an observed website implementation, not an Anthropic risk API or a supported integration contract. — [Current page script](https://ip.net.coffee/claude/claude-page.js?v=20260916a)

### Cited Findings
- **Exit discovery:** `GET https://claude.ai/cdn-cgi/trace`, `cache: no-store`, 8-second frontend timeout; parse newline-delimited `key=value` text, use `ip` and `loc` (lowercased). Failure produces no Claude-exit IP and no score. Separate `GET https://1.1.1.1/cdn-cgi/trace` discovers the Cloudflare-route exit with a 5-second timeout. No Anthropic credentials are sent by these calls. These are different destinations and therefore potentially different split-tunnel exits. — [Script, functions `fetchClaudeIP` and `fetchCfIP`](https://ip.net.coffee/claude/claude-page.js?v=20260916a)
- **Risk:** `GET https://ip.net.coffee/api/iprisk/{IP}`, JSON, frontend timeout 10 seconds; no API-key header, token, or login flow in this call. The consumer reads `is_datacenter`, `is_vpn`, `is_proxy`, `is_tor`, `is_crawler`, `is_abuser`, `is_mobile`, `company_type`, `company_name`, `abuser_score`, `datacenter_name`, `asn`, `asOrganization`, `country`, `countryCode`, `region`, `city`, `isResidential`, `isBroadcast`, `trust_score`, and `timezone`. Last two of `isBroadcast`/`timezone` were not present in the one sampled response; tolerate missing fields. — [Script](https://ip.net.coffee/claude/claude-page.js?v=20260916a)
- **Geolocation:** `GET https://ip.net.coffee/api/geoip/{IP}`, JSON. Expected object fields: `country`, `region`, `city`, `isp`, `country_code`. A page-level interceptor coalesces different IP requests within 20 ms into `GET /api/geoip-batch?ips={IP1},{IP2},…`; batch output is an object keyed by IP, each value a geo object. If batch fails, it retries individual requests. The batch contract is inferred directly from the public consumer; it was not separately probed. — [Script](https://ip.net.coffee/claude/claude-page.js?v=20260916a)
- **One bounded sample, public resolver only:** the above risk and geo endpoints returned HTTP 200 `application/json; charset=utf-8`, with `Access-Control-Allow-Origin: *`. Risk had `Cache-Control: public, max-age=600`; geo had `public, max-age=3600`. No `Retry-After`, `RateLimit-Limit`, or `X-RateLimit-Limit` header was present. Absence in this sample does not establish unlimited usage. — [Risk sample URL](https://ip.net.coffee/api/iprisk/1.1.1.1); [Geo sample URL](https://ip.net.coffee/api/geoip/1.1.1.1)

Bounded observed risk response subset (public DNS resolver query; descriptive evidence, not a recommended production call):

```json
{
  "ip": "1.1.1.2",
  "cidr": "1.1.1.0/24",
  "is_bogon": false,
  "is_datacenter": true,
  "isResidential": false,
  "is_vpn": false,
  "is_proxy": false,
  "is_tor": false,
  "is_crawler": false,
  "is_abuser": true,
  "is_mobile": false,
  "company_type": "hosting",
  "company_name": "APNIC Research and Development",
  "abuser_score": "0.0234 (Elevated)",
  "datacenter_name": "",
  "asn": 13335,
  "asOrganization": "Cloudflare, Inc.",
  "country": "Australia",
  "countryCode": "au",
  "region": "Queensland",
  "city": "South Brisbane",
  "src": "g1",
  "trust_score": 41
}
```

Source: [sample](https://ip.net.coffee/api/iprisk/1.1.1.1). Additional observed fields were `rdns: string`, `range: {first:string,last:string,count:number,prefix:number}`, `asn_tbps:string`, `asn_ipv4_count:number`, `asn_kind:string`, `asn_allocated:string`, `reddit_blocked:boolean`, `ai_verdict:{label:string,confidence:number,reasoning:string}`, `geo_sources:array`, `rep_threat:number`, `intelligence:object`, `vpn_trace:null`, `related_domains:[]`, and `related_domains_pending:boolean`. This is not a full or guaranteed schema.

Bounded observed geo response:

```json
{"country":"Australia","region":"Queensland","city":"South Brisbane","isp":"Cloudflare, Inc.","country_code":"au"}
```

Source: [sample](https://ip.net.coffee/api/geoip/1.1.1.1).

- The risk query for **1.1.1.1 returned `ip: 1.1.1.2`**, with the same `/24` range. The script explicitly describes backend trust scoring as per-CIDR and cached 365 days. Thus the host in a response is not necessarily the queried host; retain the original query separately. The 365-day statement is a script comment, not verified backend retention. — [Sample](https://ip.net.coffee/api/iprisk/1.1.1.1); [script](https://ip.net.coffee/claude/claude-page.js?v=20260916a)
- The displayed “Claude trust score” is Net.Coffee's backend number, with a frontend override to zero for its locally hardcoded restricted-country list. Availability uses `no-cors` fetch timing and that same country override. Neither is an authenticated Claude account/access verdict. — [Script, `render` and `detectClaudeAvail`](https://ip.net.coffee/claude/claude-page.js?v=20260916a)
- Opening this diagnostic page also makes a fire-and-forget **`POST /api/session`** with JSON `{claude_ip, cf_ip, cn_ip}`. Do not assume the entire page is local-only because its history feature says it uses local storage. No session POST was made during this research. Other optional diagnostics include DNS-token lookups and WebRTC/STUN. — [Script](https://ip.net.coffee/claude/claude-page.js?v=20260916a); [page](https://ip.net.coffee/claude/)

### Inferences
- A future permitted native adapter should validate the requested IP, preserve `queryIP` independently from `response.ip`, normalize mixed-case naming and lowercase country codes, make absent fields unknown rather than false, cap response size, and fail closed to “unavailable” rather than a fabricated clean score. This follows from the observed consumer and host/CIDR mismatch. — [Script](https://ip.net.coffee/claude/claude-page.js?v=20260916a); [sample](https://ip.net.coffee/api/iprisk/1.1.1.1)
- `claude.ai` trace characterizes the route to that website; it does not prove a native `api.anthropic.com` request or a CLI with different proxy settings has the same exit. — [Observed script destinations](https://ip.net.coffee/claude/claude-page.js?v=20260916a)

### Gaps
- No live trace of the user's connection was collected; no deployment IP, credential, or personal identifier is recorded. Native macOS route parity and trace availability remain unverified.
- IPv6, invalid-input errors, 429 behavior, version stability, batch size limits, and backend retention are untested. No further API probes were made after reading the automation signal below.

## Is automated use supported, licensed, and independently sourced?

### Takeaway
**Block unattended production integration pending provider permission or a documented interface.** The endpoints are publicly reachable but no supported machine API, usage quota, or reuse license was established, and the site's robots policy disallows `/api/`. — [robots.txt](https://ip.net.coffee/robots.txt); [site](https://net.coffee/); [diagnostic page](https://ip.net.coffee/claude/)

### Cited Findings
- `https://ip.net.coffee/robots.txt` returned `User-agent: *`, `Allow: /`, `Disallow: /api/`, and `Disallow: /cdn-cgi/`, plus its sitemap. This is a crawler policy, not by itself a general-purpose legal access-control rule; it is nevertheless an explicit negative automation signal. It was fetched in the same bounded request batch as the two resolver samples, and subsequent API probing stopped. — [robots.txt](https://ip.net.coffee/robots.txt)
- Inspection of the diagnostic page, script, Net.Coffee landing page, IP homepage, and targeted site search did not establish an API documentation link, published rate limit, SLA, commercial automation grant, or source-code reuse license. These public pages advertise a user-facing tool. Treat the missing documentation as unknown, not implied permission. — [Diagnostic](https://ip.net.coffee/claude/); [script](https://ip.net.coffee/claude/claude-page.js?v=20260916a); [landing page](https://net.coffee/); [IP homepage](https://ip.net.coffee/)
- The risk sample labels its selected geo source `g1` and includes `geo_sources` entries `g1` and `g3`; these opaque identifiers are not provider attribution. The public Claude script exposes only Net.Coffee risk/geo endpoints. A variable named `ipapis` is not evidence of a specific upstream contract. — [Sample](https://ip.net.coffee/api/iprisk/1.1.1.1); [script](https://ip.net.coffee/claude/claude-page.js?v=20260916a)

### Inferences
- Counting Net.Coffee risk and Net.Coffee geo as two independent reputation vendors would overstate confidence. They are one integration operator and can share cached/upstream data. Cloudflare trace is a separate route observation, not a second reputation assessment. — [Script](https://ip.net.coffee/claude/claude-page.js?v=20260916a); [sample](https://ip.net.coffee/api/iprisk/1.1.1.1)
- A useful immediate implementation boundary is a manual “Open Net.Coffee diagnostic” action with provenance labeling; a background HTTP adapter needs affirmative provider guidance, allowed polling cadence, storage/privacy terms, and a stable schema first. — [Robots policy](https://ip.net.coffee/robots.txt); [website interface](https://ip.net.coffee/claude/)

### Gaps
- Upstream vendor identity, source independence, scoring validation against Anthropic outcomes, operator contact/permission, and acceptable redistribution terms remain unestablished. Do not copy the site's scoring implementation or treat CORS `*` as a license.

## Does fuck-claude.com provide an IP-risk interface?

### Takeaway
**No IP-reputation check or machine API was found.** This is a browser-local estimate of Chinese locale/device signals, explicitly disclaimed as a heuristic rather than a Claude enforcement verdict. — [Site](https://fuck-claude.com/); [current detector script](https://fuck-claude.com/_astro/Detector.astro_astro_type_script_index_0_lang.BjyUZeoD.js)

### Cited Findings
- It scores eight signals: timezone (26), browser language (20), font detection (18), Intl locale (9), timezone offset (7), browser/WebView hints (7), device-brand hints (8), and emoji/vendor style (5). Its page states these are weighted to 0–100, with low 0–30, medium 31–60, high 61–100. — [Site](https://fuck-claude.com/)
- Static inspection of the current detector asset found no `fetch`, XHR, WebSocket, or beacon call. Its external URLs implement optional social sharing; the scan logic works on browser APIs. The HTML separately loads Google Analytics and Cloudflare Insights, so the webpage itself is not network-free. No untrusted script was executed for this research. — [Detector script](https://fuck-claude.com/_astro/Detector.astro_astro_type_script_index_0_lang.BjyUZeoD.js); [HTML](https://fuck-claude.com/)
- The site itself says a webpage cannot read shell/proxy/DNS settings or inspect account status. Its claims about Claude Code's actual timezone/proxy behavior are attributed to public reverse-engineering reports, with no primary Anthropic validation presented on the page. They must remain attributed claims, not product facts. — [Site](https://fuck-claude.com/)

### Inferences
- This site adds no independent IP-reputation evidence and should never be aggregated as a second network risk vendor. A native macOS application can provide its own separately labeled, opt-in local environment consistency diagnostic using OS timezone/locale and explicitly selected network configuration, without sending those signals to either site. Any browser-font/browser-language score would describe the embedded browser, not necessarily Claude Code. — [Site limitations and signal descriptions](https://fuck-claude.com/)

### Gaps
- No public supported machine interface, reuse license, independently validated ban-prediction model, or authoritative evidence for the reported Claude mechanism was established. Browser-derived China-like signals are not proof of unsupported physical location or account misuse.
