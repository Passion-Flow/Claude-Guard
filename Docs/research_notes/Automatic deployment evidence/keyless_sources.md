# Keyless IP Reputation Sources for Automatic Admission

Research date: 2026-11-12. Scope: documented HTTPS services requiring no end-user account or key; no private addresses or user deployment addresses were queried. This note changes no product code, settings, networking, or installed state.

## 1. Which sources are legitimately usable without a key?

### Takeaway

Proxycheck is the strongest documented keyless structured candidate found. IPQuery supplies useful classification evidence, but its published limits and commercial deployment permission remain unverified. Neither establishes an equivalent replacement for a strict IPQS-style contract covering residential classification, every abuse/bot/privacy flag, and a calibrated purity threshold.

### Cited Findings

| Provider | Current keyless contract | Implementation disposition |
| --- | --- | --- |
| **proxycheck.io v3** | 100 queries/day for unregistered clients, metered by querying IP; all API features included. HTTPS works. API responses distinguish residential/business/wireless/hosting/unknown and expose detections. Anonymous requests may be denied when the requester uses a proxy. — [API documentation](https://proxycheck.io/api/) | Best candidate for a bounded classification adapter. This proxy-origin restriction is material for a guard whose checks must travel through its candidate tunnel. |
| **IPQuery** | Documented `https://api.ipquery.io/:ip?format=json`, no key, IPv4/IPv6; `ip`, `isp`, `location`, `risk`; bulk disabled. — [API reference](https://ipquery.io/developers/api) | Optional corroborating classifier; deployment terms/quota need clarification before a required production dependency. |
| **ipapi.co** | HTTPS and ASN/organization/location are documented, without risk flags. Free trial is up to 1,000/day for a limited time and explicitly unsuitable for production/deployment. — [API fields](https://ipapi.co/api/); [pricing and limits](https://ipapi.co/pricing/) | Reject as production keyless risk evidence. A functioning anonymous endpoint is not production permission. |
| **IPinfo** | Current free Lite is country/ASN only, with token-authenticated examples. Privacy data belongs to other service tiers. — [authentication](https://ipinfo.io/developers); [Lite](https://ipinfo.io/developers/lite-api); [privacy API](https://ipinfo.io/developers/privacy-standard-api) | Public `/IP/json` is context-only in the bounded sample below. Do not depend on homepage/widget internals as a documented risk API. |
| **Scamalytics** | Supported API requires username/key; missing/invalid authentication returns 401. Free account allowance is 5,000/month. — [v3 documentation](https://docs.scamalytics.com/ip-fraud-risk-api/v3/); [pricing](https://www.scamalytics.com/ip/api/pricing) | Reject for keyless automation. Public website lookup does not grant a keyless integration contract. |
| **ipapi.is** | Anonymous tier now returns ownership/location plus `is_bogon`; VPN/proxy/Tor/datacenter/abuser flags require a key since 2026-09-01; anonymous limit is 30/client-IP/UTC-day. — [anonymous tier](https://ipapi.is/free-tier.html) | Context/bogon only; missing detection fields must remain unknown. |
| **ipwho.is** | Free HTTPS endpoint permits commercial use, 1,000/client-IP/day, no SLA; Security data is excluded. — [documentation](https://ipwhois.io/documentation) | Context-only. Free success cannot clear any security category. |

- Proxycheck terms permit enrichment/support of an own service, forbid whole-result resale/republishing as a data service, and prohibit free-account limit circumvention. The terms encourage third-party direct integration with user-supplied keys; they do not separately promise unlimited anonymous app distribution. An internal/self-use guard that consumes a few fields appears aligned with permitted enrichment, subject to the anonymous API limit; this is a technical reading, not provider confirmation. — [terms, updated 2026-07-12](https://proxycheck.io/terms/)
- IPinfo permits internal business use of site content but prohibits automated site scraping; external commercial use needs a separate agreement. Scamalytics licenses internal business use and expressly prohibits automated scraping/extraction without written consent. Consequently neither provider's website/widget should be scraped to avoid API authentication. — [IPinfo terms](https://ipinfo.io/terms-of-service); [Scamalytics terms, effective 2026-07-03](https://scamalytics.com/terms-of-service/)
- ipapi.co limits content to internal/client-internal use and imposes ephemeral retention, at most 24 hours; this does not override its free trial's deployment restriction. — [terms](https://ipapi.co/terms/)

### Inferences

- Prefer Proxycheck for any future narrow keyless adapter; distinguish optional corroboration from mandatory admission evidence. A required provider that refuses proxy-origin requests must leave the candidate blocked, not trigger a direct-route retry.
- Free keyed accounts are outside the stated no-end-user-key objective. Shipping a shared provider credential is not an equivalent keyless design.

### Gaps

- No published numeric API quota, service SLA, explicit commercial/internal-team deployment license, or complete API terms were located in IPQuery's current developer/source pages. Open-source client library licenses do not establish service permission.
- No primary documentation authorizing the IPinfo homepage/widget endpoint as an anonymous production privacy API was found. It was not probed.
- Anonymous availability and classification accuracy were not established by an uptime study or independent ground-truth dataset.

## 2. What do bounded live responses actually contain?

### Takeaway

Six fixed-public-IP HTTPS requests, each explicitly querying `1.1.1.1`, returned HTTP 200 around 2026-11-12 07:30 UTC. Only Proxycheck and IPQuery returned privacy/hosting flags; the other four supplied context without security fields. These are schema observations, not accuracy benchmarks or observations of this Mac's exit.

### Cited Findings

**Proxycheck request and observed subset:** [fixed public sample](https://proxycheck.io/v3/1.1.1.1?ver=24-June-2026&tag=0). The response included a queried-address object key and `last_updated`; the exact version was requested rather than relying on a moving default.

```json
{
  "status": "ok",
  "1.1.1.1": {
    "network": {"asn": "AS13335", "type": "Hosting"},
    "detections": {
      "proxy": false, "vpn": false, "tor": false,
      "hosting": true, "anonymous": false,
      "compromised": false, "scraper": false,
      "risk": 33, "confidence": 100
    },
    "attack_history": null,
    "operator": null,
    "last_updated": "2026-11-12T04:57:41Z"
  }
}
```

**IPQuery request and observed subset:** [fixed public sample](https://api.ipquery.io/1.1.1.1?format=json). No `risk.assessment`, explicit abuse boolean, or residential classification was present in this response.

```json
{
  "ip": "1.1.1.1",
  "isp": {"asn": "AS13335", "org": "Cloudflare, Inc."},
  "risk": {
    "is_mobile": false, "is_vpn": false, "is_tor": false,
    "is_proxy": false, "is_datacenter": true, "risk_score": 0
  }
}
```

| Other bounded request | Observed security-relevant shape |
| --- | --- |
| [ipapi.co fixed sample](https://ipapi.co/1.1.1.1/json/) | `ip`, `asn`, `org`, network/location fields; no privacy/abuse object. |
| [IPinfo public fixed sample](https://ipinfo.io/1.1.1.1/json) | `ip`, `org`, hostname/location/anycast/readme; no `privacy` or company-type object. |
| [ipapi.is fixed sample](https://api.ipapi.is/?q=1.1.1.1) | Eleven keys including `ip`, `is_bogon`, string `company`, string `asn`, location and docs; no detection flags. |
| [ipwho.is fixed sample](https://ipwho.is/1.1.1.1) | `ip`, `success: true`, `connection` and location; no `security`. |

- IPQuery defines false as a classification non-match, not a safety verdict. Private/residential proxies may be absent; VPN-list absence does not prove no VPN. — [field reference](https://ipquery.io/developers/fields); [proxy limits](https://ipquery.io/data/proxy); [VPN limits](https://ipquery.io/data/vpn)
- IPQuery's score is a documented policy score, not a statistically calibrated abuse probability; hosting alone adds zero points. Proxycheck applies a hosting baseline of 33. Therefore `0` and `33` in this same-address sample are different provider scales, not an error to reconcile by averaging. — [IPQuery score](https://ipquery.io/glossary/risk-score); [Proxycheck score documentation](https://proxycheck.io/api/)

### Inferences

- Bind parsed data to an exact canonical IP/family and the intended path observation. A lookup that echoes the requested address establishes which record was queried; it does not establish that protected service traffic used that address.
- For Proxycheck, accept actual booleans/numbers only; any missing/null/unknown field remains unknown. Parse the literal queried-IP object key, `status`, version, network type, detections and provider timestamp. Pin the documented version; do not map v2 string fields onto v3 booleans.
- `is_datacenter: false` does not prove Residential; `is_mobile: false` does not prove fixed residential; ASN/company names are not residential evidence. `compromised: false` and `scraper: false` cannot silently substitute for all IPQS abuse/bot categories.

### Gaps

- Single successful fixed-address samples do not prove sustained availability from a candidate tunnel, regional reachability, coverage of residential proxies, or freshness for every classification.
- IPQuery documentation elsewhere references explanation/freshness concepts, but this sampled API did not expose enough information to establish freshness of an explicit abuse-negative decision.

## 3. Can strict keyless automatic admission responsibly be established?

### Takeaway

**No equivalent strict all-flag keyless admission contract was established.** A limited policy can consume documented classification evidence, but must be named and evaluated as that policy. It cannot claim a universal purity score, no-abuse proof, or unchanged IPQS-equivalent guarantees.

### Cited Findings

- Proxycheck's v3 network type can be `Residential`, `Business`, `Wireless`, `Hosting`, or null; null means unknown. Its keyless service can return `denied` for proxy-origin requests or exhausted quota. — [API contract](https://proxycheck.io/api/)
- IPQuery explicitly cautions that low scores are not proof of safety and that its classifications describe the queried address rather than a person/request. Its report data uses fixed releases and assignments/membership can change after collection. — [score interpretation](https://ipquery.io/glossary/risk-score); [source and release scope](https://ipquery.io/sources)

### Inferences

Suggested normalization and admission rules, for future implementation review:

```text
Evidence = {
  provider, contract_version, queried_ip, address_family,
  fetched_at, provider_updated_at?, path_observation_id,
  fetch_status: ok | timeout | quota | rejected | invalid,
  fields: { category: positive | negative_nonmatch | unknown },
  network_type: residential | business | wireless | hosting | unknown,
  provider_score?: { name, value, semantics_version }
}

DENY: any fresh, identity/path-bound hard negative required by policy
      (proxy/VPN/Tor/hosting/compromise/etc. positive).
UNKNOWN/BLOCK: required provider failed; missing/null/paid/unsupported field;
      stale evidence; IP/family/path mismatch; unverified residential type;
      required abuse/bot category has no legitimate covering source.
ALLOW: only when every requirement in a declared local policy is covered
      by fresh, valid evidence, with no hard negative or unresolved unknown.
```

- Keep provider evidence and dissent visible. Additional clean context sources cannot vote down a positive proxy/VPN/Tor/hosting result, and majority voting cannot transform unsupported fields into false.
- Define any numeric threshold separately for each provider and retain its meaning/version. Never average incompatible scores or invent `purity = 100 - mean(risk)`.
- Preserve fail-closed behavior for TLS/JSON failures, body identity mismatch, timeout, authentication rejection, throttling, and source drift. Honor quota/Retry-After, cache only for a short bounded lease, invalidate on IP/path change, and use a finite request budget. Never route checks outside the protected candidate path to obtain a favorable response.
- A truthful no-key UX can show “provider reports no listed VPN/proxy/Tor” and “classification incomplete.” If the existing policy requires categories no permitted keyless source covers, automatic admission stays blocked until the policy or evidence contract is explicitly revised.

### Gaps

- No inspected keyless source independently covers all existing strict abuse/bot/residential requirements with equivalent field semantics, explicit negative evidence freshness, and demonstrated tunnel availability.
- Provider confirmation is still needed before treating IPQuery as a required commercial/internal-team dependency or scaling anonymous Proxycheck direct-client distribution beyond bounded self-use.
