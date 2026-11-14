# Network privacy and local visibility

Guard enforces local packet policy. It does not decrypt, modify or impersonate
ordinary browser, desktop, IDE or terminal HTTPS traffic. It installs no TLS
interception certificate. The reviewed product has no analytics, crash-upload,
account-sign-in or automatic report-upload service.

## Requests made by Guard

| Trigger | Recipient | Data visible to the recipient |
| --- | --- | --- |
| Initial discovery and active exit verification | Cloudflare HTTPS trace | Tunnel exit and ordinary TLS/HTTP connection metadata. No account cookies, application name, node credentials or local report. |
| Active continuity verification | AWS Check IP | Tunnel exit and ordinary TLS/HTTP metadata. This request cannot establish initial admission or renew risk evidence. |
| Required risk admission and renewal | Proxycheck; optionally configured IPQS | The queried exit, fixed assessment options, and a provider key only for the configured keyed mode. |
| Resolution for initial/required assessment | Cloudflare DNS over HTTPS, through the selected tunnel | The fixed assessment/continuity service hostname and the tunnel exit. No physical DNS exception is added. |
| Resolution for active independent continuity | Google DNS over HTTPS, through the selected tunnel | The fixed AWS Check IP hostname and the tunnel exit. The request suppresses EDNS client-subnet forwarding. No system-resolver or physical DNS fallback is allowed. |
| Explicit anonymous service-path check | The two fixed service trace endpoints | Tunnel exit and ordinary TLS/HTTP metadata. No bundle-derived User-Agent, language preference, cookies, credentials, report, brand tag or arbitrary diagnostic payload. Redirects and non-server-trust authentication challenges are rejected. |
| Explicit browser WebRTC check | Cloudflare STUN, through the browser | STUN connection metadata. Candidate categories/counts are submitted only to the temporary loopback page; Guard does not upload candidate addresses or SDP. |
| Explicit external diagnostic link | The selected website | The browser's ordinary information under that site's policies. This is not a Guard-controlled anonymous session. |

The optional service diagnostic suppresses the system library's default
bundle-derived User-Agent and language preference using explicitly empty overrides. It does not
pretend to be Claude, a browser or another vendor. A real Foundation loopback
fixture verifies the generated wire headers, cookie non-replay, redirect
refusal and absence of credential headers. A baseline request demonstrates
that the same system library normally adds the fixture application's name and language preference.
These are request-privacy controls, not an undetectability claim.

The independent resolver uses the documented [Google DNS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json),
including its client-subnet suppression parameter. Both resolver transports
validate the server certificate and stay bound to the approved tunnel.

## Local evidence

Approved configuration and required evidence stay in root-only state. Shared
reports redact route addresses, credentials and account identifiers. Bounded
health diagnostics retain fixed provider/error categories and times, not raw
HTTP bodies or curl error text. Raw transport error text is used only during
the private request to select a fixed category, then removed.

Risk transport diagnostics keep at most sixty entries containing request times,
policy phase, HTTP status, numeric transport exit status and the wrapper outcome.
These entries distinguish an incomplete transfer from a complete invalid body;
they contain no address, request URL, provider key or response body.

The application, its code signature, launch jobs and local files remain visible
to macOS and to local programs with sufficient access. A coding assistant given
terminal, filesystem or screen access may discover them. Renaming an application
does not remove that access. Guard does not hide processes, forge vendor
identities, conceal installation from its owner or alter service-account data.

Remote services still receive connection timing, TLS characteristics and the
information supplied by the actual client. Browsers and other applications
have their own telemetry and permissions. Guard does not certify account
eligibility, prevent every form of device identification, or guarantee an
account will remain available.
