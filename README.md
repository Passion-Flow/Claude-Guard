# Claude Guard 0.4 private beta

Claude Guard is a native macOS network guard for a dedicated Shadowrocket route. It combines a menu-bar panel, dashboard, restrictive PF policy, supervised system worker, required exit-risk admission, local diagnostics and offline recovery. It supports macOS 13 or later on Apple Silicon and Intel, English and Simplified Chinese, system/light/dark appearance and custom selection controls.

This is a private test edition. Successful compilation and offline fixtures do not establish physical network enforcement. Development evidence is recorded in [acceptance](Docs/Acceptance.md); target installation runs automatic setup and admission.

## Installation

Double-click the private installer in the disk image and authorize with an administrator account. No Node, Python or terminal commands are required on the target Mac. A paid Apple developer certificate is optional for this deployment path. The default build is ad-hoc signed and not notarized; Gatekeeper may require a per-file local allow action. Never disable Gatekeeper or SIP.

The complete [installation guide](Docs/Installation.md) covers automatic discovery, keyless risk admission, persistent protection, upgrade, restore and uninstall. The source build produces a matched application/helper package and checksums. Do not mix components from different builds.

## Enforcement and recovery

- Physical IPv4 and IPv6 traffic is blocked by default. Exceptions are loopback, interface-bound DHCP and a fixed numeric node address/port on the current physical default-route interfaces. There is no general physical LAN or DNS exception.
- Application IPv4 traffic uses the approved Shadowrocket tunnel only after six successful exit checks spanning at least 15 seconds and fresh accepted risk evidence. Reconnection, route changes and expired observations require fresh validation.
- Exit observations use strict HTTPS parsing, explicit tunnel binding and system-route cross-checks. Their 12-second lease is bound to the current session, service, interface, endpoint, expected exit and underlay. Unrelated reachability and local heartbeat timestamps cannot renew it.
- Default risk admission requires the observed approved region and an exact-address Proxycheck v3 response: Residential, risk at most 10 and all required detection flags false. Missing, invalid, rejected or expired evidence cannot authorize release. Provider outages and quota errors retain the block.
- The root guardian owns persisted approval and supervises workers. Private installation pins component identifiers and exact code hashes in root-owned trust metadata. XPC peers authenticate before transmitting configuration, keys or authorization forms. Node credentials are not persisted; the provider key and approved configuration use root-only state and are excluded from process arguments and shared reports.
- Supported active Shadowrocket profiles are detected automatically and enable persistent protection without manual parameter or API-key fields. First activation must be confirmed in the dashboard before protected use. Pause retains a restrictive filter. Resume revalidates the approved route.
- Independent recovery authenticates its operator, stops the fixed primary job before taking the shared control lock, durably disarms intent and then removes Guard rules. One visible application includes a restricted recovery mode. Separate recovery and uninstall packages are included. Keep the original image and local access available.
- An optional private Tailscale peer exception allows only SSH on its separate tunnel after OPEN. Its outer transport must use Shadowrocket. Direct LAN/DERP/control-plane bypass, exit nodes, subnet routes and other peer ports are outside this exception.

## Diagnostics and reports

The dashboard shows policy state, risk state and age, tunnel counters and bounded local events. Reports omit addresses and credentials. A five-minute loopback page tests fresh WebRTC connections in the actual browser and records candidate categories without candidate addresses or SDP. Each test explicitly contacts Cloudflare STUN and requires continuous protection.

An optional anonymous service-path check samples fixed trace endpoints on claude.ai and api.anthropic.com without account cookies. Results expire and are invalidated when protection changes. Missing endpoints or restricted responses remain unverified. Explicit external-site links use those operators' own scoring methods. None of these optional diagnostics can authorize release or prove every signed-in browser/API path.

## Protection boundary

PF is a shared administrative facility, not an Apple-supported application API. This edition cannot guarantee protection before the startup job enforces, while PF is disabled, against a root administrator, or ahead of an incompatible foreign PF rule. Rule repair does not eliminate the interval before detection.

PF cannot distinguish Shadowrocket from another process connecting to the permitted node address and port. Use a dedicated node; shared/CDN nodes are unsuitable. Admitted profiles require a fixed numeric IPv4 bootstrap address and Shadowrocket Proxy routing; hostname profiles remain blocked. Parsed profile declarations do not prove the live cryptographic handshake. Shadowrocket and the server remain trusted components.

The local ISP still carries the encrypted outer connection and link maintenance. A VPN does not establish service eligibility or guarantee account availability. Risk scores are estimates, and browser metadata is separate from physical packet enforcement. [Apple PF guidance](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)

See [development acceptance](Docs/Acceptance.md) for packet evidence, controlled failure/recovery, startup gaps, Tailscale, resource use and the Computer Use handoff prompt. See the [roadmap](Docs/ROADMAP.md) for verified work and remaining physical gates.

## Build and offline checks

Developer prerequisites are the Xcode command-line tools, Python 3 and Node for the browser fixture.

```sh
./build.sh
python3 -I Tests/guard_worker_fixture.py
python3 -I Tests/guardian_core_fixture.py
python3 -I Tests/installer_fixture.py
node Tests/browser_diagnostics_test.js
```

The build compiles both CPU targets, checks the application/helper signatures and pinned payload, runs native parser/state/ad-hoc XPC checks, inspects the expanded installer and verifies the image. It never installs a job or changes host networking. Set `RENDER_PREVIEWS=1` for native UI previews.

The default private profile requires no paid certificate. An optional distribution profile uses `CODESIGN_IDENTITY`, `GUARD_TEAM_ID`, `INSTALLER_IDENTITY` and optionally `NOTARY_PROFILE`. Signing does not change the PF enforcement limits.
