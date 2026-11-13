# Claude Guard 0.4 private installation

Requires macOS 13 or later. One universal native application supports Apple Silicon and Intel. End users do not need Node, Python, a developer account or terminal commands.

## Install and use

1. Extract the complete archive and double-click **Claude-Guard-Mac-0.4.0-private.pkg**. Authorize the installer with the macOS administrator prompt.
2. If Gatekeeper blocks this private, ad-hoc-signed build, use the per-file **Open Anyway** action for the reviewed installer. Do not disable Gatekeeper or SIP. [Apple instructions](https://support.apple.com/en-us/102445)
3. Claude Guard starts in the login session. Connect the already configured dedicated Shadowrocket profile with a numeric IPv4 server address and Global Routing set to Proxy. Allow a macOS app-data privacy prompt if it appears. The dashboard detects supported profile metadata, the signed provider's live endpoint, the tunnel and its observed exit. There are no required node, port, tunnel or API-key fields.
4. Detection enables persistent enforcement automatically. Ordinary applications are released only after six exit observations spanning at least 15 seconds and accepted risk evidence. Missing configuration, unsupported metadata or a disconnected VPN before first activation means **protection is not yet active**; the dashboard states this explicitly.
5. Keep using the normal browser, desktop application, terminal and IDE. Closing the dashboard does not stop root enforcement. The menu-bar popover opens the dashboard. English/Simplified Chinese and system/light/dark themes are available. The default approved region is US; change it in advanced preferences before activation if appropriate.

The installer registers a root supervisor, independent recovery helper and login-session app agent. After initial activation, persisted restrictive policy is restored by the root supervisor, with fresh validation before release. The app agent discovers configuration at login. The private installer pins exact component code hashes; a paid Developer ID certificate is optional. Do not mix components from different builds.

## Supported discovery

The user process reads only allowlisted connection/security fields from Shadowrocket's bounded local profile archive, never decoding passwords, subscription payloads or encryption keys. Selection must identify exactly one record. Current automatic discovery supports one observed IPv4 TCP endpoint with TLS, valid REALITY metadata, supported VMess AEAD, or supported Shadowsocks AEAD. Automatic unattended admission requires a numeric server address. Hostnames and rotating endpoint pools are rejected before enforcement, because DNS available through a connected tunnel does not establish cold bootstrap when external DNS is blocked. Ambiguity, unavailable privacy permission, unsupported protocols, changed formats and insecure verification settings are blockers. The archive is an undocumented compatibility interface, not a vendor API. Profile metadata does not prove the live cryptographic handshake.

The fixed physical node exception cannot distinguish another application using that same address and port. Use a dedicated node; shared/CDN endpoints are unsuitable. Port hopping, endpoint pools, IPv6 outer nodes and arbitrary dynamic node changes are not established as supported. No script downloads or executes third-party code during discovery.

## Automatic risk admission

The default keyless policy combines the tunnel-bound trace country with documented Proxycheck v3 residential classification, risk at most 10 and all required proxy/VPN/Tor/hosting/anonymous/compromised/scraper flags false. The literal queried IPv4 key, JSON field types, duplicate keys and timestamp format are checked. Provider confidence describes positive detections; it is validated as a bounded integer and never used to waive a positive flag or represented as clean-line confidence. This policy is explicitly different from the optional legacy IPQS policy; scores are not averaged or treated as equivalent.

[Proxycheck](https://proxycheck.io/api/) advertises an anonymous daily allowance shared by the querying exit and may reject proxy-origin requests. Guard spaces anonymous attempts by at least one hour across worker restarts and can reuse an exact-address, exact-region response only within its original one-hour lifetime. Cached evidence does not receive a new timestamp. Context changes require fresh tunnel/identity admission. Missing evidence, exhausted quota, unsupported classifications and provider failure keep ordinary traffic blocked. A failed live lookup may therefore require waiting for the retry window or restoring networking locally. This dependency cannot guarantee continuous availability or certify permanent address purity.

The supplied third-party websites remain explicit optional diagnostics. Net.Coffee has no established supported unattended API contract; the other site scores browser metadata rather than independent IP reputation. Neither can override a denied authoritative gate. Optional WebRTC tests run in the actual browser for at most five minutes and retain categories/counts without raw candidates or SDP. Optional anonymous service-path checks are credential-free, bounded, expire after five minutes and cannot authorize release.

## Pause, recovery, upgrade and uninstall

**Pause protection** seals ordinary traffic while retaining the approved route. **Resume protection** runs fresh checks. **Restore network** durably disables automatic rearming before removing Guard rules; if the VPN is absent, direct connectivity returns. Close protected applications first. Enabling automatic protection again requires the dashboard action.

There is only one installed application icon. **Open offline recovery** opens that application's restricted recovery mode, backed by a separate recovery-only XPC service. If the GUI is unavailable, double-click the included **OfflineRecovery.pkg**. Recovery runs locally with administrator authorization, stops the primary service before acquiring its control lock, disarms intent and removes only Guard-owned rules. Keep that package locally. Both helpers and the operating system's service manager/PF must remain functional; repair damaged executables with the matched installer.

Use the matched **Uninstall.pkg** to restore networking and remove Guard-owned app/jobs/helpers. Upgrades preserve restrictive maintenance state. Approvals from policies before v8 are revoked and require fresh automatic setup through the dashboard; old Resume cannot reuse them. A previous standalone guardian must first be restored with its own tool.

## Enforcement boundaries

Physical IPv4 and IPv6 are blocked by default once enforcement is active. Narrow exceptions preserve loopback, interface-bound DHCP and the approved numeric node endpoint on current physical default-route interfaces. Physical DNS, general LAN, multicast and IPv6 application traffic remain blocked. IPv4 applications use the approved Shadowrocket tunnel. The local access provider necessarily carries the encrypted outer connection and link maintenance.

Identity evidence expires after 12 seconds and is bound to session, service, interface, endpoint, exit and underlay. A heartbeat cannot renew it. Reconnection requires six successful observations spanning at least 15 seconds. Rule drift, changed paths, absent underlay and expired evidence revoke release. Root supervision restarts failed workers with fresh sessions and bounded backoff.

Tailscale outer transport receives no direct physical bypass. Userspace Tailscale has no separate tunnel interface; do not claim that the legacy interface-scoped SSH exception enforces per-peer access for that mode. Coexistence and private development access need separate evidence.

Protection applies to applications running on this Mac. SSH access does not place a remote host's applications or browser under this Mac's packet filter. A connected remote session, running service or remote-rendered browser needs evidence from its own execution host; it is not evidence of this Mac's approved path. Keep remote control services private and use narrow peer/port permissions rather than a general tailnet or LAN exception. Guard does not install a remote IDE, move workloads, change account identifiers or configure an exit node automatically.

This PF implementation cannot guarantee protection before its startup job enforces, during a PF-disabled repair interval, against root/admin software, or against browser/device metadata revealing location. PF is shared administrative machinery rather than an Apple-supported application API. [Apple technical note](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api) Network protection does not establish service eligibility or guarantee account availability. FileVault is recommended for local disk protection.

## Developer validation

The development-machine matrix is in Acceptance.md. A clean target runs automatic setup and startup checks; it must still report any unsupported profile or failed live admission. Offline fixtures and another machine's results cannot establish every target environment's behavior.

Developers need the Xcode command-line tools, Python 3 and Node for the browser fixture. Run `./build.sh`, the Python fixtures in Tests and `node Tests/browser_diagnostics_test.js`. `RENDER_PREVIEWS=1` renders native previews. Diagnostic entry points are compiled separately and excluded from shipped binaries. Optional Developer ID distribution uses `CODESIGN_IDENTITY`, `GUARD_TEAM_ID`, `INSTALLER_IDENTITY` and `NOTARY_PROFILE`.
