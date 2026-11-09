# Claude Guard 0.2.5 Beta

A native macOS utility for inspecting and guarding the IPv4 path through a Shadowrocket system tunnel. The menu-bar panel shows protection, the last observed exit, the tunnel and upload/download rates. Open Claude Guard to view the dashboard, traffic path, local events and reports. The app and offline recovery tool support English, Simplified Chinese, and system, light or dark appearance. Supports macOS 13 or later on Apple Silicon and Intel.

## Install and verify

1. Double-click the disk image and drag **Claude Guard** and **Claude Guard Recovery** into **Applications**. Open both on the target Mac while networking still works. The package is ad-hoc signed and has no Apple notarization. If Gatekeeper blocks it, verify the source before using the option in Privacy & Security. Neither app needs Node or Terminal. [Apple's Gatekeeper guide](https://support.apple.com/en-us/102445)
2. Connect the intended fixed node in Shadowrocket, then open Claude Guard and select **Detect again**. Enter the VPS IPv4 and use **Detect port and protocol** while an ordinary page generates traffic. Or copy one supported 3x-ui node link and select **Read node from clipboard**. The approved public exit defaults to the node address. Set it separately if they differ. The node must reconnect using its fixed IPv4 and port without a bootstrap DNS lookup, account login or subscription fetch.
3. Close Claude and finish ongoing work. At the target Mac, select **60-second trial** and authorize it. Activation resets existing PF states. Wait for **Protection active**, verify an uncached ordinary page loads, disconnect Shadowrocket and check that the page can no longer fetch fresh content. Reconnect and check that apps remain blocked during stability verification. The 60-second trial stays blocked on expiry.
4. Select **Continue protection** after the trial passes. Test Wi-Fi loss, switching to another network, and sleep/wake with local access to the Mac. The approved route is saved. Closing the window leaves the guardian running. Restarting the Mac clears the session rules. Open Guard and select **Enable last route** to rearm. For a different node or VPN service, run a fresh trial.
5. To intentionally remove the filter, close Claude and select **Restore network**. If the main app is unavailable, open **Claude Guard Recovery** in Applications and authorize it locally. The recovery app needs no internet. Removing the filter while the VPN is offline may restore direct networking. Use **Monitoring & reports** to export a local report. Redact public IPs before sharing it.

For an upgrade from 0.2.4 or earlier with protection active, first close Claude and use local recovery on the target Mac. Replace both apps, then rearm protection.

## Traffic policy

- **Local access.** The physical Wi-Fi or Ethernet link still uses the local provider. PF allows local loopback, basic IPv4 DHCP and one public VPS tuple. VPS replies match a state created by an outbound connection on the same interface. ARP and Wi-Fi link management are outside this IP filter. The VPS tuple is a network exception and is available to local processes able to address it.
- **Transport.** The node link is parsed locally. Guard retains endpoint and transport evidence without retaining the link or its credentials. Explicit plaintext or disabled certificate checks reject activation for that tuple until a corrected profile is reviewed. Links can declare TLS, REALITY or QUIC/TLS. If a link is absent or ambiguous, the dashboard shows **Not reviewed**. Shadowrocket and the server control the live handshake. Guard cannot inspect that handshake or detect a manual profile swap on the same service. [Xray transport documentation](https://xtls.github.io/en/config/transport.html)
- **Tunnel.** After the original Shadowrocket service and approved public IPv4 pass validation, PF allows IPv4 on the selected tunnel. Non-loopback IPv6 stays blocked, including in the tunnel. Direct physical-interface DNS and ordinary application traffic are blocked by the default rule. A separate Tailscale interface has no exception. Test your Linux workflow with strict protection enabled.
- **Restoration.** If Wi-Fi drops and no other active IPv4 link has a default route, the guardian shows **Local network unavailable** and seals apps without sending exit probes or asking the VPN to reconnect. macOS can rejoin Wi-Fi or switch to Ethernet while the guard is sealed. If the original VPN still reports Connected after local access returns and both exit probes fail in two rounds, Guard attempts to recycle that VPN once. When the VPN disconnects, the guardian preserves the fixed tuple and asks macOS to reconnect the original service, with backoff. A candidate tunnel initially carries only IPv4 HTTPS exit probes. At least six consecutive checks spanning at least 15 seconds on the same tunnel and visible IPv4 routes are required before apps reopen. A failed check or path change resets the recovery window. During normal operation one empty probe round can retry on the same approved path while direct traffic remains blocked. A confirmed wrong exit or persistent failure seals app traffic.
- **Monitoring.** The menu bar and dashboard show system interface byte rates. Events are stored locally. Probe requests go through the selected tunnel to two addresses operated by the same service. These checks sample the public exit and do not inspect application payloads.

## Verification boundary

Verification covers PF rule syntax and a simulated guardian test suite. Packet-level acceptance on the target Mac is still required for IPv4, IPv6, DNS, VPN loss and recovery. Verify the physical interface separately to detect any unexpected traffic. A restart, a forced guardian kill or third-party changes to PF can change what is enforced. A normal guardian exit tries to leave blocking in place. The app surfaces stale or altered rules. Keep local access when testing because blocking also affects remote recovery. Apple treats PF as an administrative facility. [Apple TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)

## Build and test from source

On a development Mac with the Xcode command-line tools and Python 3, run the following commands from the repository root.

```sh
./build.sh
python3 Tests/guard_worker_fixture.py
```

The build writes the DMG to `dist/` and runs the bundled syntax and parsing checks. The guardian fixture simulates PF, network interfaces, VPN status and exit probes without changing the host's network rules. Set `RENDER_PREVIEWS=1` when running the build to render the app with demo data.
