# Claude Guard 0.2.5 Beta

Claude Guard monitors a Shadowrocket system tunnel and blocks ordinary direct traffic while protection is active. The menu bar shows protection status and tunnel traffic rates. The dashboard provides configuration, local events and report export. The app and its offline recovery tool support English, Simplified Chinese, and system, light and dark appearance. Requires macOS 13 or later.

## Installation and verification

1. Open the disk image and drag **Claude Guard** and **Claude Guard Recovery** into **Applications**. Launch both before testing. The beta is ad-hoc signed. Review the source before using the Gatekeeper override. [Apple's Gatekeeper guide](https://support.apple.com/en-us/102445)
2. Connect to the intended node in Shadowrocket and select **Detect again** in Guard. Use **Read node from clipboard** with a supported single-node link from 3x-ui, or fill in the node details and select **Detect port and protocol**. The chosen node must be able to reconnect independently of subscription refresh or sign-in.
3. Finish active work, close Claude, and select **60-second trial**. Activation requires local administrator authorization and resets existing filter states. After **Protection active** appears, load an ordinary webpage. Disconnect Shadowrocket, verify fresh requests fail, then reconnect. Applications should stay blocked while Guard verifies recovery. Expiry keeps the filter in place.
4. Select **Continue protection** and test loss of local connectivity, network switching and sleep/wake. Closing the dashboard leaves the guardian running. After a system restart, select **Enable last route**. A different node or VPN service requires a fresh trial.
5. Select **Restore network** to remove the session filter. If the dashboard is unavailable, open **Claude Guard Recovery** and authorize locally. Restoring while the VPN is offline can restore direct connectivity. Review exported reports before sharing them.

Before upgrading from an active session on 0.2.4 or earlier, close Claude and restore networking locally. Replace both apps, then enable protection again.

## Traffic policy

- **Filtering.** Direct application traffic is blocked by default. Exceptions cover local network maintenance and the configured node connection. The selected tunnel carries supported application traffic after validation.
- **Transport review.** Node links are parsed locally. Guard retains endpoint and transport evidence and discards the original link and credentials. A profile that explicitly disables transport protection or certificate checks is rejected. Shadowrocket and the server perform the live handshake. [Xray transport documentation](https://xtls.github.io/en/config/transport.html)
- **Recovery.** When local connectivity is unavailable, Guard blocks application traffic and pauses probes and VPN retry requests. When connectivity returns, Guard uses the original VPN service. If the service still reports connected after two failed probe rounds, Guard attempts one restart. Applications reopen after at least six consecutive successful checks spanning at least 15 seconds on the same tunnel and visible route.
- **Monitoring.** Tunnel traffic rates come from system counters. Event records are local. Exit probes run through the selected tunnel and collect no application payloads.

## Verification boundary

The beta has passed rule syntax checks and simulated guardian tests. Validate direct-traffic blocking and recovery on the intended network before relying on it. Test with local access so the recovery tool remains available. A restart, a forced guardian stop or a third-party rule change can affect protection. Apple treats PF as an administrative facility. [Apple TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)

## Build and test from source

With the Xcode command-line tools and Python 3 installed, run the following commands from the repository root.

```sh
./build.sh
python3 Tests/guard_worker_fixture.py
```

The build writes the DMG to `dist/` and runs the bundled syntax and parsing checks. The guardian fixture simulates PF, network interfaces, VPN status and exit probes without changing the host's network rules. Set `RENDER_PREVIEWS=1` when running the build to render the app with demo data.
