# Claude Guard engineering roadmap

Updated 2026-11-15. The baseline is the existing `hardening/fail-closed-guardian` working tree, including its uncommitted changes. Milestones below describe acceptance conditions. A simulated result is recorded separately from a signed build or physical-device result.

## Release candidate acceptance

Build 42 separates request completion from retry eligibility. Deterministic
controls execute the production coordinator and reproduce two build 41 defects:
the final completed provider receives no retry when no peer remains alive, and
a child exiting between completion inspection and a separate liveness poll can
end the round before its completion is handled. Owned request slots now drain
through the completion pass. Fresh success, a rejection, a closed launch window
and restrictive phases still prevent retries without preventing child cleanup.
The original launch deadline, retry spacing and evidence lifetimes are unchanged.
Eleven targeted controls pass for the correction; complete frozen-source and
installed acceptance remain required.

The first frozen build 42 offline run remained continuously OPEN in its slow-work
cadence case but failed an assertion requiring the older intermediate
`probe-retry` publication. The corrected coordinator had recovered within the
same round. The fixture now records both injected transport timeouts and the
subsequent same-round response, while retaining its continuous-OPEN assertion.
The full state-machine case still requires an empty-round publication and
sealing on sustained loss. The original failed run is retained separately;
this fixture correction does not alter the production worker.

Build 41 passed all 33 offline checks, protected installation with 320 kernel
readbacks, three XPC identity rejection controls, compilation load, a
600.067-second warmup and login handoff. Its first primary-only fault control
failed after 23.513 seconds. The last primary attempt had a TLS peer-closure
category; other providers were deliberately unavailable. The native supervisor
removed tunnel permission at proof expiry while default-deny remained, followed
by automatic re-admission. A separate successful diagnostic used a different
connection and does not establish that the original request could succeed.
The retained failure is not a completed fault suite or continuous observation.
The deterministic scheduling defects do not establish the sole cause of that
transport incident. Build 42 must pass its own complete acceptance before delivery.

Build 41 was prepared after build 40's first warmup and independent-only
fault control failed. Build 40 passed all 32 offline checks, its protected
installation, three installed XPC rejection checks, a subsequent 600.160-second
warmup, login handoff, and strict primary-only and backup-only controls. The
initial warmup nevertheless sealed at the identity deadline after three
unavailable transports. That original failure is retained, not replaced by the
later warmup. The independent-only control then sealed after repeated encrypted
DNS timeouts with a one-second cached TTL; contemporary ordinary-service
requests received responses. This is not a completed fault or continuous pass.

A verified loopback TLS counterexample executes the frozen build 40 independent
client: a 2.3-second DNS response cannot reach the otherwise available target.
The correction allows an OPEN lookup to use half of the existing eight-second
request window and computes the target's remaining time after parsing, reserving
one second for local work and integer-clock boundaries. A quick lookup still
leaves time for a slower target. Exhausted budgets and clock reversal reject the
request. Initial warming keeps its two-second DNS limit. DNS TTLs, twelve-second
identity authority, one-hour risk authority and stable admission are unchanged.
Real paired observations also recorded two-second query failures alongside
four-second successes; separate connections do not prove the counterfactual
duration of the original request. Build 41 requires its own complete frozen
source, installed fault and twelve-hour acceptance before delivery.

Build 40 was prepared after build 39's continuous observation failed at
24,074.458 seconds, after 58,891 OPEN samples and eight real risk renewals.
The failure captured removal of the tunnel pass with default-deny still present,
while the last exit observation was six seconds old. Retained events identify
`risk-invalid-response` during proactive renewal and automatic re-admission
306 seconds later. The original risk transport outcome and body were not retained;
the exact incident cannot be attributed to a particular HTTP failure.

A separate real, certificate-verified loopback TLS control reproduces a concrete
classification defect in the frozen build 39 worker: HTTP 200 followed by a
truncated body (curl 18) or timeout (curl 28) discards still-valid risk evidence.
The corrected path treats a narrow list of incomplete-transfer errors as provider
unavailability. It keeps only the original evidence and deadlines, never grants
initial admission, and still rejects complete invalid bodies, explicit risk
rejection, unknown failures and expired evidence. A bounded redacted risk
transport record is added so future incidents retain the missing distinction.
Build 40 requires fresh frozen-source, installed-fault and continuous acceptance;
the build 39 checks below do not satisfy that requirement.

Build 39 removes a reproduced shared DNS dependency in
active independent continuity. With expired DNS and the trace operator absent,
the original worker sealed without ever reaching the available independent
address service. The corrected worker retained OPEN through three fresh
independent resolutions, without renewing risk or extending either lease.
This establishes a deterministic reliability defect and its correction; it
does not establish the cause of build 38's real transport interruption.
Initial admission retains its original restricted resolver path. Active
independent continuity uses a separately operated HTTPS resolver, explicit
tunnel binding, certificate validation and client-subnet suppression. No
system-resolver or physical DNS fallback was added.

The build 39 private candidate is version 1.0.0. Its production payload remains
frozen and its continuous gate failed; it is not accepted for delivery. The
replacement must complete twelve continuous hours, final verification and
archive checks on its own exact installed payload. Earlier results retain their
own build and observation scope; failed and interrupted runs are not relabelled.

- [x] Freeze the complete build snapshot and record all three executable hashes.
- [x] Select one SDK for both Swift compilation and linking. Both universal
  slices record SDK 27.0 and a minimum deployment target of macOS 13.0.
- [x] Pass all 31 frozen-build local checks, including native lease expiry,
  interrupted admission, independent provider scheduling, installer lifecycle,
  localization, resolver independence and diagnostic privacy.
- [x] Install the exact candidate with default-deny retained throughout 258
  sampled kernel checks; automatically re-admit fresh real evidence. Verify
  closure of the old interface before replacement and exactly one authenticated
  current application process afterward.
- [x] Reject an unpinned caller at all three actual installed XPC listeners.
- [x] Complete two simultaneous native compilation controls while protection
  remains OPEN. Resource observations include the worker's current descendants.
- [x] Complete the candidate's 600.102-second initial observation with no
  non-OPEN sample.
- [x] Complete actual login handoff, four selective provider/operator-loss
  controls, and the eleven installed fault scenarios. Each selective control
  requires fifteen additional uninterrupted seconds after injection ends.
  Trace-operator loss crosses actual independent DNS expiry and records a
  fresh independent resolution without changing the original risk timestamp.
- [x] Observe physical test flows after recovery and preserve any unavailable
  address-family positive controls as unverified.
- [ ] Complete twelve continuous hours with original evidence lifetimes and
  real provider renewals, then verify the installed payload and current policy.
- [ ] Assemble and verify the matched installer, image, source and evidence
  archive before publishing checksums and the private release.

The build 39 fault suite exercised worker termination, force-kill and stall,
supervisor loss, restrictive rule drift, VPN loss, Wi-Fi loss, total proof loss,
actual anonymous Chromium requests, userspace Tailscale SSH and physical packet
controls. The Chromium main-document requests received HTTP responses before
and after sealing and no HTTP response while sealed. An HTTP 403 response is
connection evidence, not successful account access. IPv4 negative packet
controls have a working approved-node positive control; IPv6 lacks an equivalent
working physical positive path on this host. Login-agent handoff is not a
FileVault cold-boot result. These limits remain separate from a passing test.

Two earlier build 39 observations remain retained. The first backup-provider
control lost native permission at the original identity deadline; its
contemporaneous transport cause was not captured and remains unresolved.
Another independent-provider control was incorrectly reported as passed by an
observer that waited for recovery after the injection window. It contained a
real seal after independent resolver timeouts. Ordinary service responses and
node TCP reachability during that interval do not establish fresh exit identity
or a whole-network outage. The corrected observer requires continuous OPEN,
the same session, fresh permissions and exact kernel rules throughout its tail.
Regression controls reject a delayed seal followed by recovery, changed session,
lost permission and changed rules. The subsequent strict suite passed without a
production change. The original reports and their corrected interpretations
remain part of the delivery evidence; a later pass does not erase them.

The exact frozen build source and subsequent acceptance-only test amendment are
recorded separately. Documentation updates after the freeze do not modify the
installed payload. All original DNS, transport, identity and risk deadlines
remain in force: unrelated web connectivity cannot authorize traffic when the
required exit evidence has expired.

Build 38 completed its initial 600.329-second observation, login handoff, all
three selective provider-loss controls and all eleven fault scenarios. The
later continuous-OPEN observation failed at 8,888.466 seconds after four real
risk renewals. All three worker transports timed out; separate system TLS
clients also timed out before native revocation. The first failure readback
still contained the tunnel pass at observation age 12; a readback 0.240 seconds
later confirmed its removal while default-deny remained. Automatic re-admission
followed without an operator command. This is a retained continuity failure,
not a completed twelve-hour pass or proof of physical direct leakage.

No production timeout or evidence lifetime has been relaxed. A bounded read-only
diagnostic now compares ordinary anonymous service requests, approved-node TCP
bootstrap, independent-provider DNS freshness and the active worker request
stage. It cannot authorize traffic, repair policy or turn the failed observation
into a pass. The shared transport interruption's cause remains unresolved, so
release assembly remains blocked by its acceptance checks.

Build 37 passed all three ninety-second provider-loss controls and all eleven
fault scenarios. Its later read-only observation recorded 2,061.793 seconds with
no non-OPEN sample and one real renewal before being deliberately superseded for
build 38. This was not a twelve-hour pass. Selecting one compiler SDK changed the
privileged executable hashes despite unchanged privileged source; build 38
therefore receives fresh installed acceptance.

The original build 37 fault run retained an indeterminate PF-readback failure.
A separate unreferenced-anchor experiment reproduced macOS returning partial
rule output with exit status zero and a Resource busy diagnostic during a
concurrent commit. The observer now discards those partial results and retries
only that exact diagnostic, at most three times, without holding a writer lock.
Complete missing rules, disabled filtering, unknown errors and expired evidence
still fail immediately. The original report lacked the diagnostic and remains
indeterminate; the successful subsequent run does not rewrite it.

## Earlier scheduling investigation

Build 36 passed the following checks: all 29 offline checks, exact protected
installation, 600 seconds of continuous OPEN observation, real login handoff,
90 seconds of trace-provider loss, and eleven installed fault scenarios. The
following continuous observation failed after 21.754 seconds: the native lease
revoked permission at observation age 12, with default-deny present and no tunnel
pass rule. This is a retained availability failure, not a passing long soak or
observed direct-path leak. Two providers recorded TLS peer closure after one
trace provider had succeeded. A paired independent diagnostic saw both system
TLS backends time out during that interval; changing TLS backend is not an
evidence-backed fix.

The investigation also reproduced a scheduler defect with the actual shell
definitions: a healthy primary or backup trace provider waited behind slow peers
before its next request, whereas the independent provider already had a refresh
slot. With the same response schedule, the former providers lost continuity and
the latter remained OPEN. The next candidate gives every provider a bounded,
nonoverlapping refresh slot. Joining and checking the previous result before
reuse preserves conflicting-response rejection. All original identity/risk
lifetimes and initial/recovery admission requirements remain unchanged.

Elapsed-time counterexamples now cover each provider, a slow subsequent response,
repeated conflicting replies, request overlap and retry count. This establishes
the scheduler correction independently of the external TLS incident. It does not
claim the external interruption's root cause is known. Full frozen-candidate
offline and installed acceptance must pass before delivery.

## Product requirements

- Native macOS application with existing browser, desktop, terminal and IDE workflows.
- One supervised policy owner, restrictive physical-interface rules, approved tunnel identity, narrow node bootstrap and network maintenance exceptions.
- Positive exit identity and fresh risk evidence before release. Connection recovery must complete a fresh stability window.
- English source and engineering documentation. English and Simplified Chinese through localization resources, with system, light and dark appearance and custom selection controls.
- Local diagnostics and redacted reports. Optional external diagnostics disclose their destination and run only on explicit user action.
- Double-click private installation and local offline recovery. End users do not install a language runtime or enter shell commands. Private installation uses administrator authorization and root-owned code-hash trust metadata. A paid developer certificate is optional for this deployment path.

## Milestones

| Milestone | Scope | Acceptance gate | Status |
| --- | --- | --- | --- |
| P0 enforcement and privilege | Review PF lifecycle, early boot, rule removal, skipped interfaces, concurrent control and guardian death. Implement authenticated XPC with private-install code-hash pinning. | Packet-level evidence for each supported failure mode, root-owned installation trust, caller validation and independent offline recovery. Explicitly record any pre-enforcement window. | In progress. Private installation does not require a paid certificate. Network Extension deployment is a separate architecture option with its own requirements. |
| P1 health evidence | Strict HTTPS result parsing, scoped routing, bounded evidence lifetime, context invalidation, stable recovery and safe rule readback. | Offline counterexamples cannot reopen traffic. A valid control still opens after six checks spanning at least 15 seconds. Recovery, trial and persistence tests pass. | Implemented and offline verified. Installed-host VPN and Wi-Fi recovery passed with actual Core/worker enforcement and synthetic risk admission; the remaining matrix is open. |
| P2 risk admission | Authorized provider integration with typed responses, approved region, residential policy, strict risk flags, renewal and credential protection. | Missing, expired, rejected or unavailable required evidence keeps traffic locked. Keys and raw responses are excluded from process arguments, public logs and exports. | Actual installed automatic admission passed with real original-age provider evidence. Negative and malformed controls passed offline. Provider availability and later renewal remain separate operational dependencies. |
| P3 browser and destination diagnostics | A bundled, short-lived loopback test page for the actual browser, fresh WebRTC connections per phase, destination path checks and optional external-site links. | Private and mDNS candidates, public host disclosure, reflexive exits, relay addresses and unavailable evidence have distinct outcomes. Diagnostics cannot authorize release. | Implemented. One actual browser passed protected/blocked/recovered ICE and fresh main-document checks. Other browser variants and anonymous service-path acceptance remain open. |
| P4 supervision and coexistence | Approved service recovery, Wi-Fi and Ethernet transitions, sleep and wake, unexpected process exit, existing connections and host Tailscale. | Repeated fault injection shows restrictive recovery without retry storms or a direct-connect fallback. Verify private development access separately. | Actual VPN/Wi-Fi faults, long and short sleep, worker TERM/KILL/STOP, Core replacement, rule removal/repair and userspace Tailscale SSH passed. A ten-minute supervised observation passed. Kernel-mode Tailscale, Ethernet and cold boot retain separate gates. |
| P5 interface and reports | Evidence source, scope, age and verification state in the dashboard, menu bar and redacted report. Complete localization and theme coverage. | Optional checks cannot create a whole-device safety claim. Expired or context-mismatched results lose their previous approval display. | Native bilingual light/dark checks, custom-picker keyboard controls and redacted exports passed. The actual Chinese/system-appearance menu panel rendered, and Computer Use opened the dashboard from its button after the operator opened the status item. |
| P6 private installation and acceptance | Rebuild reviewed source, ad-hoc sign and pin each component, build a private installer, publish checksums and prepare a GUI acceptance prompt. Developer ID signing and notarization remain optional distribution profiles. | Matched application/helper trust metadata, safe clean installation and upgrade, independent recovery, documented results and all mandatory enforcement gates resolved. | In progress. Installation authorization is expected. Gatekeeper may require an explicit local allow action. |

## Verification matrix

| Area | Required scenarios |
| --- | --- |
| Egress | DNS over UDP and TCP, encrypted DNS, IPv4 and IPv6, UDP, QUIC, multicast and WebRTC, existing and new connections. |
| Identity | Unexpected exit, unrelated tunnel, same service with a new tunnel, changed node or configuration, more-specific route, stale or ambiguous observations. |
| Network | Local link loss and restoration, Ethernet failover, new interfaces, sleep and wake, forward and backward clock changes, captive connectivity. |
| Control | Closed dashboard, stopped and force-killed worker, lost supervision, disabled PF, removed or foreign rules, failed rule readback, concurrent activate and restore. |
| Recovery | Trial timeout, explicit continuation, local restoration while offline, interrupted installation, restart and upgrade with active protection. |
| Browser | Protected, disconnected and recovered phases in each supported actual browser, each with a new closed PeerConnection. Permission-limited and empty results remain unverified. |
| Resource use | Bounded timeouts and backoff, no overlapping checks, limited logs and connections, no browser or third-party checks on a permanent polling loop. |
| Privacy | No node credentials, risk keys, candidate addresses or packet contents in exported reports. Separate browser diagnostics from authoritative policy state. |

## Current increment

- Implemented strict HTTP 200 and single-address trace validation, explicit tunnel interface binding and independent system-route checks for both health destinations.
- Replaced unrelated-host reachability approval with a 12-second exit-observation lifetime bound to the session, service, interface, endpoint, approved exit and visible underlay path. Heartbeats do not extend that lifetime. One bounded empty round and the full recovery dwell remain supported.
- Implemented complete canonical rule readback comparison with a restrictive fallback after an inconsistent write. A known label alone cannot establish the loaded phase.
- Added a five-minute loopback browser diagnostic with request bounds, per-session URLs, same-origin result submission and context invalidation. Tests create fresh WebRTC connections, close them and submit counts without candidate addresses. Starting it requires continuous protection. Closing a diagnostic does not change the traffic policy.
- Added explicit external diagnostic buttons and redacted report output. Existing installation and README changes were preserved.
- Passed offline probe, phase-readback, candidate classification and browser connection-lifecycle controls. The guardian simulation passed route mismatch, evidence expiry, state recovery, trial and startup scenarios. Both CPU targets compiled and the native self-test passed. English and Simplified Chinese resources and light/dark native previews were checked.
- Physical packet evidence now includes matching kernel drops for fresh IPv4/IPv6 TCP/UDP flows, with positive physical-path controls, actual Core supervision and native packet-fence writes. Real VPN and Wi-Fi faults recovered after fresh stability checks. These engineering tests substitute risk admission only; they are not live reputation acceptance.
- Actual browser ICE and fresh main-document requests passed protected, disconnected and recovered phases in one browser. The disconnected fresh main-document request failed; recovered requests returned an uncached response. Browser evidence used a separate worker fixture with synthetic readiness/risk, so it is not evidence of a physical power transition.
- Installed private services and native UI were exercised. A separately signed client with the application's identifier but an unpinned code hash was rejected by all three actual installed XPC listeners. Installed launchd restart and independent recovery from a stopped primary holding the control lock passed. Live-provider host admission, pre-enforcement windows and the remaining fault/coexistence matrix remain open. A development build is not a release acceptance result.

The existing trial intentionally restores connectivity on timeout. Browser and external-site checks are limited to continuous protection to avoid extending an active diagnostic across that automatic restoration. Update timeout semantics and recovery tests together when adopting a different trial policy.

## Release decisions

Private-install integration is implemented. A root-owned package installs one visible application, a supervised main helper and an independent recovery helper. Recovery opens within the application or through the matching offline package. Both CPU architectures are compiled. Private trust pins each component's identifiers and code hashes; non-secret XPC authentication precedes sensitive requests. Approval and trial deadlines are root-owned, worker inputs use stdin, and every supervised restart creates a fresh session. Continuing a legacy trial enables persistent protection automatically.

The independent privilege-boundary review identified a shared-lock recovery obstruction. A stopped lock holder reproduced the failure. The fix adds bounded local/file locking and control-process waits; authenticated independent recovery stops the primary job before taking that lock. The same stopped-holder trigger now restores without releasing the holder manually. Unauthorized recovery does not stop it. Corrupt or missing approval state revokes a running worker into a sealed state. Offline controls cover commit/session matching, pause/resume, fresh restart sessions, sealed upgrade, cross-instance disarm, trial expiry, failed installer preparation, bootout/bootstrap failures and recovery/uninstall fallback.

The native anonymous service-path diagnostic is explicit, cookie-free, credential-free, redirect-rejecting and response-bounded. Its observations expire after five minutes, cancel on protection changes and cannot authorize release. Browser observations retain separate scope. One actual browser ICE cycle passed; other browser variants and actual anonymous service responses retain separate acceptance gates.

The current product is a private acceptance build. The supplied installation image and acceptance prompt do not constitute a completed packet-level safety certification. The checklist records engineering verification. The user authorized installation and fault testing on the development host; target deployment uses automatic startup checks. Do not infer unobserved tests from this authorization.

PF is a shared administrative facility. A user-space restart job, an expiry timer or an additional PF anchor does not independently establish protection before the guardian starts or while PF is disabled. These conditions remain release gates, even if functional simulation passes.

The finite destination list in claude-lockdown is reference data for diagnostics, not the boundary for all application traffic. Reimplement applicable lifecycle ideas within Guard's single owner. Resolve upstream licensing before copying source.

Claude-Cage's expiring, context-bound authorization and revocation mechanisms inform P1 and P4. Its isolated guest and guest Tailscale architecture do not establish host-wide macOS enforcement.

External website scores have provider-specific meanings. Optional sites and browser self-tests are evidence with a stated scope, not substitutes for required enforcement and risk admission.

## References

- [Apple packet-filter boundary](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)
- [Apple Network Extension deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [WebRTC IP handling](https://www.rfc-editor.org/rfc/rfc8828.html)
- [Reviewed claude-lockdown source](https://github.com/xaiwind/claude-lockdown/blob/fc3bf32439df1c72901735d54fd14edba5a5ef95/claude-lockdown.sh)
- [Reviewed Claude-Cage gate](https://github.com/Lee-xeo/Claude-Cage/blob/53b7c13a9ab599d00d26dfed5a6585233d069d7d/internal/cage/gate.go)

## Automatic setup increment (0.4)

One visible application now hosts the recovery mode. A login agent launches automatic discovery while the independent root services enforce persisted intent. Initial discovery reads allowlisted numeric-node metadata, corroborates signed-provider sockets and checks the exit through the connected tunnel before authenticated activation. Hostname nodes are not admitted. The default declared keyless policy uses Proxycheck v3 and trace-country evidence, with exact-address binding, strict typed parsing, original-age cache reuse and persistent one-hour admission-batch spacing. A locked batch permits at most three connection-only attempts without an HTTP response; quota/error responses and OPEN renewal never use that retry loop. Unsupported profiles and unavailable evidence remain explicit blockers. The prior manual/IPQS/trial workflow is no longer the default UI. Development-host live enforcement results must be recorded separately from offline fixtures and target automatic checks.

## Power and packet-writer boundary

The native guardian registers IOKit power notifications before starting OPEN-capable supervision. A pending revocation closes admission before waiting for an in-flight PF writer. All shell phase loads and clears go through the signed, root-only native boundary, which serializes writers across processes and rejects old sessions. A complete write has one bounded command budget; individually bounded subprocesses cannot accumulate an unbounded writer transaction. The PF child retains the writer lock if its native parent dies.

Sleep acknowledgment follows the sealing attempt. An error is reported as a failure rather than interpreted as a successful barrier; withholding acknowledgment is not enforcement. Completed wake requires a fresh worker/session and the existing stability/risk admission. Early wake, duplicate notifications, daemon restart during pending sleep, explicit restore, pause and upgrade have separate controls. Native ownership plus exact PF readback permits safe adoption of an emergency seal without accepting foreign rules. Offline fixtures include delayed PF commands, parent death, queued writers, short sleep and restoration interleavings. Actual installed sleep/wake acceptance remains a separate gate. PF errors, root interference and pre-enforcement windows retain the architecture limits described above.

## Bootstrap boundary correction

Live testing exposed that a hostname-based shared provider can reconnect with a different address or need DNS while the physical filter is sealed. Automatic admission now requires a dedicated numeric IPv4 node and Proxy mode, with localized blockers before activation. No physical DNS exception or uncorroborated socket fallback is introduced. A connected-tunnel DNS lookup is not represented as evidence of cold-bootstrap support. Physical tap observations are separated from application connection outcomes and matching kernel PF drop records in the development harness.

Policy v8 binds approved intent to an explicit numeric bootstrap host. Earlier policy approvals migrate to a sealed, unapproved state and cannot resume silently. A runtime profile rejection revokes approval through authenticated control while retaining restrictive rules; repeated invalidation is idempotent. Fresh valid numeric setup is required before unattended release returns.

## Durable control and sealed revalidation increment

Wire version 2 carries a root-owned control revision. Restore, installation, upgrade and operator transitions rotate it. Delayed activation, invalidation, trial or resume requests cannot override a later recovery or pause. A deferred folder-access callback preserves its initiating generation and user intent; granting folder access does not become a new Enable action. Poll replies from older controller generations are discarded. Inactive-state invalidation checks freshness before acknowledging a no-op.

Revalidation of the exact same numeric node may use bootstrap context returned by the authenticated guardian for its already pinned service. This context never authorizes OPEN. It avoids requiring ordinary-user HTTPS while the whole-device filter deliberately blocks that traffic. The guardian retains the pinned service only for the same endpoint and reruns root identity, stability and risk checks. A fresh, context-matched root exit-mismatch observation can initiate revalidation with the changed exit; stale or foreign observations cannot. A different node under the sealed filter requires local restoration and a new initial discovery.

The actual-core fixture reproduces delayed control requests across independent recovery and a new core instance, along with pause, migration and invalidation controls. The discovery fixture executes the real discovery implementation with deterministic OS observations and fails on ordinary networking during sealed revalidation. Native universal builds and these offline results remain distinct from installed-host and browser acceptance.

## Clock-independent watchdog and recovery

Launch grace, worker-heartbeat observation and restart backoff now use process uptime. Re-reading one heartbeat cannot renew its lifetime after a wall-clock rewind. Deterministic tests reproduce a large rewind and repeated small rewinds against the actual Core with a paused fixture heartbeat; both revoke the old session. A continuously publishing control survives clock changes. The host clock is never altered by these tests.

A non-sleep fallback seal may retry metadata readiness only while the registered power observer remains awake. Pending sleep and a newer revocation still require their proper power transition. Automatic recovery creates a fresh session. Offline controls verify both the recovery and the pending-sleep denial case.

## Installed-host evidence ledger

Engineering run identifiers refer to private, redacted retained evidence outside the repository. No local profile or deployment address is included here.

| Evidence | Observed result | Remaining qualification |
| --- | --- | --- |
| Build 16 | Universal build, native self-tests, code-hash trust checks, package inspection and all offline CI checks passed; installation succeeded. | No release-completeness claim. |
| Run 23 | Actual browser ICE and uncached main-document requests passed protected/blocked/recovered phases. | Separate worker-only fixture with synthetic readiness and risk; one browser. |
| Run 24 | Actual Core/IOKit registration, kernel TCP/UDP drops and VPN recovery passed. Native restore returned nonzero; independent cleanup removed the test anchor. | Failure retained. Do not erase it because a later repetition passes. |
| Run 25 | The same Core/worker fault path and native restore passed; restore completed in approximately seven seconds. | Investigate any recurrence of the earlier restoration failure. |
| Run 26 | Actual Wi-Fi loss blocked release; an independent local plan restored Wi-Fi; fresh admission and native restoration passed. | No Ethernet-failover inference. |
| Run 27 | Physical IPv6 positive control was inconclusive, so no sleep fault was injected. | An inconclusive prerequisite is not a passing power test. |
| Run 29 | Actual sleep/wake, fresh session and re-admission passed. | The test's awake-service verification ran too early and reported false. The service was independently verified running; the observer was corrected and the test-owned alarm was removed. |
| Run 30 | Protected SSH and blocking of fresh/existing SSH passed; the first recovered connection failed. | Failure retained. Recovery observations now record typed failures and bounded retries without weakening the filter or host-key checks. |
| Run 31 | Fresh console-user SSH worked while protected, old and new SSH failed during VPN loss, and a fresh SSH connected after recovery. | Existing userspace Tailscale configuration only; no kernel-tunnel or general peer-access claim. |
| Run 32 | Actual short sleep lasted approximately 7.3 seconds. A new session admitted traffic approximately 30 seconds after completed wake. Awake-service restoration and exact test-alarm cleanup passed. | Actual Core/Power/Fence/worker with synthetic risk; no pre-enforcement or root-interference guarantee. |
| Build 18 / run 33 | Native replacement fencing passed offline; the first host start rejected its own preinstalled restrictive seal. | Failure retained. Build 19 adds exact native ownership/readback adoption for the initial worker; foreign-rule controls remain rejecting. |
| Run 34 | Worker/process and repair checks passed, except the repair dwell observer reused an earlier OPEN status. | Test observer corrected to measure actual kernel tunnel-rule reappearance after sealing. This run is not counted as a passing dwell measurement. |
| Build 19 / run 35 | Worker TERM, KILL and frozen-heartbeat failures sealed, then recovered through fresh sessions. Core replacement, actual rule removal/repair, VPN recovery and native restoration passed. Rule repair completed in approximately 1.8 seconds; ordinary tunnel traffic returned approximately 33.4 seconds after repair began. | Actual Core/Power/Fence/worker, isolated test paths and synthetic risk. A separate later restrictive anchor guarded the deliberate rule-removal test. Driver replacement is not a launchd or reboot test. |
| Run 36 | Ten-minute actual Core/worker/PF observation passed: 601 seconds, 285 OPEN samples, no sampled phase drop. IPv4/IPv6 TCP/UDP direct-path controls hit kernel drop rules. Native restoration returned zero in approximately 4.9 seconds. | Synthetic risk and bounded samples; no long-term availability or production resource benchmark claim. |
| Installed control plane | Actual launchd replaced a killed primary. Independent installed recovery succeeded while the primary was stopped holding its control lock; disarmed intent remained durable. All three listeners rejected the unpinned client. | Initially disarmed production intent. Active enforcement was tested separately; no cold-boot inference. |
| Installed packages | Matching offline recovery and uninstall packages ran successfully. Owned application, helper directory and jobs were removed; clean reinstallation and code-hash validation passed. | Initially disarmed production intent. Offline fixtures cover interrupted and active maintenance paths; this is not a live protected-upgrade test. |
| Run 37 | Actual product activation stayed locked after a live provider request failed; bounded local restoration succeeded. A separate tunnel-bound diagnostic received Residential, risk zero and clear required flags; the installed parser accepted it. | The diagnostic is not automatic admission. TLS setup took approximately three seconds, exceeding the old 1.5-second connection limit while fitting the existing four-second risk request budget. |
| Build 21 / run 38 | The installed product blocked forced physical UDP/TCP DNS, DoT and DoH queries. Each protocol had a successful fresh matching DNS response before activation. The restrictive filter remained loaded, aggregate kernel block counters increased and local restoration passed. | Random .invalid test names only. Aggregate counters do not identify an exclusive flow or constitute an external wire capture. OPEN-state browser DNS and VPN-failure phases retain separate gates. |
| Run 39 | An ordinary user could reach the local provider proxy while direct traffic was denied and ordinary tunnel permission was absent. | Confirmed admission bypass in the old unconditional loopback exception. Policy v9 gates local IP ingress with OPEN. |
| Build 22 / run 45 | Real automatic admission, normal IPv4/IPv6 local proxy controls, initial LOCKED denial, native Pause, fresh direct/proxy denial, retained local TCP revocation and independent restoration passed. | The retained connection was controlled local TCP; earlier external-connection and operator-timeout attempts were retained as incomplete, not passes. |
| Run 46 | Actual product VPN loss denied direct and both local proxy paths. Physical UDP/TCP DNS, DoT and DoH were blocked in OPEN, VPN loss and recovery, each with a fresh pre-activation control. New anonymous browser login requests returned uncached HTTP 200 before/after loss; the off-phase navigation reported ERR_NAME_NOT_RESOLVED. | The off-phase raw browser event buffer was truncated. The generated error page was blocked by browser URL policy and was not inspected. Protected installation retained sealed maintenance, but remote-only Resume could not cross the intentionally blocked network. |
| Run 47 | Protected installation, a local operator's Resume and real re-admission passed. | The following production ten-minute continuity check failed with repeated revalidation/settling. Local recovery succeeded. This run is not a stable-runtime pass. |
| Build 23 / run 48 | Corrected stale scheduling timestamps passed a slow-work offline reproduction and maintained initial real admission. | Production continuity still failed after approximately 64 seconds with evidence expiry. Tunnel-bound latency controls found successful requests taking more than the old two-second per-address budget. No expired evidence was made valid to satisfy the test. |
| Build 24 offline | Concurrent health requests, original response timestamps, wrong-backup rejection, strict response handling, drained cancellation and a bounded empty-round production-cadence control passed. The full worker and risk suites passed. | Installed production continuity is recorded separately; these fixtures never change host PF, networking or the clock. |
| Installed menu UI | The operator opened the menu item after SystemUIServer automation timed out. The popover displayed localized state, counters and tunnel information; Computer Use clicked its dashboard button and confirmed the main window. | Actual interaction was Chinese/system appearance; other localization/theme evidence is separate. No private screenshot or exit address is shared. |
| Build 24 / run 49 | Real production admission followed by 600.8 seconds and 1,020 sampled OPEN states passed without a phase drop. Independent restoration returned zero. | Native process CPU/RSS samples exclude the shell worker, HTTPS children and total system usage. Ten minutes does not establish a renewal-cycle pass. |
| Build 25 / run 50 | Protected installation, local Resume, dashboard absence and dashboard restart preserved actual supervision; reopening retained the root session. | The later continuity phase failed when old risk evidence expired and a DNS lookup was unavailable. Independent restoration returned zero. This is a retained availability failure. |
| Build 26 offline | Universal package/payload checks and the complete local CI suite passed. New controls cover proactive renewal, original-expiry retention, persistent rejection, identity separation, durable query spacing and UTC allowance rollover. | Actual proactive renewal remains a separate long-running host gate. |
| Run 51 | Initial real admission passed. A stricter observer stopped on an OPEN probe-retry sample; the event journal corroborated a missing new observation rather than a different exit. Independent restoration returned zero. | Observer failure retained. Its follow-up accepts only the existing bounded retry category and separately checks binding, freshness and actual phase. |
| Build 26 / run 52 | Production protection remained OPEN for 2,900.3 seconds and 4,660 samples, including a real proactive network risk renewal. New evidence replaced the original timestamp at an original age of approximately 2,705.6 seconds; no non-OPEN sample occurred. Final installed payload validation passed and protection remained active. | No host clock or cache timestamps were changed. Normal UI actions and a 19.4-second pair of optimized application compiles ran during observation. Native process CPU/RSS estimates exclude the shell worker, HTTPS children and total system usage. |
| Build 26 native diagnostics | Actual anonymous traces matched both service endpoints. English controls, dark appearance, restored Chinese/system preferences and an actual redacted report export passed. | The latest actual browser WebRTC result was unavailable and remains unverified. A missing candidate observation does not establish no leakage. |
| Build 27 / run 53 | Universal build and native controls passed. The installed notification update re-admitted real evidence and stayed OPEN for 120 seconds and 193 samples. Daily query accounting survived maintenance and remained root-only. The actual report notice rendered separately from the protection reason. | Both privileged executable hashes are identical to build 26. This update changes presentation; the real renewal evidence therefore applies to the same privileged binaries. It is not a cold-boot test. |
| Build 27 actual restart | The startup observer saw restrictive rules at its first sample, followed by LOCKED, stability/risk checks and OPEN. Current kernel boot, new worker session, current-boot power fence, endpoint, service, fresh identity/risk evidence and installed payload passed follow-up validation. | The operator manually enabled the VPN. Unattended cold connection did not pass. System logs recorded three failures to find the vendor tunnel extension before the application started. The original observer incorrectly required persistent approval-origin boot metadata to change; its failure and original output are retained. No zero-exposure interval before observation is certified. |
| Build 27 post-restart recovery | One actual original-service stop recovered automatically, without an explicit start from the test harness. A restrictive filter remained present at every sample; LOCKED preceded revalidation and risk review. Three final fully bound OPEN samples completed after approximately 72.4 seconds. Installed payload validation passed. | This is runtime recovery after the operator's first connection, not an unattended cold-start pass or a new packet-capture result. The status label lagged physical disconnection briefly; the restrictive physical filter remained present. |
| Build 28 login handoff | Universal build, native startup eligibility controls, automatic discovery and localization passed. The actual vendor application met the required signing identity. A protected local upgrade installed successfully; subsequent actual state confirmed persistent OPEN with maintenance cleared and fresh bound identity/risk evidence. | Both privileged executables remain byte-identical to build 26. The new login-session handoff still requires an unattended restart observation; it does not itself authorize traffic. The initial bounded update observer ended before readmission and is retained separately. |
| Build 28 stability regression | Actual retained events include repeated evidence-expired and probe-failed sealing while the operator reported usable networking. A passive interval also observed an unanswered trace request covered by its peer. An independent, actual tunnel-bound HTTPS address control matched the approved exit. The installed guardian and its HTTPS children were classified as background work. | This regression supersedes any claim that the earlier bounded run establishes current stability. The observations do not establish that every seal has one cause. The operator requested retaining automatic VPN recovery. |
| Build 29 stability repair | Universal build/native controls, worker lifecycle, production cadence, concurrent transport, independent continuity, strict risk/cache behavior, installer lifecycle and bilingual checks passed locally. The independent provider can maintain an already OPEN address identity only under the original accepted region/risk expiry; it cannot create new admission, renew risk without a fresh trace region or override any conflicting response. Retry presentation follows actual OPEN permission. Deadline-bound protection/recovery jobs use Interactive classification. | Actual protected installation and local Resume passed. A 65-second request-process failure control kept OPEN while both fixed trace requests failed; a 16.4-second parallel compile ran inside that control. The later production observation failed after 1,032.4 seconds. This build is not accepted as stable. A real journaled renewal occurred before that observer began, rather than inside its window. The first concurrency fixture failed its old wall-time heuristic under compilation; it now measures actual request overlap while retaining its seven-second enclosing limit and four-second transport budgets. The original failed log is retained. |

| Build 30 pending-reply repair | A real elapsed-time control reproduced a matching reply arriving within the old lease but being held behind a slow peer until expiry. Completed evidence is now processed while other requests remain pending; every update rechecks the original identity/risk leases, exact route/service context and filter. Expiry, mismatches and rule/path failures seal without waiting for another child. Response timestamps originate at completed transport, before local validation. Sixty root-only diagnostic rows retain transport categories without addresses or bodies. | Universal build/payload checks and all local CI checks passed, including full worker lifecycle, cadence, actual pending-reply/expiry controls, risk/cache, independent continuity, native fence/control, restart/migration, installer, browser, localization and the engineering harness. The harness now preserves the actual transport exit status and completion timestamp; success/failure controls exercise the transformation without host networking. One parallel-build cadence attempt timed out in its fixture clock setup; the unchanged cadence control subsequently passed. Installed observation remains pending. Request budgets, admission dwell and evidence/risk expiry are unchanged. This timing counterexample does not establish a single cause for every retained build 29 failure. |

| Build 30 / runs 58 and 59 | Exact protected installation and local Resume passed. Real health diagnostics identified two intentionally terminated trace requests plus independent transport timeouts at the four-second deadline. The simultaneous two-compile control completed in 16.3 seconds. | Production continuity failed after 120 seconds; the request-failure control failed after 9.1 seconds. Compilation continued after that failure, so it is not a passed continuity-under-load result. Both failures and actual transport categories are retained. |
| Build 31 bounded slow continuity | OPEN health requests receive up to eight seconds while pending-proof processing independently enforces the unchanged twelve-second identity lease and original risk expiry. Initial/recovery health requests retain four seconds. A completed independent client can restart at the next proof interval while slow trace peers remain pending; every rejecting peer response is still processed, and fast failures cannot cause a retry storm. Empty replies cannot renew identity; absolute expiry replaces the fast-failure count as the retry bound. Native shutdown revokes OPEN before allowing ten seconds to drain bounded children. | Development and offline/installed acceptance are pending. No policy evidence or production clock/cache timestamp is modified to obtain a pass. |

Three-minute mixed idle/fault resource samples were recorded with the dashboard visible. Later production OPEN samples and the real renewal observation have their separate scope above. They do not establish indefinite availability. Kernel-mode Tailscale, Ethernet, unattended cold connection and the interval before startup observation remain explicit gates. The actual restart exposed a vendor-extension availability gap. A login-session handoff now starts only the signed vendor app for the same previously approved persistent profile, without granting network permission; installed acceptance of that change is pending. The actual menu panel and its dashboard button passed after the operator opened the status item.

Hosted CI for the previous commit never started a step because of an account billing/spending restriction. Its failure is not a code-test failure or a pass. The same workflow checks were executed locally. No billing settings were changed.

Provider confidence is the confidence of a positive detection, not clean-line confidence. All required positive flags remain rejecting regardless of that number. Missing or malformed confidence remains unavailable; a valid low number does not independently invalidate otherwise complete negative detection evidence. See the [provider definition](https://proxycheck.io/api/).

## Failed replacement boundary

Every worker launch now forces a native restrictive seal before rotating the session. A failure to start the child or deliver its input revokes OPEN again. The decision does not trust cached phase metadata: a failed write/readback sequence can leave real tunnel rules different from the cached state. Two focused reproductions cover synchronized and stale metadata, repeated launch failures, first-retry sealing, continuous denial, successful replacement and explicit restoration. The initial shell worker adopts a preinstalled seal only after the native owner confirms its session and exact rule readback.

## Bounded risk-transport recovery

TLS setup receives each request's total budget rather than a fixed 1.5-second sublimit. Risk/DNS requests retain four seconds. Health now starts both fixed endpoints concurrently, each with a four-second deadline, avoiding two serial waits; process scheduling and local validation add overhead outside those request deadlines. A deterministic wrapper control reproduces rejection of a three-second handshake by the old budget while a four-second control succeeds.

Only a locked admission batch may retry a connection without an HTTP response, at most three connections charged to a persistent daily ceiling. Each retry publishes a restrictive heartbeat without renewing exit identity. HTTP errors, invalid bodies and negative verdicts do not cause this immediate retry. OPEN renewal remains one connection attempt. Controls cover transient recovery, quota denial, original cache age, restart-persistent spacing and UTC budget rollover. No physical DNS fallback, risk-condition relaxation or cache injection is used for live acceptance.

## Observation scheduling correction

### Evidence ordering and acceptance convergence

The next candidate distinguishes an observation's completion time from the
time its result is processed. While still OPEN, a matching observation may
continue the same identity chain only when its gap from the previous
observation and its current age are each at most twelve seconds. Current risk,
session, route, service and filter checks must also pass. A completed
observation is sampled again after local boundary work. Future observations,
an expired chain, a changed context and any negative reply are rejecting.
Once LOCKED or SEALED, a reply cannot revive the old authorization; the full
admission dwell is required. No lease or risk lifetime is extended.

A root-only atomic `evidence` record separates publication time, actual exit
observation time and risk time. Installed observers must check these distinct
values and current binding rather than infer proof freshness from a heartbeat.
This private record is not included in shared reports.

The deterministic ordering control reproduces the old on-time-response failure
before the change, then covers twenty state transitions and 289 observation-gap
and processing-age combinations. Actual elapsed-time streaming and the
production-cadence fixture pass for the candidate. Full offline and installed
acceptance remain pending; these results do not certify a release.

The first convergence candidate passed its offline controls but failed actual
acceptance: initial admission exceeded the 240-second controller deadline, and
a later observation found an expired chain. A new independent observer then
captured the accepted observation timestamp moving backwards while the worker
still reported OPEN. Both failures are retained. A completed health round could
select an older peer after a newer streamed independent response had already
been accepted; the outer decision then overwrote the newer timestamp. Every
proof writer now uses one context-bound, monotonic update. The actual outer
production decision has a regression counterexample, rather than only a test
of the pending-response helper.

The settling scheduler also measures its interval from the completed
observation. Work already spent waiting for a peer, checking the route or
reading back rules is not followed by another full settling delay. Six real
observations, the fifteen-second span and the eight-second maximum admission
gap remain unchanged. Five deterministic scheduling controls cover completed
work, partial intervals, OPEN cadence and missing initial evidence.

Build 32 passed all twenty checks in its frozen workflow snapshot. Its exact
installed component hashes matched the expanded package, and normal
administrator Resume completed real admission in approximately 42.2 seconds.
Previously accepted risk retained its original age; no clock, approval or
cache timestamp was changed. The subsequent stability/fault campaign remains
pending. An additional isolated controller fixture validates PID-reuse
protection, bounded environment restoration and HTTP reachability semantics.
The actual browser control uses a fresh Chromium profile and the debugging
pipe, so network sealing does not remove its observation channel. No user
browser account, cookie or candidate address is retained. HTTP errors count
as reachability, never as proof of interception.

Acceptance classifies availability and protection separately. A provider-loss
control expects continuous OPEN only while an independent, matching observation
actually continues the unexpired chain. If all providers become unavailable,
the required outcome is bounded sealing followed by fresh automatic admission,
with no physical application or DNS bypass. Such sealing is not itself a false
positive. Neither a status label nor a failed request alone proves the packet
boundary; packet and recovery evidence are separate requirements.

### Installed convergence evidence and remaining scheduling work

Build 32 completed a 600.2-second observation with 1,467 OPEN samples and no
failed check. Two concurrent optimized compilation controls ran during that
window. Installed worker TERM/KILL/STOP, supervisor death, restrictive rule
drift, VPN disconnection, Wi-Fi loss and complete health-request loss all
sealed and automatically re-admitted real provider evidence. The bounded
controller restored only the physical Wi-Fi setting when that test required
it; it did not clear protection or inject admission evidence. Individual
failures and the subsequent observations are retained separately.

Actual Chromium controls used fresh profiles, uncached anonymous document
requests and new WebRTC connections. Protected and recovered phases returned
HTTP responses and the approved reflexive candidate; the sealed phase returned
neither. An earlier recovered-browser failure coincided with a new evidence
expiry and remains retained. HTTP 403 establishes network reachability, not
account availability. Later controls recorded protection state continuously
during browser execution. Existing and fresh userspace Tailscale SSH failed
during VPN loss; a fresh SSH connection succeeded after automatic admission.

Physical IPv4 DNS UDP/TCP, TCP 853/443 and UDP 443 controls observed no matching
physical headers, while the approved-node positive control succeeded. Both
OPEN and sealed phases were observed. Aggregate PF counters are corroboration,
not per-flow attribution or an external wire capture. IPv6 lacked an equivalent
working positive path; its observations remain partial, rather than passing
because a socket could not route.

The attempted twelve-hour observation stopped after 374.0 seconds on an OPEN
publication with proof age thirteen seconds. That result is a failure, not a
completed soak. A follow-up observer captures immediate kernel readback and
the sealing transition, so delayed status publication is not confused with
continued kernel permission. The first failure did not retain that additional
boundary evidence and does not independently establish a physical bypass.

A separate elapsed-time counterexample shows that synchronous risk renewal
could begin with insufficient identity time remaining and then require
sealing. Build 33 schedules renewal from a fresh accepted proof, including a
streamed proof while another peer is pending. It reserves ten seconds for two
four-second network budgets and local work; otherwise it defers the lookup
without changing accepted timestamps. Controls cover deferral, successful
streamed renewal, rejection, expired identity and foreign binding.

The former continuity provider's actual resolved address belonged to the
[Cloudflare ranges](https://www.cloudflare.com/ips/), so a different domain did
not establish infrastructure diversity from the trace peers. AWS Check IP
returned the same approved address in three actual tunnel-bound HTTPS controls.
The candidate uses that service and a hostname-bound, TTL-limited resolver
cache. Controls reject legacy/foreign cache entries, time rollback, expiry,
invalid TTLs, wrong DNS questions, private addresses and the node itself.
Build 33 passed its 23 offline checks, a ten-minute installed observation,
provider-loss continuity, login-agent handoff and functional fault recovery.
The handoff exercised the installed login agent after vendor UI and VPN stop;
it was not a reboot or a FileVault-unlock test. A first thirty-second handoff
deadline failed and remains recorded; the measured vendor launch was about
31.5 seconds. IPv6 packet controls lacked an equivalent working positive path
and remain unverified.

A subsequent audit invalidated the build's full acceptance. Its worker-stall
report contained seven samples of a live tunnel rule with proof age thirteen
through fifteen seconds, and total proof loss contained another age-thirteen
sample. The controller had checked eventual sealing and recovery but omitted
the live-rule proof deadline. Physical default deny remained present; these
observations do not establish physical direct bypass. The attempted long
observation was deliberately stopped and is not a completed soak.

Build 34 adds revocation-only native observation supervision. The root guardian
checks the atomic proof's session, service, interface, endpoint, exit, original
observation and risk times independently of the UI heartbeat. Neither a new
heartbeat nor repeated reads renew an old proof. Monotonic elapsed time also
bounds the saved observation and risk lifetimes. Startup grace cannot shield
expired OPEN evidence. The single control owner checks every 250 milliseconds;
PF writer scheduling and completion remain bounded user-space operations,
not a hard-real-time kernel expiry guarantee.

Evidence is published before UI status. Both directions of that transition
are covered: a fresh restrictive publication must not cause a spurious worker
restart, and fresh OPEN evidence is checked even before the UI status catches
up. Neither transition creates an admission exception. The old native core
reproduces retained OPEN after proof expiry under a continuously fresh
heartbeat; the corrected core seals and subsequently permits fresh admission.
The installed controller now rejects actual tunnel permission with expired
proof or risk, separately from late UI publication after the kernel is sealed.
Build 34 passed all 25 offline checks, 600.1 seconds of installed continuous
OPEN observation (1,470 samples), concurrent native compilation load, all
three installed XPC wrong-hash controls, vendor login-agent handoff and a
ninety-second trace-provider interruption with independent address continuity.
The first installed worker-restart fault then failed its stricter evidence
contract: the kernel tunnel rule was committed while the published record
still showed LOCKED with no risk timestamp. The worker had accepted risk in
memory but had not published it yet. This is an admission-publication ordering
failure; it does not by itself establish that the actual risk decision was
missing or that physical direct traffic bypassed the fence. The failure is
retained, and the long observation was not started.

Admission now has an explicit prepare/commit protocol. After identity, risk
and route checks, the worker publishes a complete private ADMITTING record
while the UI remains LOCKED, then submits and reads back the kernel rules,
then publishes committed OPEN. A failed preparation cannot reach the rule
write. A failed rule write cannot publish OPEN. The native supervisor applies
the original proof and risk deadlines to ADMITTING as well as OPEN, so a
freeze after the rule write cannot hide behind a restrictive UI status.
Prepared evidence alone cannot turn the UI green or grant kernel traffic.
Production-decision and native-supervisor counterexamples reproduce both
the old publication gap and an interrupted transaction, with fixed-path
controls for preparation failure, rule failure and subsequent recovery.
Build 35 passed all 27 offline checks, a 600-second installed observation,
login handoff, a ninety-second trace-provider loss and eleven strict installed
fault scenarios. Real anonymous browser requests, fresh WebRTC observations,
userspace Tailscale SSH interruption/recovery and physical IPv4 packet controls
passed. IPv6 controls lacked an equivalent working positive path and remain
unverified; login handoff is not cold-boot evidence.

The subsequent continuous-OPEN observation failed after 7,619 seconds, with
three actual risk renewals completed. The native supervisor revoked permission
when exit evidence reached its deadline. Immediate PF readback showed the
default deny present and no tunnel-pass rule. The last two transport rounds
contained TLS handshake failures from all three probes. Fresh admission
recovered automatically; no corrective operator action was issued. This is a
failed continuous-availability run, not a completed twelve-hour soak and not
evidence of physical direct leakage. A later paired TLS-backend comparison
completed 24 matching responses per backend with no failures; it did not
reproduce or identify the original TLS failure's cause. The deadline and
admission rules have not been relaxed to turn that run into a pass.

The next candidate removes the Foundation-generated bundle identity from
explicit anonymous service checks and records only fixed local transport-error
categories. Actual loopback requests verify header suppression, cookie
non-replay, credential absence and redirect refusal, with a default-session
positive control. Hostile-error fixtures verify category-only retention and
unchanged transport verdicts. Ordinary application HTTPS is not intercepted or
rewritten. The full request inventory and local-visibility boundary are in
[network privacy](Privacy.md). The exact candidate still needs installation and
fresh stability acceptance; these changes do not claim to explain the TLS
incident.

Health observations retain the completion timestamp of the selected response, including when a slower concurrent response finishes later. Either endpoint's valid different exit is rejecting evidence. A new round starts from the actual observation time, with a two-second target interval and a fixed request budget; filter readback work is included in scheduling rather than added to a count of sleeps. Identity evidence still expires after twelve seconds. Stability requires six actual observations spanning fifteen seconds. A bounded empty round cannot renew identity or waive expiry.

Fresh keyless evidence retains its original one-hour age. OPEN proactively fetches new evidence at forty-five minutes. Transient lookup failures can retain only the remaining original lifetime; a rejection or invalid response revokes it. Negative cache replacement prevents a restart from reviving old clean evidence. A root-only budget permits at most 48 API connections per UTC day, conservatively below the provider's documented anonymous allowance of 100 shared queries. OPEN DNS/no-HTTP retry spacing is at least one minute; HTTP errors wait five minutes, quota errors and rejected evidence fifteen. None extends the accepted timestamp. Expired, future or context-mismatched evidence cannot release traffic.

OPEN renewal does not add a post-risk HTTPS round or update identity from a risk response. Identity must remain valid after all work. Initial locked admission still probes afterward, and a gap longer than eight seconds restarts the stability window while retaining independently fresh risk evidence. Concurrent health selection uses the latest actual matching response; either endpoint's valid exit or keyless-region mismatch rejects release. The app may refresh authenticated profile display metadata after restarting without submitting a new activation for an unchanged healthy root session.
