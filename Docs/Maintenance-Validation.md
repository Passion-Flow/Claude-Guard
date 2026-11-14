# Maintenance validation

## Defect and correction

An app cleaner removed the visible application while privileged enforcement components remained. The previous uninstall implementation threw when the app was already missing, and the package required an installed primary or recovery helper. Together these defects made partial deletion an unreliable recovery path.

Version 1.0.1 carries a native removal engine inside Uninstall.pkg. It does not require installed trust metadata, helpers or an app bundle. Installation also saves a copy outside the app/helper directories, and the application menu exposes removal directly.

The removal order is explicit: remove startup registrations, stop jobs and packet writers, clear and verify the owned PF anchor, release recorded references, remove known product files and user data, forget receipts, then verify again. A separate bounded task removes the final package receipt after Installer commits it. Root-only execution, fixed identifiers, bounded subprocesses and descriptor-relative deletion constrain the operation.

## Offline verification

The native fixture exercises production cleanup code against disposable files and simulated operating-system command replies. It covers:

- Complete installation and repeated removal.
- Application missing, helpers/trust missing, and both missing.
- Jobs refusing to stop and job-query errors.
- PF query, flush and repeated busy failures; bounded recovery from busy replies.
- A missing anchor corroborated by its parent, and a present child anchor that must not count as absent.
- A late packet-rule writer detected by final readback.
- Receipt removal failure and malformed PF-token records.
- Leaf symlinks unlinked without following them, and unsafe parent symlinks rejected.
- Preservation of unrelated applications, startup registrations and exported reports.

Run `python3 -I Tests/uninstall_fixture.py`. The fixture does not install a job or change host networking. Package-hook coverage also checks that removal runs with both installed helpers absent.

## Installed verification

The administrator-only driver is `Tests/installed_uninstall.py`. It requires explicit execution and root-owned staged packages. The following cases passed locally for version **1.0.1, build 43** on 2026-11-15:

| Case | Result |
| --- | --- |
| Intact installation | Passed; restrictive rules and installed components removed. |
| Application removed first | Passed; independent local recovery copy completed removal. |
| Application and helpers removed first | Passed without installed trust or helper executables. |
| Live guardian jobs and a process writing a final seal on exit | Passed; jobs and writer stopped before the final verified rule cleanup. |
| Repeated uninstall after each case | Passed in all four cases. |
| Fresh HTTPS after each removal | Passed in all four cases. |

Each case uses a real restrictive product anchor, the independent recovery copy and residual-file/job/receipt readback. The fourth case starts a controlled root writer with the production worker's process contract; its termination handler writes another restrictive rule. This checks actual process termination and late-write ordering, rather than only a mocked state transition. A separate local watchdog can run removal if the controller stalls. The test reference is released by the test controller; it is not represented as a product-owned reference.

Tested installer SHA-256: `f0b2ac189c83623359bb5ddc83fb94d5503feec1ed6bacb7fb30e82c90e41919`.

Tested independent uninstaller SHA-256: `dc38f2a9267fc36c4d238e2ab40824fdb2ab5c706ff64a3e0a773ab090d119a8`.

The release includes redacted machine-readable results. These checks establish maintenance behavior for the tested packages; they do not reclassify earlier release observations or waived tests.

## Cross-environment regression follow-up

Hosted validation exposed two timing assumptions before publication. The worker fixture now requires the injected failures and a newer accepted response, rather than requiring a transient retry label when recovery completes within the same round.

A separate slow-boundary counterexample reproduced a runtime scheduling defect: repeated unchanged checks used their start time, consuming the remaining retry window while finished request slots were reaped. Build 44 schedules those checks from completion. Evidence expiry and newly changed replies are still evaluated before throttling; proof lifetimes, request budgets and admission dwell are unchanged.

The deterministic regression executes the production pending-evidence and completion functions with a local fixture clock. The old worker seals without retrying; the corrected worker retries and accepts fresh evidence. Additional cases retain immediate rejection for conflicting replies and expired identity/risk, and recheck a changed path on the next tick. A real elapsed-time simulation with bounded additional local-command delays also reproduces the old failure and passes with the correction. These simulations do not modify host networking or the system clock.

Final build 44 package acceptance must be recorded in the release's machine-readable evidence before publication; the build 43 hashes above identify the earlier maintenance run.

## Limits

The driver reproduces partial deletion; it does not claim GUI testing of every cleaner's proprietary removal strategy. No uninstaller can run a file that another privileged program has also deleted. Keep the standalone release package separately. Unknown PF reference identifiers are preserved if their ownership records are gone; global PF is never disabled to guess at cleanup.

Removal does not erase system audit/Installer history, user exports, downloaded archives or another application's configuration. New installation, reactivation and account availability are separate concerns. This maintenance acceptance does not establish cold-boot behavior, every macOS/CPU combination or a twelve-hour endurance result.
