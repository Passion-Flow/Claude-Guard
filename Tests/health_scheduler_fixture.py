"""Elapsed-time counterexamples for independent health-provider scheduling.

Only the production shell definitions execute. HTTP, routes and packet writes
are replaced locally; host networking, clocks and installed policy are untouched.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import json
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("--worker", type=Path)
parser.add_argument("--expect-counterexample", action="store_true")
options = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
worker = options.worker or repo / "Sources/GuardWorker.sh"
definitions = worker.read_text().split("action=${1-}")[0]

def exercise(provider, rejection=False):
    with tempfile.TemporaryDirectory(prefix="cg-provider-scheduling-") as temporary:
        root = Path(temporary)
        runtime = root / "runtime"
        runtime.mkdir(mode=0o700)
        settings = {"provider": provider, "rejection": rejection}
        (root / "scenario.json").write_text(json.dumps(settings))
        curl = root / "curl"
        curl.write_text("""#!/usr/bin/python3
from pathlib import Path
import json,os,sys,time
root=Path(__file__).parent
args=sys.argv[1:]
label="independent" if args[-1]=="https://checkip.amazonaws.com" else ("primary" if args[-1].startswith("https://1.1.1.1/") else "backup")
settings=json.loads((root/"scenario.json").read_text())
counter=root/(label+".count")
count=int(counter.read_text())+1 if counter.exists() else 1
counter.write_text(str(count))
def event(kind):
 with (root/"events").open("a") as stream:
  stream.write(json.dumps({"provider":label,"kind":kind,"at":time.time(),"attempt":count,"round":2 if (root/"second-round").exists() else 1})+"\\n")
event("start")
budget=float(args[args.index("--max-time")+1])
healthy=label==settings["provider"]
delay=(6.3 if (root/"second-round").exists() else .1) if healthy else 9
time.sleep(min(delay,budget))
if not healthy or delay>budget:
 event("end");raise SystemExit(28)
address="192.0.2.99" if settings["rejection"] and count>1 else "192.0.2.42"
body=address if label=="independent" else "ip="+address+"\\nloc=US\\n"
Path(args[args.index("--output")+1]).write_text(body)
event("end")
print("200",end="")
""")
        curl.chmod(0o700)
        (runtime / "independent-address").write_text("9.9.9.9|" + str(int(time.time())) + "|600|checkip.amazonaws.com")
        setup = f"""
directory='{runtime}'; health_cache_file="$directory/independent-address"
iface=utun1; peer=192.0.2.7; expected=192.0.2.42; risk_region=US
session=fixture; vpn_service=service; endpoint_key=endpoint; bound_path=path
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_context="$evidence_context|$risk_region"
phase=OPEN; risk_checked_at=$(( $(/bin/date +%s) - 100 ))
last_verified=$(( $(/bin/date +%s) - 1 ))
rules_intact() {{ return 0; }}
underlay_snapshot() {{ printf path; }}
vpn_connection() {{ printf 'Connected utun1'; }}
probe_route_reason() {{ return 0; }}
route_via_tunnel() {{ return 0; }}
load_phase() {{ /bin/date +%s >> '{root}/sealed'; }}
enforce_seal() {{ load_phase SEALED; }}
publish() {{ return 0; }}
if sample_exit; then :; fi
"""
        if not rejection:
            setup += f"""
/usr/bin/touch '{root}/second-round'
if sample_exit; then :; fi
"""
        setup += """
fresh=false; if identity_fresh "$(/bin/date +%s)"; then fresh=true; fi
printf '%s|%s' "$phase" "$fresh"
"""
        result = subprocess.run(["/bin/sh", "-c", definitions.replace("/usr/bin/curl", str(curl)) + setup],
                                capture_output=True, text=True, timeout=40)
        assert result.returncode == 0, (provider, result.stderr)
        assert not list(runtime.glob("health.*")), "request children were not drained"
        events = [json.loads(line) for line in (root / "events").read_text().splitlines()]
        active = {}
        starts = {}
        for row in events:
            label = row["provider"]
            if row["kind"] == "start":
                assert not active.get(label), ("overlapping provider requests", label)
                active[label] = True
                starts.setdefault((label,row["round"]), []).append(row["at"])
            else:
                assert active.get(label), ("unpaired request completion", label)
                active[label] = False
        assert not any(active.values())
        # Wall-clock scheduling can cross a second boundary; enforce a lower
        # elapsed-time bound as well as a bounded total number of attempts.
        for label, times in starts.items():
            assert len(times) <= 12, ("unbounded request count", label, times)
            assert all(b-a >= .8 for a,b in zip(times,times[1:])), ("request storm", label, times)
        outcome = {"provider": provider, "rejection": rejection, "result": result.stdout,
                   "sealed": (root / "sealed").exists(), "attempts": {k[0]+"-round-"+str(k[1]):len(v) for k,v in starts.items()}}
        if rejection:
            assert outcome["sealed"] and result.stdout.split("|")[0] != "OPEN", outcome
        return outcome

with ThreadPoolExecutor(max_workers=3) as pool:
    continuity = list(pool.map(exercise, ("primary", "backup", "independent")))
if options.expect_counterexample:
    assert all(row["sealed"] for row in continuity if row["provider"] in ("primary","backup")), continuity
    assert not next(row for row in continuity if row["provider"]=="independent")["sealed"], continuity
    print("CONFIRMED: the previous scheduler stalls healthy trace providers behind slow peers")
else:
    assert all(row["result"]=="OPEN|true" and not row["sealed"] for row in continuity), continuity
    with ThreadPoolExecutor(max_workers=3) as pool:
        rejecting = list(pool.map(lambda name: exercise(name, True), ("primary","backup","independent")))
    print("PASS: every healthy provider maintains continuity across slow peers; repeated conflicting replies still seal; no per-provider overlap or request storm")
print(json.dumps(continuity, sort_keys=True))

