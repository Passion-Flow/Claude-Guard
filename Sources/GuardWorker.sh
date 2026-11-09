# Executed by an administrator-authorized /bin/sh on the target Mac.
set -eu
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
unset CDPATH ENV BASH_ENV
pf=/sbin/pfctl
anchor=com.apple/00000.org.claudeguard.runtime
directory=/var/run/org.claudeguard.runtime
probe_primary=1.1.1.1
probe_backup=1.0.0.1
stability_seconds=15
stability_samples=6
stability_tick=3
stability_max_gap=8
policy_id=ipv4-tunnel-v1
session=
mode=
owned=0
token=
status_file=
last_journal_key=
finish_reason=stopped
end_state=IDLE
restore_requested=0
trial_verified=0
vpn_service=
endpoint_key=
loaded=

valid_ip() {
  printf '%s\n' "$1" | /usr/bin/awk -F. '
    NF != 4 { exit 1 }
    { for (i=1; i<=4; i++) if ($i !~ /^(0|[1-9][0-9]*)$/ || length($i)>3 || $i>255) exit 1 }'
}
valid_iface() {
  case "$1" in utun*) suffix=$(printf '%s' "$1" | /usr/bin/cut -c5-);; *) return 1;; esac
  case "$suffix" in ""|*[!0-9]*) return 1;; esac
}
valid_port() {
  case "$1" in ""|*[!0-9]*) return 1;; esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
valid_session() {
  case "$1" in ""|*[!a-f0-9-]*) return 1;; esac
  [ "$(/bin/echo "$1" | /usr/bin/tr -d '\n' | /usr/bin/wc -c | /usr/bin/tr -d ' ')" -eq 36 ]
}
shadowrocket_services() {
  /usr/sbin/scutil --nc list | /usr/bin/awk '
    index($0, "[VPN:com.liguangming.Shadowrocket]") {
      for (i=1; i<=NF; i++) if (length($i)==36 && $i ~ /^[0-9A-Fa-f-]+$/) print $i
    }'
}

vpn_connection() {
  shadowrocket_services | /usr/bin/grep -Fxq "$1" || return 1
  /usr/sbin/scutil --nc status "$1" | parse_vpn_status
}

parse_vpn_status() {
  /usr/bin/awk '
    NR==1 { state=$0 }
    /^[[:space:]]*}[[:space:]]*$/ {
      if (depth==layer) layer=0
      if (depth==extended) extended=0
      depth--
      next
    }
    /[{][[:space:]]*$/ {
      depth++
      if ($0 ~ /^Extended Status <dictionary>/) extended=depth
      if (extended && depth==extended+1 && $1 ~ /^IPv[46]$/) layer=depth
      next
    }
    layer && depth==layer && $1=="InterfaceName" && $2==":" && $3~/^utun[0-9]+$/ {
      if (tunnel!="" && tunnel!=$3) ambiguous=1
      tunnel=$3
    }
    END {
      if (state=="Connected" && tunnel!="" && !ambiguous) print "Connected " tunnel
      else if (state=="Disconnected" || state=="Connecting" || state=="Disconnecting") print state
      else exit 1
    }'
}

pin_vpn_service() {
  matches=
  for service_id in $(shadowrocket_services); do
    if [ "$(vpn_connection "$service_id" || true)" = "Connected $iface" ]; then
      [ -z "$matches" ] || return 1
      matches=$service_id
    fi
  done
  [ -n "$matches" ] || return 1
  printf '%s\n' "$matches"
}

build_rules() {
  rule_phase=$1
  extra=
  [ "$protocol" != tcp ] || extra='flags any'
  printf 'pass quick on lo0 all no state label "CG_LOOP"\n'
  printf 'pass out quick inet proto %s from any to %s port = %s %s keep state (if-bound) label "CG_PEER_OUT"\n' "$protocol" "$peer" "$port" "$extra"
  # IPv4 DHCP only. No general LAN, DNS, or IPv6 exception.
  printf 'pass out quick inet proto udp from any port = 68 to 255.255.255.255 port = 67 no state label "CG_DHCP_OUT"\n'
  printf 'pass in quick inet proto udp from any port = 67 to any port = 68 no state label "CG_DHCP_IN"\n'
  if [ "$rule_phase" = OPEN ]; then
    printf 'pass quick on %s inet all no state label "CG_TUNNEL"\n' "$iface"
  elif [ "$rule_phase" = LOCKED ]; then
    for probe in "$probe_primary" "$probe_backup"; do
      printf 'pass out quick on %s inet proto tcp from any to %s port = 443 flags any no state label "CG_PROBE_OUT"\n' "$iface" "$probe"
      printf 'pass in quick on %s inet proto tcp from %s port = 443 to any flags any no state label "CG_PROBE_IN"\n' "$iface" "$probe"
    done
  fi
  printf 'block drop quick all label "CG_BLOCK"\n'
}

preflight() {
  # Do not reload the system's root rules. Refuse a layout we have not accounted for.
  main=$("$pf" -sr 2>/dev/null) || return 1
  printf '%s\n' "$main" | /usr/bin/awk '
    /^[[:space:]]*$/ { next }
    $0=="anchor \"cisco.anyconnect.vpn\" all" { next }
    $0=="anchor \"com.apple/*\" all" { count++; next }
    { bad=1 }
    END { exit (bad || count!=1) }' || return 1
  if printf '%s\n' "$main" | /usr/bin/grep -q 'cisco.anyconnect.vpn'; then
    cisco=$("$pf" -a cisco.anyconnect.vpn -sr 2>/dev/null) || return 1
    [ -z "$cisco" ] || return 1
  fi
  siblings=$("$pf" -a com.apple -s Anchors 2>/dev/null) || return 1
  printf '%s\n' "$siblings" | /usr/bin/awk -v ours="$anchor" '
    NF {
      name=$1
      if (name !~ /\//) name="com.apple/"name
      if (name != ours && name < ours) bad=1
    }
    END { exit bad }' || return 1
  interfaces=$("$pf" -v -s Interfaces 2>/dev/null) || return 1
  # On supported layouts the verbose output marks skipped interfaces with "(skip)".
  printf '%s\n' "$interfaces" | /usr/bin/awk '/skip/ && $1!="lo0" { bad=1 } END { exit bad }'
}

publish() {
  now=$(/bin/date +%s)
  tmp=$(/usr/bin/mktemp "$directory/status.XXXXXX")
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$session" "$1" "$now" "$iface" "$expected" "$2" "$3" "$expires" "$mode" "$trial_verified" "$vpn_service" "$endpoint_key" "$policy_id" > "$tmp"
  /bin/chmod 0644 "$tmp"
  /bin/mv -f "$tmp" "$status_file"
  key="$session|$1|$iface|$2|$3|$mode|$trial_verified"
  if [ "$last_journal_key" != "$key" ]; then
    journal=$(/usr/bin/mktemp "$directory/events.XXXXXX")
    if [ -f "$directory/events" ]; then /usr/bin/tail -n 249 "$directory/events" > "$journal"; fi
    /bin/cat "$status_file" >> "$journal"
    /bin/chmod 0644 "$journal"
    /bin/mv -f "$journal" "$directory/events"
    last_journal_key=$key
  fi
}

clear_owned() {
  if [ "$owned" = 1 ]; then
    "$pf" -a "$anchor" -F rules >/dev/null 2>&1 || return 1
    remaining=$("$pf" -a "$anchor" -sr 2>/dev/null) || return 1
    [ -z "$remaining" ] || return 1
  fi
  if [ -n "$token" ]; then
    "$pf" -X "$token" >/dev/null 2>&1 || return 1
  fi
}

remove_marker() {
  if [ -f "$1" ]; then /bin/unlink "$1"; fi
}

remove_active() {
  for field in pid token session verified; do
    remove_marker "$directory/active/$field"
  done
  /bin/rmdir "$directory/active"
  remove_marker "$directory/restore-$session"
  remove_marker "$directory/continue-$session"
}

cleanup() {
  trap - EXIT HUP INT TERM
  if [ "$owned" = 1 ] && [ "$restore_requested" = 0 ]; then
    # Exit traps run on ordinary errors too. Preserve the filter on faults.
    current=$("$pf" -a "$anchor" -sr 2>/dev/null || true)
    if [ -n "$loaded" ] && [ "$current" = "$loaded" ]; then
      load_phase SEALED || true
    fi
    publish ERROR "-" worker-stopped || true
    return
  fi
  if clear_owned; then
    publish "$end_state" "-" "$finish_reason" || true
    remove_active
  else
    publish ERROR "-" rollback-failed || true
  fi
}

handle_signal() {
  if [ -f "$directory/restore-$session" ]; then
    restore_requested=1
    finish_reason=stopped
    end_state=IDLE
  fi
  exit 0
}

load_phase() {
  build_rules "$1" | "$pf" -a "$anchor" -f - >/dev/null 2>&1 || return 1
  loaded=$("$pf" -a "$anchor" -sr 2>/dev/null) || return 1
  case "$loaded" in *CG_BLOCK*CG_*) return 1;; *CG_BLOCK*) :;; *) return 1;; esac
  case "$1:$loaded" in
    OPEN:*CG_TUNNEL*|LOCKED:*CG_PROBE_OUT*) :;;
    SEALED:*CG_TUNNEL*|SEALED:*CG_PROBE_OUT*) return 1;;
    SEALED:*CG_PEER_OUT*) :;;
    *) return 1;;
  esac
}

rules_intact() {
  current=$("$pf" -a "$anchor" -sr 2>/dev/null) || return 1
  info=$("$pf" -s info 2>/dev/null) || return 1
  preflight && [ "$current" = "$loaded" ] &&
    printf '%s\n' "$info" | /usr/bin/grep -q '^Status: Enabled'
}

underlay_snapshot() {
  routes=$(/usr/sbin/netstat -rn -f inet 2>/dev/null) || return 1
  [ -n "$routes" ] || return 1
  links=$(/sbin/ifconfig -a 2>/dev/null) || return 1
  [ -n "$links" ] || return 1
  # A default route can linger after a Wi-Fi disconnect. Require a live IPv4 link too.
  usable=$(printf '%s\n' "$links" | /usr/bin/awk '
    /^[^[:space:]]/ {
      iface_name=$1
      sub(/:$/, "", iface_name)
      if ($0 ~ /[<,]UP[,>]/ && $0 ~ /[<,]RUNNING[,>]/) up[iface_name]=1
    }
    $1=="inet" { ipv4[iface_name]=1 }
    $1=="status:" && $2!="active" { down[iface_name]=1 }
    END { for (i in up) if (ipv4[i] && !down[i]) printf "%s ", i }') || return 1
  # Store only visible non-tunnel default routes, in memory, to detect a path change.
  keys=$(printf '%s\n' "$routes" | /usr/bin/awk -v usable="$usable" '
    BEGIN { count=split(usable, list, " "); for (i=1; i<=count; i++) ready[list[i]]=1 }
    $1=="default" && ready[$4] && $4 !~ /^(utun|lo)[0-9]+$/ {
      print $4 "=" $2
    }') || return 1
  keys=$(printf '%s\n' "$keys" | /usr/bin/sort -u) || return 1
  printf 'v4:%s\n' "$keys"
}

reset_stability() {
  stable_since=0
  consecutive=0
  missed_round=0
  last_verified=0
}

sample_exit() {
  # An actual, different IP is evidence. A timeout or malformed response is not.
  # Only fall back if the primary produced no valid IP.
  probe_used=
  for probe in "$probe_primary" "$probe_backup"; do
    result=$(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/var/empty \
      /usr/bin/curl -q -4 --noproxy '*' --interface "$iface" --proto '=https' \
        --connect-timeout 1.5 --max-time 2 -fsS "https://$probe/cdn-cgi/trace" 2>/dev/null) || continue
    observed=$(printf '%s\n' "$result" | /usr/bin/awk -F= '$1=="ip" { print $2; exit }')
    if valid_ip "$observed"; then
      probe_used=$probe
      return 0
    fi
  done
  observed=-
  return 1
}

action=$1
case "$action" in
  parse-vpn) parse_vpn_status; exit;;
  rules)
    # Nonprivileged preview and syntax tests. No /dev/pf writes.
    iface=$2; peer=$3; protocol=$4; port=$5; rule_phase=$6
    valid_iface "$iface" && valid_ip "$peer" && valid_port "$port" || exit 2
    case "$protocol" in tcp|udp) :;; *) exit 2;; esac
    case "$rule_phase" in OPEN|LOCKED|SEALED) :;; *) exit 2;; esac
    build_rules "$rule_phase"
    exit
    ;;
esac

[ "$(/usr/bin/id -u)" -eq 0 ] || exit 77
if [ ! -d "$directory" ]; then
  /bin/mkdir -m 0755 "$directory"
fi
[ ! -L "$directory" ] && [ "$(/usr/bin/stat -f '%u:%Lp' "$directory")" = 0:755 ] || exit 78
status_file=$directory/status

case "$action" in
  continue)
    [ -f "$directory/active/verified" ] || exit 82
    session=$(/bin/cat "$directory/active/session")
    valid_session "$session" || exit 82
    /usr/bin/awk -F'|' -v id="$session" '
      $1==id && ($9=="trial" || $9=="paused") && $2!="DRIFT" && $2!="ERROR" { ok=1 }
      END { exit !ok }' "$status_file" || exit 82
    : > "$directory/continue-$session"
    exit
    ;;
  stop)
    [ -d "$directory/active" ] || exit 0
    worker_pid=$(/bin/cat "$directory/active/pid" 2>/dev/null || true)
    session=$(/bin/cat "$directory/active/session" 2>/dev/null || true)
    token=$(/bin/cat "$directory/active/token" 2>/dev/null || true)
    case "$worker_pid" in ""|*[!0-9]*) worker_pid=0;; esac
    case "$token" in *[!0-9]*) exit 79;; esac
    if [ "$worker_pid" -gt 1 ] && valid_session "$session"; then
      command=$(/bin/ps -ww -p "$worker_pid" -o command= 2>/dev/null || true)
      case "$command" in
        *" claude-guard-worker worker $session "*)
          : > "$directory/restore-$session"
          /bin/kill -TERM "$worker_pid" 2>/dev/null || true
          for tick in 1 2 3 4 5 6; do
            [ -d "$directory/active" ] || exit 0
            /bin/sleep 1
          done
          if /bin/kill -0 "$worker_pid" 2>/dev/null; then exit 80; fi
          ;;
      esac
    fi
    loaded=$("$pf" -a "$anchor" -sr 2>/dev/null)
    case "$loaded" in *CG_BLOCK*) owned=1;; "") :;; *) exit 81;; esac
    clear_owned
    remove_active
    mode=manual; expires=0; iface=-; expected=-
    publish IDLE "-" stopped
    exit
    ;;
  worker)
    session=$2; mode=$3; iface=$4; peer=$5; protocol=$6; port=$7; expected=$8
    shift 8
    approved_service=
    if [ "$#" -gt 0 ]; then approved_service=$1; fi
    endpoint_key="$peer:$port/$protocol"
    valid_session "$session" && valid_iface "$iface" && valid_ip "$peer" && valid_ip "$expected" && valid_port "$port" || exit 2
    case "$protocol" in tcp|udp) :;; *) exit 2;; esac
    case "$mode" in trial|live) :;; *) exit 2;; esac
    [ "$peer" != "$probe_primary" ] && [ "$peer" != "$probe_backup" ] || exit 2
    /bin/mkdir -m 0700 "$directory/active" || exit 83
    printf '%s\n' "$$" > "$directory/active/pid"
    printf '%s\n' "$session" > "$directory/active/session"
    expires=0
    if [ "$mode" = trial ]; then expires=$(($(/bin/date +%s) + 60)); fi
    trap cleanup EXIT
    trap handle_signal HUP INT TERM
    publish VERIFYING "-" preflight
    end_state=ERROR
    finish_reason=pf-layout
    preflight || exit 84
    [ -z "$("$pf" -a "$anchor" -sr 2>/dev/null)" ] || exit 85
    finish_reason=tunnel-unverified
    phase=LOCKED
    if [ -n "$approved_service" ]; then
      [ "$mode" = live ] || exit 86
      case "$approved_service" in *[!0-9A-Fa-f-]*) exit 86;; esac
      shadowrocket_services | /usr/bin/grep -Fxq -- "$approved_service" || exit 86
      vpn_service=$approved_service
      connection=$(vpn_connection "$vpn_service" || true)
      case "$connection" in
        "Connected utun"*)
          iface=$(printf '%s' "$connection" | /usr/bin/cut -d' ' -f2)
          valid_iface "$iface" && /sbin/ifconfig "$iface" >/dev/null 2>&1 || exit 86
          ;;
        *) phase=SEALED;;
      esac
    else
      vpn_service=$(pin_vpn_service) || exit 86
      /sbin/ifconfig "$iface" >/dev/null 2>&1 || exit 86
    fi
    finish_reason=pf-load
    build_rules "$phase" | "$pf" -n -a "$anchor" -f - >/dev/null 2>&1 || exit 87
    owned=1
    load_phase "$phase" || exit 88
    enabled=$("$pf" -E 2>&1) || exit 89
    token=$(printf '%s\n' "$enabled" | /usr/bin/awk -F: '/Token[[:space:]]*:/ {gsub(/[[:space:]]/,"",$2); print $2; exit}')
    case "$token" in ""|*[!0-9]*) token=; exit 90;; esac
    printf '%s\n' "$token" > "$directory/active/token"
    # Remove floating state inherited from before activation. This resets active connections once.
    "$pf" -F states >/dev/null 2>&1 || exit 91
    last_probe=0
    reset_stability
    bound_path=
    drift=0
    next_retry=0
    retry_delay=3
    retry_pid=
    recovery_link_lost=0
    recovery_probe_misses=0
    while :; do
      now=$(/bin/date +%s)
      current=
      if [ "$drift" = 1 ] || ! rules_intact; then
        # Latch drift. Other rules may have created new floating states in the meantime.
        drift=1
        if [ "$phase" = OPEN ] && [ "$current" = "$loaded" ]; then
          if load_phase SEALED; then phase=SEALED; fi
        fi
        publish DRIFT "-" pf-changed
        reset_stability
        /bin/sleep 2
        continue
      fi
      if [ "$trial_verified" = 1 ] && [ "$mode" != live ] && [ -f "$directory/continue-$session" ]; then
        remove_marker "$directory/continue-$session"
        mode=live
        expires=0
      fi
      if [ "$mode" = trial ] && [ "$now" -ge "$expires" ]; then
        mode=paused
        expires=0
        reset_stability
      fi
      if [ "$mode" = paused ]; then
        if [ "$phase" != SEALED ]; then
          load_phase SEALED || { drift=1; continue; }
          phase=SEALED
        fi
        publish LOCKED "-" trial-paused
        /bin/sleep 1
        continue
      fi
      path_reason=
      if ! path=$(underlay_snapshot); then
        path_reason=route-unknown
      elif [ "$path" = v4: ]; then
        path_reason=underlay-offline
        recovery_link_lost=1
      fi
      if [ -n "$path_reason" ]; then
        reset_stability
        recovery_probe_misses=0
        bound_path=
        next_retry=0
        retry_delay=3
        if [ "$phase" != SEALED ]; then
          load_phase SEALED || { drift=1; continue; }
          phase=SEALED
        fi
        publish LOCKED "-" "$path_reason"
        /bin/sleep 1
        continue
      fi
      connection=$(vpn_connection "$vpn_service" || true)
      case "$connection" in
        "Connected utun"*)
          candidate=$(printf '%s' "$connection" | /usr/bin/cut -d' ' -f2)
          valid_iface "$candidate" || exit 92
          reason=revalidating
          if [ -n "$bound_path" ] && [ "$path" != "$bound_path" ]; then reason=route-changed; fi
          if [ "$phase" = SEALED ] || [ "$candidate" != "$iface" ] || [ "$reason" = route-changed ] ||
             { [ "$phase" = OPEN ] && { [ $((now - last_probe)) -gt 10 ] || [ "$now" -lt "$last_probe" ]; }; }; then
            iface=$candidate
            phase=LOCKED
            reset_stability
            load_phase LOCKED || { drift=1; continue; }
            publish LOCKED "-" "$reason"
          fi
          bound_path=$path
          ;;
        *)
          reset_stability
          bound_path=
          if [ "$phase" != SEALED ]; then
            load_phase SEALED || { drift=1; continue; }
            phase=SEALED
          fi
          reason=vpn-wait
          if [ "$connection" = Disconnected ]; then
            if [ "$recovery_link_lost" = 1 ]; then
              next_retry=$now
              recovery_link_lost=0
            elif [ "$next_retry" -eq 0 ]; then
              next_retry=$((now + retry_delay))
            fi
            if [ "$now" -ge "$next_retry" ] &&
               { [ -z "$retry_pid" ] || ! /bin/kill -0 "$retry_pid" 2>/dev/null; }; then
              /usr/sbin/scutil --nc start "$vpn_service" >/dev/null 2>&1 &
              retry_pid=$!
              next_retry=$((now + retry_delay))
              if [ "$retry_delay" -lt 48 ]; then retry_delay=$((retry_delay * 2)); fi
              reason=vpn-reconnect
            fi
          fi
          publish LOCKED "-" "$reason"
          /bin/sleep 1
          continue
          ;;
      esac
      observed=-
      probe_ok=0
      if /sbin/ifconfig "$iface" >/dev/null 2>&1 && sample_exit; then probe_ok=1; fi
      last_probe=$(/bin/date +%s)
      if [ "$mode" = trial ] && [ "$last_probe" -ge "$expires" ]; then
        continue
      fi
      path_after=$(underlay_snapshot || true)
      connection_after=$(vpn_connection "$vpn_service" || true)
      if [ "$connection_after" != "Connected $iface" ] || [ "$path_after" != "$bound_path" ]; then
        reset_stability
        if [ "$phase" != SEALED ]; then
          load_phase SEALED || { drift=1; continue; }
          phase=SEALED
        fi
        reason=vpn-wait
        case "$path_after" in
          '') reason=route-unknown;;
          v4:) reason=underlay-offline; recovery_link_lost=1; recovery_probe_misses=0;;
          *) if [ "$connection_after" = "Connected $iface" ]; then reason=route-changed; fi;;
        esac
        publish LOCKED "-" "$reason"
        /bin/sleep 1
        continue
      fi

      desired=LOCKED
      reason=probe-failed
      if [ "$probe_ok" = 1 ] && [ "$observed" = "$expected" ]; then
        recovery_link_lost=0
        recovery_probe_misses=0
        missed_round=0
        if [ "$phase" = OPEN ]; then
          desired=OPEN
          reason=probe-ok
          if [ "$probe_used" = "$probe_backup" ]; then reason=probe-backup; fi
        else
          gap=$((last_probe - last_verified))
          if [ "$consecutive" -eq 0 ] || [ "$gap" -lt 0 ] || [ "$gap" -gt "$stability_max_gap" ]; then
            stable_since=$last_probe
            consecutive=0
          fi
          consecutive=$((consecutive + 1))
          reason=settling
          if [ "$consecutive" -ge "$stability_samples" ] && [ $((last_probe - stable_since)) -ge "$stability_seconds" ]; then
            # Validate the boundary again after the last network probe, before exposing ordinary traffic.
            if ! rules_intact; then
              drift=1
              publish DRIFT "-" pf-changed
              /bin/sleep 2
              continue
            fi
            desired=OPEN
            reason=stable-open
            next_retry=0
            retry_delay=3
          fi
        fi
        last_verified=$last_probe
      elif [ "$probe_ok" = 1 ]; then
        recovery_link_lost=0
        recovery_probe_misses=0
        reset_stability
        reason=exit-mismatch
      else
        observed=-
        if [ "$recovery_link_lost" = 1 ] && [ "$phase" = LOCKED ]; then
          recovery_probe_misses=$((recovery_probe_misses + 1))
          if [ "$recovery_probe_misses" -ge 2 ]; then
            # A provider may report Connected after Wi-Fi is back even when its transport is stale.
            # Recycle the original service once for this local outage, with apps still sealed.
            load_phase SEALED || { drift=1; continue; }
            phase=SEALED
            recovery_link_lost=0
            recovery_probe_misses=0
            next_retry=$last_probe
            reset_stability
            /usr/sbin/scutil --nc stop "$vpn_service" >/dev/null 2>&1 &
            publish LOCKED "-" vpn-restarting
            /bin/sleep 1
            continue
          fi
        fi
        age=$((last_probe - last_verified))
        if [ "$phase" = OPEN ] && [ "$missed_round" = 0 ] && [ "$age" -ge 0 ] && [ "$age" -le 12 ]; then
          # One empty round is tolerated only on the same verified tunnel and visible route.
          missed_round=1
          publish OPEN "-" probe-retry
          /bin/sleep 1
          continue
        fi
        reset_stability
      fi
      if [ "$desired" != "$phase" ]; then
        if ! load_phase "$desired"; then
          drift=1
          publish DRIFT "-" pf-load
          /bin/sleep 2
          continue
        fi
        phase=$desired
      fi
      if [ "$phase" = OPEN ] && [ "$mode" = trial ] && [ "$trial_verified" = 0 ]; then
        : > "$directory/active/verified"
        trial_verified=1
      fi
      publish "$phase" "$observed" "$reason"
      if [ "$phase" = OPEN ] && [ "$mode" = live ]; then
        # The kernel still blocks direct traffic between health checks.
        /bin/sleep 5
      elif [ "$reason" = settling ]; then
        /bin/sleep "$stability_tick"
      else
        /bin/sleep 1
      fi
    done
    ;;
  *) exit 2;;
esac
