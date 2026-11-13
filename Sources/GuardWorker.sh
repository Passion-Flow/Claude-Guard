# Executed by an administrator-authorized /bin/sh on the target Mac.
set -eu
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
unset CDPATH ENV BASH_ENV
pf=/sbin/pfctl
anchor=com.apple/00000.org.claudeguard.runtime
directory=/var/run/org.claudeguard.runtime
boot_dir=/Library/PrivilegedHelperTools/org.claudeguard
filter_helper=$boot_dir/GuardDaemon
boot_plist=/Library/LaunchDaemons/org.claudeguard.guardian.plist
boot_label=org.claudeguard.guardian
launchctl=/bin/launchctl
chown_tool=/usr/sbin/chown
boot_mode=0
probe_primary=1.1.1.1
probe_backup=1.0.0.1
identity_lease_seconds=12
stability_seconds=15
stability_samples=6
stability_tick=3
stability_max_gap=8
policy_id=ipv4-tunnel-v8
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
peer_ifaces=
admin_source=
probe_failures=0
backoff=1
last_state=
last_observed=
last_reason=
evidence_context=
probe_file=
risk_key=
risk_region=
risk_evaluator=
risk_checked_at=0
risk_context=
risk_api_ip=
risk_host=proxycheck.io
observed_region=
risk_attempt_at=0
risk_max_age=3600
risk_renew_age=2700
risk_retry_seconds=60
approved_deadline=0
development_peer=
development_binding=
development_iface=
development_self=
maintenance_links=

maintenance_snapshot() {
  /sbin/ifconfig -a 2>/dev/null | /usr/bin/awk '
    /^[^[:space:]]/ {name=$1; sub(/:$/, "", name); if(name ~ /^en[0-9]+$/) print name}' | /usr/bin/sort -u
}

valid_ip() {
  # awk validates per line, so reject anything that could span lines first.
  case "$1" in ""|*[!0-9.]*) return 1;; esac
  printf '%s\n' "$1" | /usr/bin/awk -F. '
    NF != 4 { exit 1 }
    { for (i=1; i<=4; i++) if ($i !~ /^(0|[1-9][0-9]*)$/ || length($i)>3 || $i>255) exit 1 }'
}
valid_iface() {
  case "$1" in utun*) suffix=${1#utun};; *) return 1;; esac
  case "$suffix" in ""|*[!0-9]*) return 1;; esac
}
valid_development_peer() {
  valid_ip "$1" || return 1
  printf '%s\n' "$1" | /usr/bin/awk -F. '$1!=100 || $2<64 || $2>127 {exit 1}'
}

development_snapshot() {
  [ -n "$development_peer" ] || return 0
  development_route=$(/sbin/route -n get -inet "$development_peer" 2>/dev/null) || return 0
  development_link=$(printf '%s\n' "$development_route" | /usr/bin/awk '
    $1=="interface:" {count++; link=$2; if(NF!=2) bad=1}
    END {if(count!=1 || bad) exit 1; print link}') || return 0
  valid_iface "$development_link" && [ "$development_link" != "$iface" ] || return 0
  development_addresses=$(/sbin/ifconfig "$development_link" 2>/dev/null | /usr/bin/awk '$1=="inet" {print $2}') || return 0
  development_source=
  for address in $development_addresses; do
    if valid_development_peer "$address"; then
      [ -z "$development_source" ] || return 0
      development_source=$address
    fi
  done
  [ -n "$development_source" ] && [ "$development_source" != "$development_peer" ] || return 0
  printf '%s|%s' "$development_link" "$development_source"
}
valid_port() {
  case "$1" in ""|*[!0-9]*) return 1;; esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
valid_session() {
  printf '%s\n' "$1" | /usr/bin/awk -F- '
    NF!=5 || length($1)!=8 || length($2)!=4 || length($3)!=4 ||
      length($4)!=4 || length($5)!=12 || $0 !~ /^[0-9A-Fa-f-]+$/ { bad=1 }
    END { exit (bad || NR!=1) }'
}
shadowrocket_services() {
  /usr/sbin/scutil --nc list | /usr/bin/awk '
    $1=="*" && $4=="VPN" && $5=="(com.liguangming.Shadowrocket)" &&
      $NF=="[VPN:com.liguangming.Shadowrocket]" && length($3)==36 &&
      $3 ~ /^[0-9A-Fa-f-]+$/ { print $3 }'
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
  if [ -n "$admin_source" ]; then
    # Optional remote console. Replies follow this state and nothing else is opened.
    printf 'pass in quick inet proto tcp from %s to any port = 22 flags S/SA keep state (if-bound) label "CG_ADMIN"\n' "$admin_source"
  fi
  for link in $peer_ifaces; do
    printf 'pass out quick on %s inet proto %s from any to %s port = %s %s keep state (if-bound) label "CG_PEER_OUT"\n' "$link" "$protocol" "$peer" "$port" "$extra"
  done
  # Bind network maintenance to physical Ethernet/Wi-Fi interfaces. DHCP replies
  # remain narrowly port-scoped; known servers also receive unicast renewals.
  for link in $maintenance_links; do
    printf 'pass out quick on %s inet proto udp from any port = 68 to 255.255.255.255 port = 67 no state label "CG_DHCP_OUT"\n' "$link"
    printf 'pass in quick on %s inet proto udp from any port = 67 to any port = 68 no state label "CG_DHCP_IN"\n' "$link"
    dhcp_server=$(/usr/sbin/ipconfig getoption "$link" server_identifier 2>/dev/null || true)
    if valid_ip "$dhcp_server"; then
      printf 'pass out quick on %s inet proto udp from any port = 68 to %s port = 67 no state label "CG_DHCP_RENEW"\n' "$link" "$dhcp_server"
    fi
  done
  if [ "$rule_phase" = OPEN ]; then
    if [ -n "$development_iface" ] && [ -n "$development_self" ] && [ -n "$development_peer" ]; then
      printf 'pass out quick on %s inet proto tcp from %s to %s port = 22 flags any no state label "CG_DEV_OUT"\n' "$development_iface" "$development_self" "$development_peer"
      printf 'pass in quick on %s inet proto tcp from %s port = 22 to %s flags any no state label "CG_DEV_IN"\n' "$development_iface" "$development_peer" "$development_self"
    fi
    printf 'block drop quick on %s inet from any to { 224.0.0.0/4, 255.255.255.255 } label "CG_MCAST"\n' "$iface"
    printf 'pass quick on %s inet all no state label "CG_TUNNEL"\n' "$iface"
  elif [ "$rule_phase" = LOCKED ]; then
    for probe in "$probe_primary" "$probe_backup"; do
      printf 'pass out quick on %s inet proto tcp from any to %s port = 443 user root flags any no state label "CG_PROBE_OUT"\n' "$iface" "$probe"
      printf 'pass in quick on %s inet proto tcp from %s port = 443 to any flags any no state label "CG_PROBE_IN"\n' "$iface" "$probe"
    done
    if [ -n "$risk_api_ip" ]; then
      printf 'pass out quick on %s inet proto tcp from any to %s port = 443 user root flags any no state label "CG_RISK_OUT"\n' "$iface" "$risk_api_ip"
      printf 'pass in quick on %s inet proto tcp from %s port = 443 to any flags any no state label "CG_RISK_IN"\n' "$iface" "$risk_api_ip"
    fi
  fi
  printf 'block drop quick all label "CG_BLOCK"\n'
}

preflight() {
  # Do not reload the system's root rules. Refuse a layout we have not accounted for.
  main=$("$pf" -sr 2>/dev/null) || return 1
  printf '%s\n' "$main" | /usr/bin/awk '
    /^[[:space:]]*$/ { next }
    # Scrub rules normalize packets and never admit traffic.
    /^scrub-anchor "com\.apple\/\*" all( fragment reassemble)?$/ { next }
    /^scrub-anchor "cisco\.anyconnect\.vpn" all( fragment reassemble)?$/ { next }
    $0=="anchor \"cisco.anyconnect.vpn\" all" { next }
    $0=="anchor \"com.apple/*\" all" { count++; next }
    { bad=1 }
    END { exit (bad || count!=1) }' || return 1
  if printf '%s\n' "$main" | /usr/bin/grep -q 'cisco.anyconnect.vpn'; then
    cisco=$("$pf" -a cisco.anyconnect.vpn -sr 2>/dev/null) || return 1
    [ -z "$cisco" ] || return 1
  fi
  siblings=$("$pf" -a com.apple -s Anchors 2>/dev/null) || return 1
  earlier=$(printf '%s\n' "$siblings" | /usr/bin/awk -v ours="$anchor" '
    NF {
      if (NF!=1 || $1 !~ /^[A-Za-z0-9_.\/-]+$/) { bad=1; next }
      name=$1
      if (name !~ /\//) name="com.apple/"name
      if (name != ours && name < ours) print name
    }
    END { exit bad }') || return 1
  for previous_anchor in $earlier; do
    previous_rules=$("$pf" -a "$previous_anchor" -sr 2>/dev/null) || return 1
    [ -z "$previous_rules" ] || return 1
  done
  interfaces=$("$pf" -v -s Interfaces 2>/dev/null) || return 1
  # On supported layouts the verbose output marks skipped interfaces with "(skip)".
  printf '%s\n' "$interfaces" | /usr/bin/awk '/skip/ && $1!="lo0" { bad=1 } END { exit bad }'
}

publish() {
  last_state=$1
  last_observed=$2
  last_reason=$3
  now=$(/bin/date +%s)
  tmp=$(/usr/bin/mktemp "$directory/status.XXXXXX")
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$session" "$1" "$now" "$iface" "$expected" "$2" "$3" "$expires" "$mode" "$trial_verified" "$vpn_service" "$endpoint_key" "$policy_id" "$risk_checked_at" > "$tmp"
  /bin/chmod 0600 "$tmp"
  /bin/mv -f "$tmp" "$status_file"
  key="$session|$1|$iface|$2|$3|$mode|$trial_verified"
  if [ "$last_journal_key" != "$key" ]; then
    journal=$(/usr/bin/mktemp "$directory/events.XXXXXX")
    if [ -f "$directory/events" ]; then /usr/bin/tail -n 249 "$directory/events" > "$journal"; fi
    /bin/cat "$status_file" >> "$journal"
    /bin/chmod 0600 "$journal"
    /bin/mv -f "$journal" "$directory/events"
    last_journal_key=$key
  fi
}

anchor_rules() {
  # PF can discard an anchor once it is empty, and querying it then fails.
  if anchor_text=$("$pf" -a "$anchor" -sr 2>/dev/null); then
    printf '%s\n' "$anchor_text"
    return 0
  fi
  anchor_listing=$("$pf" -a com.apple -s Anchors 2>/dev/null) || return 1
  case "$anchor_listing" in *"${anchor##*/}"*) return 1;; esac
}

clear_owned() {
  if [ "$owned" = 1 ]; then
    "$filter_helper" --filter-clear "$session" >/dev/null 2>&1 || return 1
    remaining=$(anchor_rules) || return 1
    [ -z "$remaining" ] || return 1
  fi
  if [ -n "$token" ]; then
    # A forced PF shutdown invalidates the token. The rules are already gone.
    "$pf" -X "$token" >/dev/null 2>&1 || true
  fi
}

remove_marker() {
  if [ -f "$1" ]; then /bin/unlink "$1"; fi
}

remove_active() {
  for field in pid token session verified admin last_rules next_rules; do
    remove_marker "$directory/active/$field"
  done
  /bin/rmdir "$directory/active"
  remove_marker "$directory/restore-$session"
  remove_marker "$directory/continue-$session"
}

remove_boot_files() {
  if [ -f "$boot_plist" ]; then /bin/unlink "$boot_plist"; fi
  remove_marker "$boot_dir/guardian.sh"
  remove_marker "$boot_dir/boot.conf"
  # Temporary files from an interrupted install.
  /bin/rm -f -- "$boot_dir"/guardian.?????? "$boot_dir"/conf.?????? "$boot_dir"/plist.??????
  if [ -d "$boot_dir" ]; then /bin/rmdir "$boot_dir" || true; fi
}

unload_boot_job() {
  "$launchctl" bootout "system/$boot_label" >/dev/null 2>&1 || true
}

cleanup() {
  trap - EXIT HUP INT TERM
  discard_probe
  if [ "$owned" = 1 ] && [ "$restore_requested" = 0 ]; then
    # Exit traps run on ordinary errors too. Leave the block in force on faults.
    enforce_seal || true
    publish ERROR "-" worker-stopped || true
    return
  fi
  if clear_owned; then
    remove_active || true
    publish "$end_state" "-" "$finish_reason" || true
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
  generated=$(build_rules "$1") || return 1
  canonical=$(printf '%s\n' "$generated" | "$pf" -n -v -a "$anchor" -f - 2>/dev/null) || return 1
  [ -n "$canonical" ] || return 1
  if [ -d "$directory/active" ]; then
    rule_record=$(/usr/bin/mktemp "$directory/active/rules.XXXXXX") || return 1
    printf '%s' "$canonical" > "$rule_record" && /bin/mv -f "$rule_record" "$directory/active/next_rules" || return 1
  fi
  printf '%s\n' "$generated" | "$filter_helper" --filter-load "$session" "$1" >/dev/null 2>&1 || return 1
  if ! readback=$("$pf" -a "$anchor" -sr 2>/dev/null) || [ "$readback" != "$canonical" ]; then
    if [ "$1" != SEALED ]; then load_phase SEALED || true; fi
    return 1
  fi
  loaded=$readback
  if [ -d "$directory/active" ]; then
    /bin/mv -f "$directory/active/next_rules" "$directory/active/last_rules" || return 1
  fi
}

rules_intact() {
  current=$("$pf" -a "$anchor" -sr 2>/dev/null) || return 1
  info=$("$pf" -s info 2>/dev/null) || return 1
  preflight && [ "$current" = "$loaded" ] &&
    printf '%s\n' "$info" | /usr/bin/grep -q '^Status: Enabled'
}

acquire_pf() {
  previous_token=$token
  enabled=$("$pf" -E 2>&1) || return 1
  new_token=$(printf '%s\n' "$enabled" | /usr/bin/awk -F: '/Token[[:space:]]*:/ {gsub(/[[:space:]]/,"",$2); print $2; exit}')
  case "$new_token" in ""|*[!0-9]*) return 1;; esac
  token=$new_token
  printf '%s\n' "$token" > "$directory/active/token"
  if [ -n "$previous_token" ] && [ "$previous_token" != "$token" ]; then
    "$pf" -X "$previous_token" >/dev/null 2>&1 || true
  fi
}

enforce_seal() {
  load_phase SEALED || return 1
  phase=SEALED
  pf_info=$("$pf" -s info 2>/dev/null) || return 1
  case "$pf_info" in *"Status: Enabled"*) [ -n "$token" ] || acquire_pf || return 1;; *) acquire_pf || return 1;; esac
  # Connections admitted while the filter was down must not outlive it.
  "$pf" -F states >/dev/null 2>&1
}

seal_holds() {
  [ "$phase" = SEALED ] || return 1
  current=$("$pf" -a "$anchor" -sr 2>/dev/null) || return 1
  info=$("$pf" -s info 2>/dev/null) || return 1
  [ "$current" = "$loaded" ] && printf '%s\n' "$info" | /usr/bin/grep -q '^Status: Enabled'
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

underlay_ifaces() {
  printf '%s\n' "${1#v4:}" | /usr/bin/awk -F= '$1 ~ /^[a-z]+[0-9]+$/ { print $1 }' |
    /usr/bin/sort -u | /usr/bin/tr '\n' ' ' | /usr/bin/sed 's/ $//'
}

reset_stability() {
  stable_since=0
  consecutive=0
  missed_round=0
  last_verified=0
  evidence_context=
  risk_checked_at=0
  risk_context=
}

identity_fresh() {
  [ "$last_verified" -gt 0 ] && [ "$1" -ge "$last_verified" ] &&
    [ $(($1 - last_verified)) -le "$identity_lease_seconds" ] &&
    [ "$evidence_context" = "$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path" ]
}

guard_sleep() {
  # The health check can wait. A damaged filter cannot.
  guard_left=$1
  while [ "$guard_left" -gt 0 ]; do
    /bin/sleep 1
    guard_left=$((guard_left - 1))
    rules_intact || return 0
    sleep_now=$(/bin/date +%s)
    if [ "$phase" = OPEN ] && { ! identity_fresh "$sleep_now" || ! risk_fresh "$sleep_now"; }; then
      load_phase LOCKED || { drift=1; return 0; }
      phase=LOCKED
      reset_stability
      publish LOCKED "-" evidence-expired
      return 0
    fi
    publish "$last_state" "$last_observed" "$last_reason"
  done
}

next_backoff() {
  probe_failures=$((probe_failures + 1))
  case "$probe_failures" in
    1) backoff=1;;
    2) backoff=2;;
    3) backoff=4;;
    # Stay under the ten-second gap that forces a fresh validation while open.
    *) backoff=6;;
  esac
}

route_via_tunnel() {
  route_info=$(/sbin/route -n get -inet "$1" 2>/dev/null) || return 2
  route_interface=$(printf '%s\n' "$route_info" | /usr/bin/awk '
    $1=="interface:" { count++; if (NF!=2) bad=1; interface=$2 }
    END { if (bad || count!=1) exit 1; print interface }') || return 2
  [ "$route_interface" = "$iface" ]
}

probe_route_reason() {
  for route_probe in "$probe_primary" "$probe_backup"; do
    if route_via_tunnel "$route_probe"; then continue
    else route_status=$?
    fi
    if [ "$route_status" -eq 2 ]; then printf '%s\n' route-unknown
    else printf '%s\n' route-mismatch
    fi
    return
  done
}

discard_probe() {
  # Retain only a bounded HTTP category for transport retry decisions. Never
  # retain a destination, response body or credential in this diagnostic.
  case "${http_status:-}" in
    [0-9][0-9][0-9]) printf '%s\n' "$http_status" > "$directory/transport-status";;
  esac
  if [ -n "$probe_file" ]; then
    /bin/rm -f -- "$probe_file" "$probe_file.clean"
    probe_file=
  fi
}

tunnel_response() {
    request_timeout=$1
    shift
    http_status=
    probe_file=$(/usr/bin/mktemp "$directory/probe.XXXXXX") || return 1
    if ! http_status=$(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/var/empty \
      /usr/bin/curl -q -4 --noproxy '*' --interface "if!$iface" --proto '=https' --tlsv1.2 \
        --connect-timeout "$request_timeout" --max-time "$request_timeout" --max-filesize 16384 --output "$probe_file" --write-out '%{http_code}' \
        -fsS "$@" 2>/dev/null); then
      discard_probe
      return 1
    fi
    if [ "$http_status" != 200 ]; then discard_probe; return 1; fi
    probe_size=$(/usr/bin/stat -f '%z' "$probe_file") || { discard_probe; return 1; }
    if [ "$probe_size" -gt 16384 ]; then discard_probe; return 1; fi
    # Shell strings cannot preserve NUL bytes. Reject them before reading the body.
    if ! /usr/bin/tr -d '\000' < "$probe_file" > "$probe_file.clean" ||
       ! /usr/bin/cmp -s "$probe_file" "$probe_file.clean"; then
      discard_probe
      return 1
    fi
    /bin/cat "$probe_file" || { discard_probe; return 1; }
    discard_probe
}

sample_exit() {
  # An actual different address is evidence. An unavailable response is not.
  probe_used=
  for probe in "$probe_primary" "$probe_backup"; do
    result=$(tunnel_response 2 "https://$probe/cdn-cgi/trace") || continue
    [ "${#result}" -le 4096 ] || continue
    observed=$(printf '%s\n' "$result" | /usr/bin/awk '
      /^ip=/ { count++; address=substr($0, 4) }
      END { if (count!=1) exit 1; print address }') || continue
    observed_region=$(printf '%s\n' "$result" | /usr/bin/awk '
      /^loc=/ { count++; region=substr($0, 5) }
      END { if (count!=1 || region !~ /^[A-Z][A-Z]$/) exit 1; print region }') || observed_region=
    if valid_ip "$observed"; then
      probe_used=$probe
      return 0
    fi
  done
  observed=-
  return 1
}

valid_risk_key() {
  case "$1" in ''|*[!a-zA-Z0-9_-]*) return 1;; esac
  [ "${#1}" -ge 16 ] && [ "${#1}" -le 128 ]
}

risk_fresh() {
  [ "$risk_checked_at" -gt 0 ] && [ "$1" -ge "$risk_checked_at" ] &&
    [ $(($1 - risk_checked_at)) -lt "$risk_max_age" ] &&
    [ "$risk_context" = "$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path|$risk_region" ]
}

json_field() {
  printf '%s' "$1" | /usr/bin/plutil -extract "$2" raw -expect "$3" -o - - 2>/dev/null
}

public_risk_address() {
  valid_ip "$1" || return 1
  printf '%s\n' "$1" | /usr/bin/awk -F. '
    $1==0 || $1==10 || $1==127 || $1>=224 ||
    ($1==100 && $2>=64 && $2<=127) || ($1==169 && $2==254) ||
    ($1==172 && $2>=16 && $2<=31) || ($1==192 && ($2==0 || $2==168)) ||
    ($1==198 && ($2==18 || $2==19 || ($2==51 && $3==100))) ||
    ($1==203 && $2==0 && $3==113) { exit 1 }'
}

resolve_risk_api() {
  dns=$(tunnel_response 4 --resolve "cloudflare-dns.com:443:$probe_primary" \
    -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$risk_host&type=A") || return 1
  [ "$(json_field "$dns" Status integer)" = 0 ] &&
    [ "$(json_field "$dns" TC bool)" = false ] &&
    [ "$(json_field "$dns" Question.0.type integer)" = 1 ] || return 1
  question_name=$(json_field "$dns" Question.0.name string) || return 1
  case "$question_name" in "$risk_host"|"$risk_host.") :;; *) return 1;; esac
  for answer in 0 1 2 3 4 5 6 7; do
    type=$(json_field "$dns" "Answer.$answer.type" integer) || return 1
    [ "$type" = 1 ] || continue
    address=$(json_field "$dns" "Answer.$answer.data" string) || return 1
    if public_risk_address "$address" && [ "$address" != "$peer" ]; then
      printf '%s' "$address"
      return
    fi
  done
  return 1
}

review_exit_risk() {
  risk_admission_at=
  risk_issue=risk-unavailable
  [ -x "$risk_evaluator" ] || return 2
  if [ -n "$risk_key" ]; then
    valid_risk_key "$risk_key" || return 2
    risk_host=www.ipqualityscore.com
  else
    risk_host=proxycheck.io
    case "$observed_region" in [A-Z][A-Z]) :;; *) return 2;; esac
    [ "$observed_region" = "$risk_region" ] || return 1
    # Anonymous service quotas are shared by the exit. Reuse only a recent,
    # exact-address response, and persist attempt spacing across worker restarts.
    risk_now=$(/bin/date +%s)
    if [ -f "$directory/risk-cache" ]; then
      cached_header=$(/usr/bin/head -n 1 "$directory/risk-cache")
      IFS='|' read -r cached_at cached_exit cached_region <<EOF
$cached_header
EOF
      case "$cached_at" in ''|*[!0-9]*) cached_at=0;; esac
      if [ "${#cached_at}" -le 12 ] && [ "$risk_now" -ge "$cached_at" ] &&
         [ $((risk_now - cached_at)) -lt 3600 ] && [ "$cached_exit" = "$observed" ] &&
         [ "$cached_region" = "$risk_region" ]; then
        if { printf '%s|%s|%s\n' "$risk_region" "$observed" "$observed_region"; /usr/bin/tail -n +2 "$directory/risk-cache"; } |
            "$risk_evaluator" --validate-keyless-risk; then risk_admission_at=$cached_at; return 0
        else cached_result=$?; risk_issue=risk-invalid-response; return "$cached_result"; fi
      fi
    fi
    if [ -f "$directory/risk-last-attempt" ]; then
      previous_attempt=$(/bin/cat "$directory/risk-last-attempt")
      case "$previous_attempt" in ''|*[!0-9]*) return 2;; esac
      [ "${#previous_attempt}" -le 12 ] && [ "$risk_now" -ge "$previous_attempt" ] &&
        [ $((risk_now - previous_attempt)) -ge 3600 ] || { risk_issue=risk-rate-limited; return 2; }
    fi
  fi
  risk_address=$(resolve_risk_api) || { risk_issue=risk-dns-unavailable; return 2; }
  if [ "$phase" = LOCKED ]; then
    risk_api_ip=$risk_address
    if ! load_phase LOCKED; then risk_api_ip=; return 3; fi
  fi
  [ -n "$risk_key" ] || printf '%s\n' "$risk_now" > "$directory/risk-last-attempt"
  response=
  # Credentials and the queried exit are supplied through stdin, never argv.
  if [ -n "$risk_key" ]; then
    request=$(printf 'url = "https://%s/api/json/ip?ip=%s&strictness=1&allow_public_access_points=false&lighter_penalties=false"\nheader = "IPQS-KEY: %s"\n' "$risk_host" "$observed" "$risk_key")
  else
    request=$(printf 'url = "https://%s/v3/%s?ver=24-June-2026&tag=0"\n' "$risk_host" "$observed")
  fi
  # A transient connection failure must not make the first anonymous attempt
  # the sole chance for an entire hour. At most three connections share this
  # one persisted hourly budget. Retry only without an HTTP response, only
  # while ordinary traffic is already LOCKED. An HTTP error (including quota
  # responses), malformed body or negative verdict never triggers this retry.
  for risk_connection in 1 2 3; do
    /bin/rm -f "$directory/transport-status"
    if [ "$phase" = LOCKED ]; then publish LOCKED "-" risk-review; fi
    if body=$(printf '%s\n' "$request" | tunnel_response 4 --resolve "$risk_host:443:$risk_address" --config -); then
      response=$body
      break
    fi
    risk_http=$(/bin/cat "$directory/transport-status" 2>/dev/null || printf '000')
    [ "$phase" = LOCKED ] && [ "$risk_http" = 000 ] && [ "$risk_connection" -lt 3 ] || break
    /bin/sleep 1
  done
  if [ "$phase" = LOCKED ]; then
    risk_api_ip=
    load_phase LOCKED || return 3
  fi
  [ -n "$response" ] || { risk_issue=risk-provider-unavailable; return 2; }
  if [ -n "$risk_key" ]; then
    if printf '%s' "$response" | "$risk_evaluator" --validate-risk "$risk_region"; then return 0; else risk_result=$?; fi
  else
    if printf '%s|%s|%s\n%s' "$risk_region" "$observed" "$observed_region" "$response" | "$risk_evaluator" --validate-keyless-risk; then
      { printf '%s|%s|%s\n' "$risk_now" "$observed" "$risk_region"; printf '%s' "$response"; } > "$directory/risk-cache.tmp"
      /bin/mv -f "$directory/risk-cache.tmp" "$directory/risk-cache"
      risk_admission_at=$risk_now
      return 0
    else risk_result=$?; fi
  fi
  case "$risk_result" in 1) return 1;; *) risk_issue=risk-invalid-response; return 2;; esac
}

action=${1-}
case "$action" in
  parse-vpn) parse_vpn_status; exit;;
  rules)
    # Nonprivileged preview and syntax tests. No /dev/pf writes.
    iface=$2; peer=$3; protocol=$4; port=$5; rule_phase=$6
    peer_ifaces=${7:-en0}
    maintenance_links=$peer_ifaces
    admin_source=${8:-}
    valid_iface "$iface" && valid_ip "$peer" && valid_port "$port" || exit 2
    if [ -n "$admin_source" ]; then valid_ip "$admin_source" || exit 2; fi
    case "$protocol" in tcp|udp) :;; *) exit 2;; esac
    case "$rule_phase" in OPEN|LOCKED|SEALED) :;; *) exit 2;; esac
    build_rules "$rule_phase"
    exit
    ;;
  worker-input)
    [ "$#" -eq 2 ] && valid_session "$2" || exit 2
    input_session=$2
    IFS= read -r risk_key || exit 2
    IFS= read -r route_input || exit 2
    IFS= read -r risk_evaluator || exit 2
    [ "${#route_input}" -le 1024 ] || exit 2
    printf '%s\n' "$route_input" | /usr/bin/awk -F'|' 'NR!=1 || NF!=12 {exit 1}' || exit 2
    IFS='|' read -r input_mode input_iface input_peer input_transport input_port input_exit risk_region input_service input_boot approved_deadline input_admin development_peer <<EOF
$route_input
EOF
    case "$risk_region" in [A-Z][A-Z]) :;; *) exit 2;; esac
    case "$approved_deadline" in ''|*[!0-9]*) exit 2;; esac
    [ "${#approved_deadline}" -le 12 ] || exit 2
    [ "$risk_evaluator" = /Library/PrivilegedHelperTools/org.claudeguard/GuardDaemon ] || exit 2
    [ -z "$development_peer" ] || valid_development_peer "$development_peer" || exit 2
    set -- worker "$input_session" "$input_mode" "$input_iface" "$input_peer" "$input_transport" "$input_port" "$input_exit" "$input_service" "$input_boot" "$input_admin"
    action=worker
    ;;
esac

[ "$(/usr/bin/id -u)" -eq 0 ] || exit 77
if [ ! -d "$directory" ]; then
  /bin/mkdir -m 0700 "$directory"
fi
[ ! -L "$directory" ] && [ "$(/usr/bin/stat -f '%u' "$directory")" = 0 ] || exit 78
/bin/chmod 0700 "$directory"
[ "$(/usr/bin/stat -f '%Lp' "$directory")" = 700 ] || exit 78
status_file=$directory/status

case "$action" in
  persist)
    # Install a boot job for the route that is live and verified right now.
    [ "$#" -eq 2 ] && [ -n "$2" ] || exit 2
    worker_text=$2
    [ -d "$directory/active" ] || exit 82
    worker_pid=$(/bin/cat "$directory/active/pid" 2>/dev/null || true)
    case "$worker_pid" in ""|*[!0-9]*) exit 82;; esac
    /bin/kill -0 "$worker_pid" 2>/dev/null || exit 82
    fields=$(/usr/bin/awk -F'|' '$2=="OPEN" && $9=="live" && $11!="" { print $4, $5, $11, $12 }' "$status_file")
    [ -n "$fields" ] || exit 82
    set -- $fields
    [ "$#" -eq 4 ] || exit 82
    iface=$1; expected=$2; vpn_service=$3; endpoint_key=$4
    peer=${endpoint_key%%:*}
    endpoint_rest=${endpoint_key#*:}
    port=${endpoint_rest%/*}
    protocol=${endpoint_rest#*/}
    valid_iface "$iface" && valid_ip "$peer" && valid_ip "$expected" && valid_port "$port" || exit 82
    case "$protocol" in tcp|udp) :;; *) exit 82;; esac
    case "$vpn_service" in ""|*[!0-9A-Fa-f-]*) exit 82;; esac
    /bin/mkdir -p -m 0755 "$boot_dir"
    [ ! -L "$boot_dir" ] || exit 78
    "$chown_tool" root:wheel "$boot_dir"
    /bin/chmod 0755 "$boot_dir"
    script_tmp=$(/usr/bin/mktemp "$boot_dir/guardian.XXXXXX")
    printf '%s' "$worker_text" > "$script_tmp"
    /bin/sh -n "$script_tmp"
    "$chown_tool" root:wheel "$script_tmp"
    /bin/chmod 0644 "$script_tmp"
    conf_tmp=$(/usr/bin/mktemp "$boot_dir/conf.XXXXXX")
    admin_source=$(/bin/cat "$directory/active/admin" 2>/dev/null || true)
    [ -n "$admin_source" ] || admin_source=-
    [ "$admin_source" = - ] || valid_ip "$admin_source" || exit 82
    printf '%s %s %s %s %s %s %s\n' "$iface" "$peer" "$protocol" "$port" "$expected" "$vpn_service" "$admin_source" > "$conf_tmp"
    "$chown_tool" root:wheel "$conf_tmp"
    /bin/chmod 0600 "$conf_tmp"
    plist_tmp=$(/usr/bin/mktemp "$boot_dir/plist.XXXXXX")
    /bin/cat > "$plist_tmp" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$boot_label</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>$boot_dir/guardian.sh</string><string>boot</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
</dict></plist>
PLIST
    /usr/bin/plutil -lint "$plist_tmp" >/dev/null
    "$chown_tool" root:wheel "$plist_tmp"
    /bin/chmod 0644 "$plist_tmp"
    /bin/mv -f "$script_tmp" "$boot_dir/guardian.sh"
    /bin/mv -f "$conf_tmp" "$boot_dir/boot.conf"
    /bin/mv -f "$plist_tmp" "$boot_plist"
    exit
    ;;
  boot)
    # Started by launchd. Block first, then wait for the saved route.
    [ -f "$boot_dir/boot.conf" ] || exit 0
    read -r iface peer protocol port expected approved_service admin_source < "$boot_dir/boot.conf"
    if [ -d "$directory/active" ]; then
      worker_pid=$(/bin/cat "$directory/active/pid" 2>/dev/null || true)
      case "$worker_pid" in ""|*[!0-9]*) worker_pid=0;; esac
      if [ "$worker_pid" -gt 1 ]; then
        command=$(/bin/ps -ww -p "$worker_pid" -o command= 2>/dev/null || true)
        case "$command" in *" claude-guard-worker worker "*) exit 0;; esac
      fi
      session=$(/bin/cat "$directory/active/session" 2>/dev/null || true)
      remove_active
    fi
    session=$(/usr/bin/uuidgen | /usr/bin/tr 'A-F' 'a-f')
    exec /bin/sh -c "$(/bin/cat "$boot_dir/guardian.sh")" claude-guard-worker worker \
      "$session" live "$iface" "$peer" "$protocol" "$port" "$expected" "$approved_service" boot "$admin_source"
    ;;
  continue)
    [ -f "$directory/active/verified" ] || exit 82
    session=$(/bin/cat "$directory/active/session")
    valid_session "$session" || exit 82
    /usr/bin/awk -F'|' -v id="$session" '
      $1==id && $9=="trial" && $2!="DRIFT" && $2!="ERROR" { ok=1 }
      END { exit !ok }' "$status_file" || exit 82
    : > "$directory/continue-$session"
    exit
    ;;
  stop)
    # Remove the boot job first so a failed restore cannot re-arm after restart.
    remove_boot_files
    [ -d "$directory/active" ] || { unload_boot_job; exit 0; }
    worker_pid=$(/bin/cat "$directory/active/pid" 2>/dev/null || true)
    session=$(/bin/cat "$directory/active/session" 2>/dev/null || true)
    token=$(/bin/cat "$directory/active/token" 2>/dev/null || true)
    case "$worker_pid" in ""|*[!0-9]*) worker_pid=0;; esac
    case "$token" in *[!0-9]*) exit 79;; esac
    if [ "$worker_pid" -gt 1 ] && valid_session "$session"; then
      command=$(/bin/ps -ww -p "$worker_pid" -o uid= -o command= 2>/dev/null || true)
      command=$(printf '%s' "$command" | /usr/bin/sed 's/^[[:space:]]*//')
      case "$command" in
        "0 "*" claude-guard-worker worker-input $session"|"0 "*" claude-guard-worker worker $session "*)
          : > "$directory/restore-$session"
          /bin/kill -TERM "$worker_pid" 2>/dev/null || true
          # The trap runs only after the current probe or sleep finishes.
          for tick in 1 2 3 4 5 6 7 8 9 10; do
            [ -d "$directory/active" ] || { unload_boot_job; exit 0; }
            /bin/sleep 1
          done
          if /bin/kill -0 "$worker_pid" 2>/dev/null; then exit 80; fi
          ;;
      esac
    fi
    loaded=$(anchor_rules) || exit 81
    case "$loaded" in *CG_BLOCK*) owned=1;; "") :;; *) exit 81;; esac
    clear_owned
    remove_active
    mode=manual; expires=0; iface=-; expected=-
    publish IDLE "-" stopped
    unload_boot_job
    exit
    ;;
  worker)
    session=$2; mode=$3; iface=$4; peer=$5; protocol=$6; port=$7; expected=$8
    shift 8
    approved_service=
    if [ "$#" -gt 0 ]; then approved_service=$1; fi
    if [ "$#" -gt 1 ] && [ "$2" = boot ]; then boot_mode=1; fi
    if [ "$#" -gt 2 ] && [ "$3" != - ]; then admin_source=$3; fi
    endpoint_key="$peer:$port/$protocol"
    valid_session "$session" && valid_iface "$iface" && valid_ip "$peer" && valid_ip "$expected" && valid_port "$port" || exit 2
    case "$protocol" in tcp|udp) :;; *) exit 2;; esac
    case "$mode" in trial|live|sealed) :;; *) exit 2;; esac
    [ "$peer" != "$probe_primary" ] && [ "$peer" != "$probe_backup" ] || exit 2
    if [ -n "$admin_source" ]; then valid_ip "$admin_source" || exit 2; fi
    adopted=0
    if ! /bin/mkdir -m 0700 "$directory/active" 2>/dev/null; then
      previous_pid=$(/bin/cat "$directory/active/pid" 2>/dev/null || true)
      case "$previous_pid" in ''|*[!0-9]*) exit 83;; esac
      [ "$previous_pid" -gt 1 ] && ! /bin/kill -0 "$previous_pid" 2>/dev/null || exit 83
      previous_rules=$(/bin/cat "$directory/active/last_rules" 2>/dev/null || true)
      pending_rules=$(/bin/cat "$directory/active/next_rules" 2>/dev/null || true)
      existing_rules=$(anchor_rules) || exit 85
      if [ -n "$existing_rules" ] && [ "$existing_rules" != "$previous_rules" ] && [ "$existing_rules" != "$pending_rules" ]; then
        printf '%s' "$existing_rules" | "$filter_helper" --filter-adopt "$session" >/dev/null 2>&1 || exit 85
      fi
      token=$(/bin/cat "$directory/active/token" 2>/dev/null || true)
      case "$token" in *[!0-9]*) exit 79;; esac
      loaded=$existing_rules
      owned=1
      adopted=1
      remove_marker "$directory/active/verified"
    fi
    printf '%s\n' "$$" > "$directory/active/pid"
    printf '%s\n' "$session" > "$directory/active/session"
    if [ -n "$admin_source" ]; then printf '%s\n' "$admin_source" > "$directory/active/admin"; fi
    expires=0
    if [ "$mode" = trial ]; then
      if [ "$approved_deadline" -gt 0 ]; then expires=$approved_deadline
      else expires=$(($(/bin/date +%s) + 60))
      fi
    fi
    trap cleanup EXIT
    trap handle_signal HUP INT TERM
    publish VERIFYING "-" preflight
    maintenance_links=$(maintenance_snapshot)
    peer_ifaces=$(underlay_ifaces "$(underlay_snapshot || true)")
    end_state=ERROR
    finish_reason=pf-layout
    if [ "$mode" = sealed ]; then
      owned=1
      enforce_seal || exit 88
    elif [ "$boot_mode" = 1 ]; then
      # Block first. macOS may still load its own PF layout, which the drift branch handles.
      case "$approved_service" in ""|*[!0-9A-Fa-f-]*) exit 86;; esac
      vpn_service=$approved_service
      finish_reason=pf-load
      owned=1
      enforce_seal || exit 88
    else
      preflight || exit 84
      if [ "$adopted" = 0 ]; then
        finish_reason=pf-load
        existing_rules=$(anchor_rules) || exit 85
        if [ -n "$existing_rules" ]; then
          # Native startup seals before the first shell creates its marker.
          # Accept only exact native ownership and actual readback, including
          # on a fresh runtime; a block label alone is not ownership evidence.
          printf '%s' "$existing_rules" | "$filter_helper" --filter-adopt "$session" >/dev/null 2>&1 || exit 85
          loaded=$existing_rules
          owned=1
          adopted=1
        fi
      fi
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
      if [ "$adopted" = 0 ] || ! "$pf" -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled' || [ -z "$token" ]; then
        acquire_pf || exit 89
      fi
      # Remove floating state inherited from before activation. This resets active connections once.
      "$pf" -F states >/dev/null 2>&1 || exit 91
    fi
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
      if [ "$mode" = sealed ]; then
        if ! seal_holds; then enforce_seal || true; fi
        publish LOCKED "-" manual-paused
        /bin/sleep 1
        continue
      fi
      if [ "$trial_verified" = 1 ] && [ "$mode" != live ] && [ -f "$directory/continue-$session" ]; then
        remove_marker "$directory/continue-$session"
        mode=live
        expires=0
      fi
      if [ "$mode" = trial ] && [ "$now" -ge "$expires" ]; then
        # An unconfirmed trial must not strand a Mac behind the filter.
        restore_requested=1
        end_state=IDLE
        finish_reason=trial-ended
        exit 0
      fi
      if [ "$drift" = 1 ] && seal_holds && preflight && "$pf" -F states >/dev/null 2>&1; then
        # The block held for a full cycle and the layout is clean. Connections admitted
        # while it was down are gone, so the tunnel can be validated again from sealed.
        drift=0
        reset_stability
        publish LOCKED "-" vpn-wait
        /bin/sleep 1
        continue
      fi
      if [ "$drift" = 1 ] || ! rules_intact; then
        # Keep re-establishing the block for as long as the drift lasts.
        if [ "$drift" = 0 ] || ! seal_holds; then
          enforce_seal || true
        fi
        drift=1
        reset_stability
        publish DRIFT "-" pf-changed
        /bin/sleep 2
        continue
      fi
      path_reason=
      next_maintenance=$(maintenance_snapshot)
      if [ "$next_maintenance" != "$maintenance_links" ]; then
        maintenance_links=$next_maintenance
        load_phase "$phase" || { drift=1; continue; }
      fi
      if ! path=$(underlay_snapshot); then
        path_reason=route-unknown
      elif [ "$path" = v4: ]; then
        path_reason=underlay-offline
        recovery_link_lost=1
      fi
      if [ "$path_reason" != route-unknown ]; then
        # Keep the node exception on the links that currently carry the default route.
        next_ifaces=$(underlay_ifaces "$path")
        if [ "$next_ifaces" != "$peer_ifaces" ]; then
          peer_ifaces=$next_ifaces
          load_phase "$phase" || { drift=1; continue; }
        fi
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
      next_development=$(development_snapshot)
      if [ "$next_development" != "$development_binding" ]; then
        development_binding=$next_development
        development_iface=${next_development%%|*}
        development_self=${next_development#*|}
        load_phase "$phase" || { drift=1; continue; }
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
      route_reason=$(probe_route_reason)
      if [ -z "$route_reason" ] && /sbin/ifconfig "$iface" >/dev/null 2>&1 && sample_exit; then
        probe_ok=1
      fi
      if [ -z "$route_reason" ]; then route_reason=$(probe_route_reason); fi
      last_probe=$(/bin/date +%s)
      if [ "$mode" = trial ] && [ "$last_probe" -ge "$expires" ]; then
        continue
      fi
      path_after=$(underlay_snapshot || true)
      connection_after=$(vpn_connection "$vpn_service" || true)
      if [ "$connection_after" != "Connected $iface" ] || [ "$path_after" != "$bound_path" ] ||
         [ -n "$route_reason" ]; then
        reset_stability
        if [ "$phase" != SEALED ]; then
          load_phase SEALED || { drift=1; continue; }
          phase=SEALED
        fi
        reason=vpn-wait
        case "$path_after" in
          '') reason=route-unknown;;
          v4:) reason=underlay-offline; recovery_link_lost=1; recovery_probe_misses=0;;
          *)
            if [ "$connection_after" = "Connected $iface" ]; then
              if [ "$path_after" != "$bound_path" ]; then reason=route-changed
              else reason=$route_reason
              fi
            fi
            ;;
        esac
        publish LOCKED "-" "$reason"
        /bin/sleep 1
        continue
      fi

      # A delayed probe or a clock jump cannot renew an expired authorization.
      if [ "$phase" = OPEN ] && ! identity_fresh "$last_probe"; then
        load_phase LOCKED || { drift=1; continue; }
        phase=LOCKED
        reset_stability
        publish LOCKED "-" evidence-expired
        continue
      fi
      desired=LOCKED
      reason=probe-failed
      if [ "$probe_ok" = 1 ] && [ "$observed" = "$expected" ]; then
        recovery_link_lost=0
        recovery_probe_misses=0
        missed_round=0
        probe_failures=0
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
        evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
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
        if [ "$phase" = OPEN ] && [ "$missed_round" = 0 ] && identity_fresh "$last_probe" && risk_fresh "$last_probe"; then
          # One empty round is tolerated only on the same verified tunnel and visible route.
          missed_round=1
          publish OPEN "-" probe-retry
          /bin/sleep 1
          continue
        fi
        reset_stability
      fi
      if [ "$desired" = OPEN ] && { ! risk_fresh "$last_probe" || [ $((last_probe - risk_checked_at)) -ge "$risk_renew_age" ]; }; then
        risk_reason=risk-unavailable
        if [ "$last_probe" -lt "$risk_attempt_at" ] || [ $((last_probe - risk_attempt_at)) -ge "$risk_retry_seconds" ]; then
          risk_attempt_at=$last_probe
          publish "$phase" "$observed" risk-review
          if review_exit_risk; then
            risk_checked_at=${risk_admission_at:-$(/bin/date +%s)}
            risk_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path|$risk_region"
            risk_attempt_at=0
          else
            risk_result=$?
            risk_checked_at=0
            case "$risk_result" in 1) risk_reason=risk-rejected;; 2) risk_reason=${risk_issue:-risk-unavailable};; *) drift=1; continue;; esac
          fi
        fi
        if ! risk_fresh "$(/bin/date +%s)"; then
          reset_stability
          desired=LOCKED
          reason=$risk_reason
        elif [ "$(underlay_snapshot || true)" != "$bound_path" ] ||
             [ "$(vpn_connection "$vpn_service" || true)" != "Connected $iface" ] ||
             [ -n "$(probe_route_reason)" ]; then
          reset_stability
          desired=SEALED
          reason=route-changed
        elif ! sample_exit; then
          reset_stability
          desired=LOCKED
          reason=probe-failed
        elif [ "$observed" != "$expected" ]; then
          reset_stability
          desired=LOCKED
          reason=exit-mismatch
        else
          last_verified=$(/bin/date +%s)
          evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
        fi
      fi
      # No request can carry an old decision across a route change, clock jump,
      # trial deadline or an expired admission lease, including the post-risk probe.
      if [ "$desired" = OPEN ]; then
        release_now=$(/bin/date +%s)
        if [ "$mode" = trial ] && [ "$release_now" -ge "$expires" ]; then continue; fi
        if ! identity_fresh "$release_now" || ! risk_fresh "$release_now"; then
          reset_stability
          desired=LOCKED
          reason=evidence-expired
        elif [ "$(underlay_snapshot || true)" != "$bound_path" ] ||
             [ "$(vpn_connection "$vpn_service" || true)" != "Connected $iface" ] ||
             [ -n "$(probe_route_reason)" ]; then
          reset_stability
          desired=SEALED
          reason=route-changed
        elif ! rules_intact; then drift=1; continue
        fi
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
        guard_sleep 5
      elif [ "$reason" = settling ]; then
        /bin/sleep "$stability_tick"
      elif [ "$reason" = probe-failed ]; then
        next_backoff
        guard_sleep "$backoff"
      else
        /bin/sleep 1
      fi
    done
    ;;
  *) exit 2;;
esac
