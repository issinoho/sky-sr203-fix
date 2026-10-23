#!/usr/bin/env bash
#
# sr203.sh — configure a Sky Hub SR203 from the command line, working around the
# firmware bug where the web UI shows "Session expired! Please press OK to refresh
# the page" on every security change.
#
# Root cause (diagnosed 2026-10-21): the router's *.sky POST handlers reply with a
# malformed HTTP/0.9 response (no status line, no headers). Modern browsers reject
# HTTP/0.9, so the GUI treats the POST as failed and blames the session. The change
# is actually accepted by the server. `curl --http0.9` accepts the reply, so the
# change applies cleanly. This script drives that path.
#
# Auth: HTTP Digest. Credentials come from a curl netrc file so the password never
# appears on the command line, in the process list, or in shell history.
#
# Usage:
#   ./sr203.sh list-sites                 # show currently blocked keywords
#   ./sr203.sh block-site <keyword>       # block URLs containing <keyword> (min 3 chars)
#   ./sr203.sh unblock-site <keyword>     # remove a blocked keyword
#   ./sr203.sh set-admin-password         # change the router admin password (prompts; updates netrc)
#   ./sr203.sh set-wifi-password          # change the Wi-Fi WPA2 passphrase (prompts; disconnects clients)
#   ./sr203.sh firewall-rule list                     # list inbound firewall rules (port forwards)
#   ./sr203.sh firewall-rule add <service> <lan-ip>   # add an inbound ALLOW rule for a defined Service
#   ./sr203.sh firewall-rule remove <service>         # remove an inbound rule by Service name
#   ./sr203.sh get <page.html>            # fetch any admin page (debug/inspection)
#   ./sr203.sh raw-post <endpoint> [--form <page.html>] k=v ...   # advanced: hand-crafted POST
#
# Passwords are read interactively (no terminal echo) or from an env var, never
# as a command-line argument:  SR203_NEW_PW=... (admin), SR203_WIFI_PW=... (Wi-Fi).
#
# Config via environment (sensible defaults shown):
#   SR203_HOST=192.168.0.1
#   SR203_NETRC=./.sr203_netrc     # format: machine 192.168.0.1 login admin password SECRET
#
set -euo pipefail

HOST="${SR203_HOST:-192.168.0.1}"
NETRC="${SR203_NETRC:-$(dirname "$0")/.sr203_netrc}"
BASE="http://${HOST}"

die() { echo "error: $*" >&2; exit 1; }

# --help / no args don't need credentials.
case "${1:-}" in
  ""|-h|--help) sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

[ -r "$NETRC" ] || die "netrc file not readable: $NETRC
  create it with:  umask 077; printf 'machine %s login admin password YOURPASS\\n' '$HOST' > '$NETRC'"

# Core curl wrappers. --http0.9 is the critical flag that makes POSTs work.
_get() {  # _get <path>  -> page body on stdout
  curl -s -m 15 --digest --netrc-file "$NETRC" "${BASE}/$1"
}
_post() { # _post <endpoint> <--data-urlencode args...> -> raw response body on stdout
  local ep="$1"; shift
  curl -s -m 15 --http0.9 --digest --netrc-file "$NETRC" "$@" "${BASE}/${ep}"
}

# Extract the anti-CSRF token from a page's HTML (read on stdin). The token appears
# either as a JS variable (var sessionID = '123'; on the firewall-rules pages, where
# the hidden field is a value="0" placeholder) or as a hidden field value (everywhere
# else). Zeros are ignored so we never pick up a placeholder.
_extract_key() {
  local html; html="$(cat)"
  { printf '%s' "$html" | grep -oiE "sessionID *= *'[0-9]+'" | grep -oE '[0-9]+'
    printf '%s' "$html" | grep -oiE 'name="sessionKey" value="[0-9]+"' | grep -oE '[0-9]+'
  } 2>/dev/null | grep -vxE '0' | head -1
}

# Pull the per-render token from a form page.
_session_key() { # _session_key <form_page>
  _get "$1" | _extract_key
}

# Read a hidden field's value from a page's HTML. Handles both attribute orders
# (name-before-value and value-before-name — the firmware mixes them).
_hidden_val() { # _hidden_val <html> <field-name>
  local html="$1" name="$2" v
  v="$(printf '%s' "$html" | grep -oiE "name=\"$name\" value=\"[^\"]*\"" | sed -E 's/.*value="([^"]*)".*/\1/' | head -1)"
  [ -n "$v" ] && { printf '%s' "$v"; return; }
  printf '%s' "$html" | grep -oiE "value=\"[^\"]*\" name=\"$name\"" | sed -E 's/value="([^"]*)".*/\1/' | head -1
}

# ---- block-sites (sky_blocksite.sky) --------------------------------------
PAGE="sky_block_sites.html"
EP="sky_blocksite.sky"

# Read the current url_setting blob (the firmware's source of truth:
#   field0=keyword-filter enable, field1=trusted-IP enable, field2=trusted IP,
#   field3.. = blocked keywords).
_current_urlset() {
  _get "$PAGE" | grep -oE 'name="url_setting"[^>]*>[^<]*(<br>[^<]*)*' | sed 's/.*display:none;">//' | head -1
}

# Remove one keyword from a url_setting blob (keeps the first three fields).
_urlset_without() { # _urlset_without <urlset> <keyword>
  local urlset="$1" kw="$2" IFS='|' i=0 out=""
  local parts; parts="$(printf '%s' "$urlset" | sed 's/<br>/|/g')"
  local arr; IFS='|' read -ra arr <<<"$parts"
  for i in "${!arr[@]}"; do
    local v="${arr[$i]}"
    if [ "$i" -lt 3 ]; then out+="${v}<br>"; continue; fi   # preserve header fields
    [ -z "$v" ] && continue                                  # drop empties
    [ "$v" = "$kw" ] && continue                             # drop target keyword
    out+="${v}<br>"
  done
  printf '%s' "$out"
}

_blocksite_post() {
  # args: todo_urlAddaction todo_urlRemoveaction h_KeyWordList h_KeyWordListRemove urlset_override
  local addact="$1" remact="$2" kwadd="$3" kwrem="$4" urlset_override="${5:-}"
  local page key urlset
  page="$(_get "$PAGE")"
  key="$(printf '%s' "$page" | _extract_key)"
  [ -n "$key" ] || die "could not read sessionKey (auth problem?)"
  if [ -n "$urlset_override" ]; then
    urlset="$urlset_override"
  else
    # preserve existing url_setting so we don't clobber trusted-IP/schedule state
    urlset="$(printf '%s' "$page" | grep -oE 'name="url_setting"[^>]*>[^<]*(<br>[^<]*)*' | sed 's/.*display:none;">//')"
  fi
  [ -n "$urlset" ] || urlset="1<br>0<br>0.0.0.0<br>"
  _post "$EP" \
    --data-urlencode "todo=save" \
    --data-urlencode "todo_urlAddaction=${addact}" \
    --data-urlencode "todo_urlRemoveaction=${remact}" \
    --data-urlencode "h_KeyWordList=${kwadd}" \
    --data-urlencode "h_KeyWordListRemove=${kwrem}" \
    --data-urlencode "h_skeyword=1" \
    --data-urlencode "h_ruleSelect=0" \
    --data-urlencode "h_trustipenable=disable" \
    --data-urlencode "c4_Trusted_IPAddress=0.0.0.0" \
    --data-urlencode "Trusted_IPAddress1=0" --data-urlencode "Trusted_IPAddress2=0" \
    --data-urlencode "Trusted_IPAddress3=0" --data-urlencode "Trusted_IPAddress4=0" \
    --data-urlencode "Trusted_IPAddressV6=" \
    --data-urlencode "skeyword=1" \
    --data-urlencode "url_setting=${urlset}" \
    --data-urlencode "sessionKey=${key}" \
    --data-urlencode "this_file=${PAGE}" \
    --data-urlencode "next_file=${PAGE}" >/dev/null
}

cmd_list_sites() {
  local urlset; urlset="$(_current_urlset)"
  # keywords are fields 4+ (after enable / trusted-IP enable / trusted-IP address)
  printf '%s' "$urlset" | sed 's/<br>/\n/g' | tail -n +4 \
    | { grep . || echo "(no keywords blocked)"; }
}

cmd_block_site() {
  local kw="${1:?usage: block-site <keyword>}"
  [ "${#kw}" -ge 3 ] || die "keyword must be at least 3 characters"
  case "$kw" in *\\*|*\"*) die 'keyword must not contain  \\  or  "' ;; esac
  _blocksite_post "set_url" "" "${kw}^" ""
  echo "blocked: $kw"
  echo "now blocked:"; cmd_list_sites | sed 's/^/  /'
}

cmd_unblock_site() {
  local kw="${1:?usage: unblock-site <keyword>}"
  # Removal only sticks if url_setting ALSO omits the keyword, otherwise the
  # firmware re-applies it from url_setting and cancels the remove.
  local stripped; stripped="$(_urlset_without "$(_current_urlset)" "$kw")"
  _blocksite_post "" "remove_url" "" "${kw}<br>" "$stripped"
  echo "unblocked: $kw"
  echo "now blocked:"; cmd_list_sites | sed 's/^/  /'
}

# ---- credentials in the netrc --------------------------------------------
_netrc_pw()   { awk '{for(i=1;i<=NF;i++) if($i=="password") print $(i+1)}' "$NETRC" | head -1; }
_netrc_user() { awk '{for(i=1;i<=NF;i++) if($i=="login")    print $(i+1)}' "$NETRC" | head -1; }
_write_netrc() { # _write_netrc <password>
  local u; u="$(_netrc_user)"; : "${u:=admin}"
  ( umask 077; printf 'machine %s login %s password %s\n' "$HOST" "$u" "$1" > "$NETRC" )
}
_login_works() { # _login_works <password>  -> 0 if that password authenticates
  local tmp code; tmp="$(mktemp)"; chmod 600 "$tmp"
  printf 'machine %s login %s password %s\n' "$HOST" "$(_netrc_user)" "$1" > "$tmp"
  code="$(curl -s -m 10 --digest --netrc-file "$tmp" -o /dev/null -w '%{http_code}' "${BASE}/sky_router_status.html")"
  rm -f "$tmp"
  [ "$code" = "200" ]
}
_read_secret() { # _read_secret <prompt>  -> echoes entered secret (no terminal echo)
  local s; read -rsp "$1" s </dev/tty; echo >/dev/tty; printf '%s' "$s"
}

# ---- admin (router) password: sky_password.scgi --------------------------
cmd_set_admin_password() {
  local new="${SR203_NEW_PW:-}"
  [ -n "$new" ] || new="$(_read_secret 'New admin password (1-16 chars): ')"
  [ -n "$new" ] || die "no password entered"
  [ "${#new}" -le 16 ] || die "password must be 1-16 characters"
  local old; old="$(_netrc_pw)"
  [ -n "$old" ] || die "could not read current password from netrc ($NETRC)"
  [ "$new" != "$old" ] || die "new password must differ from the current one"

  local page key timeout
  page="$(_get sky_set_password.html)"
  key="$(printf '%s' "$page" | _extract_key)"
  [ -n "$key" ] || die "could not read sessionKey (auth problem?)"
  timeout="$(printf '%s' "$page" | grep -oiE 'name="sessionIdleTimeout"[^>]*value="[0-9]+"' | grep -oE '[0-9]+' | head -1)"
  : "${timeout:=5}"

  _post "sky_password.scgi" \
    --data-urlencode "inUserName=admin" \
    --data-urlencode "inOrgPassword=${old}" \
    --data-urlencode "inPassword=${new}" \
    --data-urlencode "inConfirmPasswd=${new}" \
    --data-urlencode "sessionIdleTimeout=${timeout}" \
    --data-urlencode "todo=save_passwd" \
    --data-urlencode "sessionKey=${key}" \
    --data-urlencode "this_file=sky_set_password.html" \
    --data-urlencode "next_file=sky_set_password.html" >/dev/null || true

  if _login_works "$new"; then
    _write_netrc "$new"
    echo "admin password changed. netrc updated: $NETRC"
  elif _login_works "$old"; then
    die "password unchanged (router still accepts the old password). Check the old password / charset rules."
  else
    die "cannot authenticate with either password after the attempt. Verify manually before locking yourself out."
  fi
}

# ---- Wi-Fi (WPA2-PSK) password: sky_wireless_update.cmd -------------------
cmd_set_wifi_password() {
  local new="${SR203_WIFI_PW:-}"
  [ -n "$new" ] || new="$(_read_secret 'New Wi-Fi password (8-63 chars): ')"
  [ "${#new}" -ge 8 ] && [ "${#new}" -le 63 ] || die "WPA passphrase must be 8-63 characters"

  local page key mode
  page="$(_get sky_wireless_password.html)"
  key="$(printf '%s' "$page" | _extract_key)"
  [ -n "$key" ] || die "could not read sessionKey (auth problem?)"
  mode="$(printf '%s' "$page" | grep -oiE "var sky_wlAuthMode *= *'[^']*'" | sed -E "s/.*'([^']*)'.*/\1/")"
  case "$mode" in
    psk2|"psk psk2") : ;;
    *) die "this helper supports WPA2/WPA+WPA2-PSK only; your network mode is '${mode:-unknown}'. Use the GUI/proxy for other modes." ;;
  esac

  echo "WARNING: changing the Wi-Fi key disconnects all wireless clients until they reconnect with the new key." >&2
  _post "sky_wireless_update.cmd" \
    --data-urlencode "wlWpaPsk=${new}" \
    --data-urlencode "wlAuthMode=${mode}" \
    --data-urlencode "wlAuth=0" \
    --data-urlencode "wlWep=disabled" \
    --data-urlencode "wlWpa=aes" \
    --data-urlencode "wlPreauth=1" \
    --data-urlencode "wlKey1=" --data-urlencode "wlKeyText=" --data-urlencode "wlKeys=" \
    --data-urlencode "todo=save" \
    --data-urlencode "sessionKey=${key}" \
    --data-urlencode "this_file=sky_wireless_password.html" \
    --data-urlencode "next_file=sky_wireless_password.html" >/dev/null || true

  # verify: the page re-exposes the stored key in a JS var
  local now
  now="$(_get sky_wireless_password.html | grep -oiE "var sky_wlWpaKeyValue *= *decodeHtml\('[^']*'\)" | sed -E "s/.*'([^']*)'.*/\1/")"
  if [ "$now" = "$new" ]; then
    echo "Wi-Fi password updated (mode: $mode)."
  else
    die "Wi-Fi password may not have applied (verification mismatch). Check the GUI via the proxy."
  fi
}

# ---- inbound firewall rules (sky_firewall_rules.cmd) -----------------------
# Inbound rules (a.k.a. port forwards) map a predefined Service to a LAN IP. The
# add form lives on sky_firewall_rules-in.html (token in `var sessionID`), the list
# and delete on sky_firewall_rules.html (token in the hidden field).
FWPAGE="sky_firewall_rules.html"
FWADD="sky_firewall_rules-in.html"
FWEP="sky_firewall_rules.cmd"

# Fetch the firewall rules page, verifying it's the real page (retry transient fetches).
_fw_page() {
  local html i
  for i in 1 2 3; do
    html="$(_get "$FWPAGE")"
    case "$html" in *'name="fwrules"'*) printf '%s' "$html"; return 0 ;; esac
  done
  die "could not fetch the firewall rules page (auth/connection problem?)"
}

# Emit the inbound rule rows as TSV: service<TAB>action<TAB>lan<TAB>wan
_fw_rows() {
  _fw_page | sed 's/<tr>/\n<tr>/g' | grep -i 'name="in_sel"' | while IFS= read -r row; do
    local svc spans
    svc="$(printf '%s' "$row" | grep -oiE 'value="[^"]*" name="in_sel"' | sed -E 's/value="([^"]*)".*/\1/')"
    # spans in order: index, service, action, LAN, WAN, log
    spans="$(printf '%s' "$row" | grep -oE '<span class="thead">[^<]*</span>' | sed -E 's/<[^>]*>//g')"
    local action lan wan
    action="$(printf '%s\n' "$spans" | sed -n '3p')"
    lan="$(printf '%s\n' "$spans" | sed -n '4p')"
    wan="$(printf '%s\n' "$spans" | sed -n '5p')"
    printf '%s\t%s\t%s\t%s\n' "$svc" "$action" "$lan" "$wan"
  done
}

cmd_fw_list() {
  local rows; rows="$(_fw_rows)"
  if [ -z "$rows" ]; then echo "(no inbound firewall rules)"; return; fi
  printf '%-20s %-14s %-24s %s\n' "SERVICE" "ACTION" "LAN TARGET" "WAN SOURCE"
  printf '%s\n' "$rows" | while IFS=$'\t' read -r svc action lan wan; do
    printf '%-20s %-14s %-24s %s\n' "$svc" "$action" "$lan" "$wan"
  done
}

cmd_fw_add() {
  local svc="${1:?usage: firewall-rule add <service> <lan-ip>}" ip="${2:?usage: firewall-rule add <service> <lan-ip>}"
  case "$ip" in
    *.*.*.*) : ;;
    *) die "lan-ip must be an IPv4 address like 192.168.0.50" ;;
  esac
  local o1 o2 o3 o4; IFS=. read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    case "$o" in ''|*[!0-9]*) die "invalid IPv4 address: $ip" ;; esac
    [ "$o" -le 255 ] || die "invalid IPv4 address: $ip"
  done
  local key; key="$(_session_key "$FWADD")"
  [ -n "$key" ] || die "could not read sessionKey (auth problem?)"
  # Mirrors exactly what the web form submits for an inbound ALLOW rule from any WAN IP.
  _post "$FWEP" \
    --data-urlencode "service_list=${svc}" --data-urlencode "h_service_list=${svc}" \
    --data-urlencode "fw_action=2" --data-urlencode "h_fw_action=2" \
    --data-urlencode "fw_waniptype=anyip" --data-urlencode "h_fw_waniptype=anyip" \
    --data-urlencode "fw_logging=0" --data-urlencode "h_fw_logging=0" \
    --data-urlencode "lan_start_ip1=${o1}" --data-urlencode "lan_start_ip2=${o2}" \
    --data-urlencode "lan_start_ip3=${o3}" --data-urlencode "lan_start_ip4=${o4}" \
    --data-urlencode "c4_lan_start_ip=${ip}" \
    --data-urlencode "c4_wan_start_ip=0.0.0.0" --data-urlencode "c4_wan_finish_ip=0.0.0.0" \
    --data-urlencode "fw_direction=1" --data-urlencode "fw_ip_version=4" \
    --data-urlencode "h_ruleSelect=" --data-urlencode "edit=0" \
    --data-urlencode "fwall_action=add" --data-urlencode "todo=save" \
    --data-urlencode "sessionKey=${key}" \
    --data-urlencode "this_file=sky_firewall_rules-in.html" --data-urlencode "next_file=sky_firewall_rules.html" \
    >/dev/null
  if _fw_rows | cut -f1 | grep -qxF "$svc"; then
    echo "added inbound rule: $svc -> $ip"
  else
    die "rule did not appear (is '$svc' a defined Service on the router?)"
  fi
}

cmd_fw_remove() {
  local svc="${1:?usage: firewall-rule remove <service>}"
  local page; page="$(_fw_page)"
  # 0-based index of the rule among inbound rules (what selected_index_edit_delete wants)
  local idx; idx="$(printf '%s' "$page" | sed 's/<tr>/\n<tr>/g' | grep -i 'name="in_sel"' \
    | grep -oiE 'value="[^"]*" name="in_sel"' | sed -E 's/value="([^"]*)".*/\1/' \
    | grep -nxF "$svc" | head -1 | cut -d: -f1)"
  [ -n "$idx" ] || die "no inbound rule named '$svc' (try: firewall-rule list)"
  idx=$((idx - 1))
  local cnt; cnt="$(_hidden_val "$page" inboundRuleCnt)"
  case "$cnt" in ''|*[!0-9]*) die "could not read inbound rule count; aborting delete" ;; esac
  local key; key="$(printf '%s' "$page" | _extract_key)"
  [ -n "$key" ] || die "could not read sessionKey (auth problem?)"
  # preserve current firewall toggles so we don't change them
  _post "$FWEP" \
    --data-urlencode "fwall_action=remove" --data-urlencode "todo=delete" \
    --data-urlencode "selected_index_edit_delete=${idx}" \
    --data-urlencode "in_sel=${svc}" --data-urlencode "h_in_sel=${svc}" \
    --data-urlencode "h_ip_version=4" \
    --data-urlencode "inboundRuleCnt=${cnt}" \
    --data-urlencode "in_enable=$(_hidden_val "$page" in_enable)" \
    --data-urlencode "out_enable=$(_hidden_val "$page" out_enable)" \
    --data-urlencode "outboundRuleCnt=$(_hidden_val "$page" outboundRuleCnt)" \
    --data-urlencode "ipv6firewallenable=$(_hidden_val "$page" ipv6firewallenable)" \
    --data-urlencode "ipsecfirewallenable=$(_hidden_val "$page" ipsecfirewallenable)" \
    --data-urlencode "icmpv6echoreqallow=$(_hidden_val "$page" icmpv6echoreqallow)" \
    --data-urlencode "sessionKey=${key}" \
    --data-urlencode "this_file=sky_firewall_rules.html" --data-urlencode "next_file=sky_firewall_rules.html" \
    >/dev/null
  if _fw_rows | cut -f1 | grep -qxF "$svc"; then
    die "rule '$svc' still present (removal may have failed)"
  else
    echo "removed inbound rule: $svc"
  fi
}

cmd_firewall_rule() {
  local sub="${1:-}"; shift || true
  case "$sub" in
    list)   cmd_fw_list "$@" ;;
    add)    cmd_fw_add "$@" ;;
    remove) cmd_fw_remove "$@" ;;
    *) die "usage: firewall-rule list | add <service> <lan-ip> | remove <service>" ;;
  esac
}

# ---- generic helpers ------------------------------------------------------
cmd_get() { _get "${1:?usage: get <page.html>}"; }

# Map a write endpoint to the form page that carries its token (best-effort).
_form_page_for() {
  case "$1" in
    sky_blocksite.sky)        echo "sky_block_sites.html" ;;
    sky_firewall_rules.cmd)   echo "sky_firewall_rules-in.html" ;;
    sky_password.scgi)        echo "sky_set_password.html" ;;
    sky_wireless_update.cmd)  echo "sky_wireless_password.html" ;;
    *.sky|*.cmd|*.scgi)       echo "${1%.*}.html" ;;   # fallback guess
    *)                        echo "" ;;
  esac
}

cmd_raw_post() {
  local ep="${1:?usage: raw-post <endpoint> [--form <page.html>] k=v [k=v ...]}"; shift
  local form="" args=() have_key=""
  if [ "${1:-}" = "--form" ]; then form="$2"; shift 2; fi
  [ -n "$form" ] || form="$(_form_page_for "$ep")"
  for kv in "$@"; do
    case "$kv" in sessionKey=*) have_key=1 ;; esac
    args+=(--data-urlencode "$kv")
  done
  # only fetch/stamp a token if the caller didn't supply one
  if [ -z "$have_key" ] && [ -n "$form" ]; then
    local key; key="$(_session_key "$form" 2>/dev/null || true)"
    [ -n "$key" ] && args+=(--data-urlencode "sessionKey=${key}")
  fi
  _post "$ep" "${args[@]}"
}

# ---- dispatch -------------------------------------------------------------
case "${1:-}" in
  list-sites)         shift; cmd_list_sites "$@" ;;
  block-site)         shift; cmd_block_site "$@" ;;
  unblock-site)       shift; cmd_unblock_site "$@" ;;
  set-admin-password) shift; cmd_set_admin_password "$@" ;;
  set-wifi-password)  shift; cmd_set_wifi_password "$@" ;;
  firewall-rule)      shift; cmd_firewall_rule "$@" ;;
  get)                shift; cmd_get "$@" ;;
  raw-post)           shift; cmd_raw_post "$@" ;;
  *) die "unknown command: $1  (try --help)" ;;
esac
