#!/usr/bin/env bash
# The country check of a participant node (docs/network.md#country). Sourced, never run; source it
# after scripts/lib/env.sh.
#
# The country a node shows is always the owner's choice: it is never detected, never filled in and
# never sent anywhere by this check. The check only compares the chosen code with a GeoIP database
# ON THIS MACHINE, to catch a typo or a VPS that is in another country than expected. It never asks
# an outside service where this machine is.
#
#   geo_own_addresses          the public addresses of this machine, read from its own interfaces
#                              (`ip`), plus SELF_ADDRESS from .env. Nothing is looked up outside.
#   geo_sources                which local databases exist (prints one name per line)
#   geo_check CC               sets GEO_RESULT (match, mismatch, unknown), GEO_FOUND (the country
#                              of the database), GEO_ADDR, GEO_SOURCE and GEO_WHY (for unknown)
#   geo_download               fetches DB-IP's free country list (CSV, CC BY 4.0) into
#                              .suckerpot-state/geoip/. The ONLY outside request of this file, made
#                              only after the owner said yes to it (or --country-check download).
#
# Local databases, in this order:
#   1. .suckerpot-state/geoip/dbip-country-lite.csv.gz (an earlier geo_download), or the CSV in
#      SUCKERPOT_GEOIP_CSV (DB-IP's "IP to Country Lite" CSV, plain or gzip);
#   2. the GeoIP files ingest already keeps in its geoip-data volume (GeoLite2 or DB-IP Lite, when
#      the stack runs and has downloaded them: full installs and VPN nodes), read inside the
#      running ingest container;
#   3. a system database read with mmdblookup (libmaxminddb), for example from geoipupdate.

# shellcheck disable=SC2034 # GEO_* are the results, read by the callers
true
GEO_CSV=.suckerpot-state/geoip/dbip-country-lite.csv.gz
GEO_ATTRIBUTION="IP geolocation by DB-IP.com (CC BY 4.0)"
GEO_DOWNLOAD_HOST=download.db-ip.com

# ISO 3166-1 alpha-2 codes (officially assigned), for a fast check of a typed code.
GEO_CODES="AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ
BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE
EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR
HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS
LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL
NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI
SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY
UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"

# geo_code_ok CC: a known two-letter code (any case). Prints the reason on failure.
geo_code_ok() {
  local cc=${1^^}
  if ! [[ $cc =~ ^[A-Z]{2}$ ]]; then
    echo "a country is two letters, for example FR, DE or CH"
    return 1
  fi
  case " ${GEO_CODES//$'\n'/ } " in *" $cc "*) return 0 ;; esac
  echo "$cc is not a country code (ISO 3166-1), for example FR, DE or CH"
  return 1
}

# geo_public ADDR: a globally routable address (no private, shared, loopback, link-local,
# documentation or multicast range). The tests let documentation addresses through with
# SELFHOSTR_GEO_ALLOW_DOC=1: it only changes which address the local check looks up.
geo_public() {
  local a=$1 o1 o2 o3 o4 rest doc=0
  [ "${SELFHOSTR_GEO_ALLOW_DOC:-}" != 1 ] || doc=1
  if [[ $a =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    o1=${BASH_REMATCH[1]} o2=${BASH_REMATCH[2]} o3=${BASH_REMATCH[3]} o4=${BASH_REMATCH[4]}
    [ "$o1" -le 255 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] && [ "$o4" -le 255 ] || return 1
    if [ "$doc" = 0 ]; then
      case "$o1.$o2.$o3" in 192.0.2 | 198.51.100 | 203.0.113) return 1 ;; esac
    fi
    case $o1 in 0 | 10 | 127) return 1 ;; esac
    [ "$o1" -lt 224 ] || return 1
    [ "$o1" != 100 ] || [ "$o2" -lt 64 ] || [ "$o2" -gt 127 ] || return 1
    [ "$o1" != 169 ] || [ "$o2" != 254 ] || return 1
    [ "$o1" != 172 ] || [ "$o2" -lt 16 ] || [ "$o2" -gt 31 ] || return 1
    [ "$o1" != 192 ] || [ "$o2" != 168 ] || return 1
    [ "$o1" != 198 ] || { [ "$o2" != 18 ] && [ "$o2" != 19 ]; } || return 1
    return 0
  fi
  rest=${a,,}
  [[ $rest =~ ^[0-9a-f:]+$ && $rest == *:* ]] || return 1
  # Global unicast is 2000::/3; the documentation prefix 2001:db8::/32 is not routed.
  [[ $rest =~ ^[23] ]] || return 1
  if [ "$doc" = 0 ]; then [[ $rest != 2001:db8:* && $rest != 2001:0db8:* ]] || return 1; fi
  return 0
}

# geo_own_addresses: public addresses of this machine, first the one set by hand (SELF_ADDRESS,
# or GEO_SELF_ADDRESS from the installer's --self-address), then the interfaces. A machine behind a
# home router has none: its public address is the router's, and only an outside service could
# tell it, which this check never asks.
geo_own_addresses() {
  local a list="" seen=" " found=0
  list="${GEO_SELF_ADDRESS:-}"
  if [ -f .env ]; then list+=",$(env_get SELF_ADDRESS)"; fi
  if command -v ip > /dev/null 2>&1; then
    list+=",$(ip -o addr show scope global 2> /dev/null | awk '{split($4, a, "/"); printf "%s,", a[1]}')"
  fi
  while IFS= read -r a; do
    [ -n "$a" ] || continue
    case $seen in *" $a "*) continue ;; esac
    seen+="$a "
    if geo_public "$a"; then printf '%s\n' "$a"; found=1; fi
  done < <(printf '%s\n' "$list" | tr ' ,' '\n\n')
  # Optional (SUCKERPOT_GEO_METADATA=1): the cloud's own metadata service, when no address was
  # found. It answers on the link-local address 169.254.169.254 inside the provider's network
  # (never on the internet), so the address is not asked of an outside service.
  if [ "$found" = 0 ] && [ "${SUCKERPOT_GEO_METADATA:-}" = 1 ]; then
    a=$(_geo_metadata_address)
    [ -z "$a" ] || ! geo_public "$a" || printf '%s\n' "$a"
  fi
}

# _geo_metadata_address: the public IPv4 the metadata service of AWS, Google Cloud or Azure gives
# this VM (2 s at most each, the link-local address only). Oracle Cloud's does not list it.
_geo_metadata_address() {
  local m=http://169.254.169.254 tok a=""
  command -v curl > /dev/null 2>&1 || return 0
  local c=(curl -fsS --max-time 2 --noproxy '*')
  if tok=$("${c[@]}" -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' "$m/latest/api/token" 2> /dev/null); then
    a=$("${c[@]}" -H "X-aws-ec2-metadata-token: $tok" "$m/latest/meta-data/public-ipv4" 2> /dev/null || true)
  fi
  [ -n "$a" ] || a=$("${c[@]}" -H 'Metadata-Flavor: Google' "$m/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" 2> /dev/null || true)
  [ -n "$a" ] || a=$("${c[@]}" -H 'Metadata: true' "$m/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" 2> /dev/null || true)
  [[ $a =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && printf '%s' "$a"
  return 0
}

# _geo_csv_lookup FILE ADDR: the country of ADDR in a DB-IP country CSV ("first,last,CC" rows,
# sorted). Prints the code, or nothing. Plain awk: the addresses become fixed-width hex strings
# and compare as text.
_geo_csv_lookup() {
  local file=$1 addr=$2 cat=cat
  case $file in *.gz) cat="gzip -dc" ;; esac
  $cat "$file" 2> /dev/null | awk -F, -v want="$addr" '
    function v4(s,   a) { split(s, a, "."); return sprintf("4%02x%02x%02x%02x", a[1], a[2], a[3], a[4]) }
    function v6(s,   head, tail, h, t, nh, nt, i, out, g, fill) {
      s = tolower(s)
      if (index(s, "::")) { head = substr(s, 1, index(s, "::") - 1); tail = substr(s, index(s, "::") + 2) }
      else { head = s; tail = "" }
      nh = (head == "") ? 0 : split(head, h, ":")
      nt = (tail == "") ? 0 : split(tail, t, ":")
      out = "6"
      for (i = 1; i <= nh; i++) { g = h[i]; while (length(g) < 4) g = "0" g; out = out g }
      fill = 8 - nh - nt
      for (i = 0; i < fill; i++) out = out "0000"
      for (i = 1; i <= nt; i++) { g = t[i]; while (length(g) < 4) g = "0" g; out = out g }
      return out
    }
    function key(s) { return index(s, ":") ? v6(s) : v4(s) }
    BEGIN { k = key(want); fam = substr(k, 1, 1) }
    NF >= 3 {
      if ((index($1, ":") ? "6" : "4") != fam) next
      lo = key($1)
      if (lo > k) exit
      hi = key($2)
      # ZZ means unknown in the list.
      if (k <= hi) { cc = toupper($3); gsub(/[^A-Z]/, "", cc); if (cc != "ZZ") print cc; exit }
    }'
}

# _geo_ingest_lookup ADDR: the country from the GeoIP files of the running ingest container.
_geo_ingest_lookup() {
  dc exec -T ingest python -I -c '
import sys
from pathlib import Path
try:
    import maxminddb
except ImportError:
    sys.exit(0)
for name in ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb", "GeoLite2-Country.mmdb", "dbip-country-lite.mmdb"):
    path = Path("/data/geoip") / name
    if not path.is_file():
        continue
    try:
        with maxminddb.open_database(str(path)) as db:
            rec = db.get(sys.argv[1]) or {}
    except (OSError, ValueError):
        continue
    code = (rec.get("country") or {}).get("iso_code")
    if isinstance(code, str) and len(code) == 2:
        print(code.upper() + " " + name)
    break
' "$1" 2> /dev/null | tr -d '\r' | head -n 1
}

# _geo_mmdb_files: system GeoIP databases that mmdblookup can read.
_geo_mmdb_files() {
  local d f root=${SELFHOSTR_GEO_ROOT:-}
  for d in /usr/share/GeoIP /var/lib/GeoIP /usr/local/share/GeoIP; do
    for f in GeoLite2-Country.mmdb GeoLite2-City.mmdb dbip-country-lite.mmdb dbip-city-lite.mmdb; do
      [ -r "$root$d/$f" ] && printf '%s\n' "$root$d/$f"
    done
  done
  return 0
}

_geo_ingest_up() {
  [ -f .env ] && command -v "${ENGINE_CTR[0]}" > /dev/null 2>&1 || return 1
  [ -n "$(dc ps --status running -q ingest 2> /dev/null)" ]
}

# geo_csv_file: the local CSV, when there is one.
geo_csv_file() {
  if [ -n "${SUCKERPOT_GEOIP_CSV:-}" ] && [ -r "$SUCKERPOT_GEOIP_CSV" ]; then
    printf '%s' "$SUCKERPOT_GEOIP_CSV"
  elif [ -r "$GEO_CSV" ]; then
    printf '%s' "$GEO_CSV"
  else
    return 1
  fi
}

geo_sources() {
  geo_csv_file > /dev/null && echo csv
  _geo_ingest_up && echo ingest
  command -v mmdblookup > /dev/null 2>&1 && [ -n "$(_geo_mmdb_files)" ] && echo mmdb
  return 0
}

# geo_check CC
geo_check() {
  local want=${1^^} addr found="" src="" file out
  GEO_RESULT=unknown GEO_FOUND="" GEO_ADDR="" GEO_SOURCE="" GEO_WHY=""
  # sed reads it all: head would close the pipe early and, under pipefail, the SIGPIPE of the
  # loop that still writes ended the calling script without a word (exit 141).
  addr=$(geo_own_addresses | sed -n 1p)
  if [ -z "$addr" ]; then
    GEO_WHY="no public address on this machine's interfaces (a home router, or a cloud server behind NAT such as Oracle Cloud, AWS or Google Cloud), and no SELF_ADDRESS. Give it with --self-address ADDR (or SELF_ADDRESS in .env); on AWS, Google Cloud or Azure, SUCKERPOT_GEO_METADATA=1 asks the cloud's local metadata service. The check never asks an outside service"
    return 0
  fi
  GEO_ADDR=$addr
  if file=$(geo_csv_file); then
    found=$(_geo_csv_lookup "$file" "$addr")
    src="DB-IP country list on this machine ($GEO_ATTRIBUTION)"
  fi
  if [ -z "$found" ] && _geo_ingest_up; then
    out=$(_geo_ingest_lookup "$addr")
    if [ -n "$out" ]; then
      found=${out%% *}
      src="ingest's GeoIP database (${out#* })"
    fi
  fi
  if [ -z "$found" ] && command -v mmdblookup > /dev/null 2>&1; then
    while IFS= read -r file; do
      found=$(mmdblookup --file "$file" --ip "$addr" country iso_code 2> /dev/null | sed -n 's/^ *"\([A-Za-z][A-Za-z]\)".*/\1/p' | sed -n 1p)
      if [ -n "$found" ]; then src="$file (mmdblookup)"; break; fi
    done < <(_geo_mmdb_files)
  fi
  if [ -z "$found" ]; then
    if [ -n "$(geo_sources)" ]; then
      GEO_WHY="the local GeoIP database does not know $addr"
    else
      GEO_WHY="no GeoIP database on this machine"
    fi
    return 0
  fi
  GEO_FOUND=${found^^}
  GEO_SOURCE=$src
  if [ "$GEO_FOUND" = "$want" ]; then GEO_RESULT=match; else GEO_RESULT=mismatch; fi
  return 0
}

# geo_download: DB-IP's "IP to Country Lite" list of this month (or the last one), checked for its
# shape before it is kept. Contacts download.db-ip.com over HTTPS from this machine's own address
# (and its DNS resolver), and nothing else; the address being checked is never sent.
geo_download() {
  local dir=.suckerpot-state/geoip tmp month url ok=0 m
  command -v curl > /dev/null 2>&1 || { echo "curl is not installed" >&2; return 1; }
  mkdir -p "$dir"
  tmp=$(mktemp "$dir/download.XXXXXX")
  for m in 0 1; do
    month=$(date -u -d "$(date -u +%Y-%m-15) -$m month" +%Y-%m 2> /dev/null) || continue
    url="https://$GEO_DOWNLOAD_HOST/free/dbip-country-lite-$month.csv.gz"
    if curl -fsSL --proto '=https' --tlsv1.2 --max-time 180 --max-filesize 104857600 -o "$tmp" "$url" 2> /dev/null; then
      ok=1
      break
    fi
  done
  if [ "$ok" = 0 ]; then rm -f "$tmp"; echo "the download from $GEO_DOWNLOAD_HOST failed" >&2; return 1; fi
  # The shape of every one of the first lines: "first,last,CC".
  if ! gzip -t "$tmp" 2> /dev/null || [ "$( (gzip -dc "$tmp" | head -n 50 | grep -cvE '^[0-9a-fA-F.:]+,[0-9a-fA-F.:]+,[A-Z]{2}$') 2> /dev/null || true)" != 0 ]; then
    rm -f "$tmp"
    echo "the file from $GEO_DOWNLOAD_HOST does not look like the country list" >&2
    return 1
  fi
  chmod 644 "$tmp"
  mv "$tmp" "$GEO_CSV"
  printf '%s\nDownloaded %s from %s.\n' "$GEO_ATTRIBUTION" "$(date -u +%Y-%m-%d)" "$url" > "$dir/README"
  return 0
}
