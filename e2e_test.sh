#!/usr/bin/env bash
#
# e2e_test.sh -- end-to-end proof that QueryShield does its job.
#
# Starts the vulnerable victim (:8081) and the proxy in BLOCK mode (:8080),
# then asserts three things the README claims:
#
#   A. The three real exploits are BLOCKED (403) when sent through the proxy.
#   B. Normal traffic still works through the proxy (including hard negatives
#      like a name with an apostrophe).
#   C. The real fix: the same attacks that succeed against the vulnerable
#      endpoints FAIL against the /safe/* endpoints (PreparedStatement),
#      measured directly against the victim with no proxy.
#
# Exits non-zero if any assertion fails. Targets only localhost + fake data.
# Prerequisite: bash victim/setup_db.sh

set -uo pipefail
cd "$(dirname "$0")"

VICTIM=http://127.0.0.1:8081
PROXY=http://127.0.0.1:8080
PASS=0; FAIL=0

[ -f victim/local.properties ] || { echo "run: bash victim/setup_db.sh first"; exit 1; }

# Fail fast if the ports are busy (a stale server would invalidate the test).
if lsof -nP -iTCP:8080 -iTCP:8081 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "error: port 8080 or 8081 already in use; stop the other process first." >&2
  exit 1
fi

echo "== building =="
make -s build

CP="out/main:src/main/resources:$(ls lib/mysql-connector-j-*.jar)"
java -cp "$CP" com.queryshield.victim.VictimApp --port=8081 >/tmp/qs_e2e_victim.log 2>&1 & VPID=$!
java -cp "$CP" com.queryshield.proxy.ProxyServer >/tmp/qs_e2e_proxy.log 2>&1 & XPID=$!
cleanup(){ kill "$VPID" "$XPID" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 40); do
  curl -fs "$VICTIM/health" >/dev/null 2>&1 && curl -fs "$PROXY/health" >/dev/null 2>&1 && break
  if ! kill -0 "$VPID" 2>/dev/null; then echo "victim died:"; cat /tmp/qs_e2e_victim.log; exit 1; fi
  if ! kill -0 "$XPID" 2>/dev/null; then echo "proxy died:"; cat /tmp/qs_e2e_proxy.log; exit 1; fi
  sleep 0.5
done

# ---- helpers ---------------------------------------------------------------
# call <curl args...> ; sets CODE and BODY
call(){ local r; r=$(curl -s -w $'\n%{http_code}' "$@"); CODE=${r##*$'\n'}; BODY=${r%$'\n'*}; }
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
expect_code(){ [ "$CODE" = "$1" ] && ok "$2 (HTTP $CODE)" || no "$2 (expected $1, got $CODE)"; }
body_has(){ case "$BODY" in *"$1"*) ok "$2";; *) no "$2 (missing '$1')";; esac; }
body_lacks(){ case "$BODY" in *"$1"*) no "$2 (unexpectedly found '$1')";; *) ok "$2";; esac; }

echo
echo "== A. exploits BLOCKED through the proxy (:8080, block mode) =="
call -X POST "$PROXY/login" --data-urlencode "username=admin' -- " --data-urlencode "password=x"
expect_code 403 "auth-bypass login is blocked"
call --get "$PROXY/search" --data-urlencode "q=' UNION SELECT id, value, 1 FROM secrets -- "
expect_code 403 "UNION extraction is blocked"
call --get "$PROXY/profile" --data-urlencode "id=1 AND 1=1"
expect_code 403 "boolean-blind probe is blocked"
# Time-based: must be blocked AND fast, proving it never reached the DB to sleep.
read CODE_T TIME_T < <(curl -s -o /dev/null -w '%{http_code} %{time_total}' --get "$PROXY/profile" --data-urlencode "id=1 AND SLEEP(3)")
[ "$CODE_T" = "403" ] && ok "time-based probe is blocked (HTTP 403)" || no "time-based blocked (got $CODE_T)"
awk "BEGIN{exit !($TIME_T < 1.0)}" && ok "time-based blocked FAST (${TIME_T}s, never slept)" || no "time-based was slow (${TIME_T}s) -- did it reach the DB?"

echo
echo "== B. normal traffic still works through the proxy =="
call --get "$PROXY/search" --data-urlencode "q=mug"
expect_code 200 "benign search forwarded"; body_has "Union Station Mug" "benign search returns the product"
call -X POST "$PROXY/login" --data-urlencode "username=admin" --data-urlencode "password=wrong"
expect_code 401 "benign login forwarded (app rejects bad password)"
call --get "$PROXY/profile" --data-urlencode "id=1"
expect_code 200 "benign profile forwarded"; body_has "admin" "benign profile returns data"
# Hard negative: the proxy must NOT block an apostrophe name. We send it to the
# /safe endpoint, because the *vulnerable* /search itself 500s on an apostrophe
# (its concatenated SQL breaks) -- a symptom of the very bug this project is
# about. A 200 here proves the proxy forwarded it AND a correct endpoint serves it.
call --get "$PROXY/safe/search" --data-urlencode "q=O'Brien"
expect_code 200 "hard negative (O'Brien) is NOT blocked by the proxy"
call --get "$PROXY/safe/search" --data-urlencode "q=union station timetable"
expect_code 200 "hard negative ('union station timetable') is NOT blocked"

echo
echo "== C. the real fix: vulnerable vs /safe (direct to victim, no proxy) =="
call -X POST "$VICTIM/login" --data-urlencode "username=admin' -- " --data-urlencode "password=x"
body_has '"authenticated":true' "vulnerable /login IS bypassed (proof the app is vulnerable)"
call -X POST "$VICTIM/safe/login" --data-urlencode "username=admin' -- " --data-urlencode "password=x"
body_lacks '"authenticated":true' "/safe/login resists the same bypass (PreparedStatement)"
call --get "$VICTIM/search" --data-urlencode "q=' UNION SELECT id, value, 1 FROM secrets -- "
body_has "FAKE" "vulnerable /search leaks the secrets table"
call --get "$VICTIM/safe/search" --data-urlencode "q=' UNION SELECT id, value, 1 FROM secrets -- "
body_lacks "FAKE" "/safe/search does not leak (treated as a literal search string)"

echo
echo "============================================================"
echo "  e2e result: $PASS passed, $FAIL failed"
echo "============================================================"
[ "$FAIL" -eq 0 ]
