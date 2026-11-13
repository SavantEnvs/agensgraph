#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer functional oracle for AgensGraph: initdb + start the server built by
# mayhem/build.sh (mayhem/install-test, normal flags), run SQL, jsonb/jsonpath and openCypher statements
# through psql and compare the exact output with the expected values.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/mayhem/install-test/bin"
export LD_LIBRARY_PATH="$SRC/mayhem/install-test/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
TOOL="agensgraph-psql-kat"
passed=0; failed=0

for x in initdb pg_ctl psql postgres; do
  [ -x "$BIN/$x" ] || { echo "missing $BIN/$x — mayhem/build.sh did not build the test install" >&2; emit_ctrf "$TOOL" 0 1 0; exit 1; }
done

WORK="$(mktemp -d)"
SOCK="$WORK/sock"; mkdir -p "$SOCK"
started=0
cleanup() {
  [ "$started" = 1 ] && "$BIN/pg_ctl" -D "$WORK/data" -m immediate stop >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

if "$BIN/initdb" -D "$WORK/data" -A trust --no-sync >"$WORK/initdb.log" 2>&1 \
   && "$BIN/pg_ctl" -D "$WORK/data" -w -l "$WORK/server.log" \
        -o "-c listen_addresses= -c unix_socket_directories=$SOCK -c fsync=off" start >"$WORK/start.log" 2>&1; then
  started=1
else
  tail -20 "$WORK/initdb.log" "$WORK/start.log" 2>/dev/null >&2
  emit_ctrf "$TOOL" 0 1 0; exit 1
fi

# check <name> <expected-output>; the SQL / Cypher script comes on stdin.
check() {
  local name="$1" expected="$2" got
  got="$("$BIN/psql" -h "$SOCK" -d postgres -AtqX -v ON_ERROR_STOP=1 2>&1)"
  if [ "$got" = "$expected" ]; then
    passed=$((passed+1)); echo "ok   $name"
  else
    failed=$((failed+1)); echo "FAIL $name"; echo "  expected: $expected" | head -20; echo "  got:      $got" | head -20
  fi
}

check "sql arithmetic" "3" <<'SQL'
SELECT 1 + 2;
SQL

check "sql text" "ab|3" <<'SQL'
SELECT 'a' || 'b', length('xyz');
SQL

check "jsonb operators" "[1, 2]|{\"a\": [1, 2], \"b\": null}" <<'SQL'
SELECT '{"a":[1,2]}'::jsonb -> 'a', jsonb_set('{"a":[1,2]}'::jsonb, '{b}', 'null');
SQL

check "jsonpath query" "[2, 3]" <<'SQL'
SELECT jsonb_path_query_array('{"a":[1,2,3]}', '$.a[*] ? (@ > 1)');
SQL

check "cypher create + match" '"alice"|"bob"|2020' <<'SQL'
CREATE GRAPH kat1;
SET graph_path = kat1;
CREATE (:person {name: 'alice', age: 30})-[:knows {since: 2020}]->(:person {name: 'bob', age: 25});
MATCH (a)-[k:knows]->(b) RETURN a.name, b.name, k.since;
SQL

check "cypher order by + aggregate" '"bob"
"alice"
2|55' <<'SQL'
SET graph_path = kat1;
MATCH (n:person) RETURN n.name ORDER BY n.age;
MATCH (n:person) RETURN count(n), sum(n.age);
SQL

check "cypher variable-length path" '"b"
"c"
"d"' <<'SQL'
CREATE GRAPH kat2;
SET graph_path = kat2;
CREATE (:n {name: 'a'})-[:next]->(:n {name: 'b'})-[:next]->(:n {name: 'c'})-[:next]->(:n {name: 'd'});
MATCH (:n {name: 'a'})-[:next*1..3]->(x) RETURN x.name ORDER BY x.name;
SQL

check "cypher set" '31' <<'SQL'
SET graph_path = kat1;
MATCH (n:person {name: 'alice'}) SET n.age = 31 RETURN n.age;
SQL

check "cypher expression functions" '"ABC"|1024|"ell"|3' <<'SQL'
RETURN toUpper('abc'), 2 ^ 10, substring('hello', 1, 3), size([1, 2, 3]);
SQL

emit_ctrf "$TOOL" "$passed" "$failed" 0
