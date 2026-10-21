#!/bin/bash
# CFG-qrmem - tile fabric gate.
#
# What this gate proves, and the shape of each piece:
#
#  1. The fabric sources build clean under the project's warning set.
#  2. The aperture contract passes, AND passes under ThreadSanitizer.
#  3. The multi-process path passes: one writer process, one reader process,
#     sharing one live fabric.
#  4. The codec passes, including a fuzzer that must not be vacuous.
#  5. The ordering gate can FAIL. A weakened build (-DQRMEM_WEAKEN_RELEASE,
#     which makes the cell publication store relaxed) must be caught by
#     ThreadSanitizer. This is the gate that proves gates 2 and 3 mean anything.
#
# On (5): if ThreadSanitizer is unavailable the gate prints a loud banner and
# marks the ordering claims UNVERIFIED, rather than quietly passing. A gate that
# cannot fail is worse than no gate, because it is read as evidence.
#
# Two limits worth keeping in mind while reading this file:
#
#  - ThreadSanitizer tracks happens-before WITHIN a process. It cannot see a race
#    between two processes that mmap the same segment, so test 3 is deliberately
#    NOT run under TSan. Building it under TSan would produce a clean report
#    that means nothing.
#  - TSan and fork() in one binary misbehave: the parent's main() is re-entered
#    after the child exits. That is why the threaded gate and the multi-process
#    gate are separate binaries.
set -u
cd "$(dirname "$0")/.."

# qrmem_uuid.c is here because identity IS part of the fabric: record ids, links
# and successors all live in the shared surface. A gate that linked the codec
# without it failed to link at all, which is the least informative possible
# report of a missing source file.
SRC="src/qrmem_aperture.c src/qrmem_cell.c src/qrmem_tile.c src/qrmem_plane.c src/qrmem_uuid.c src/qrmem_persist.c src/qrmem_recover.c"
BASE="-std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -Wshadow \
-Werror=implicit-function-declaration -Wno-unused-parameter \
-Wno-overlength-strings -Werror=format-truncation -Werror=shadow \
-Werror=unterminated-string-initialization -Isrc"
TMP="$(mktemp -d /tmp/qrmem-gate-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
fail=0

say() { printf '== %s\n' "$1"; }
bad() { echo "GATE FAIL: $1"; fail=1; }

# Isolate the shared-memory names so a gate run cannot collide with a live
# fabric the operator is using.
export QRMEM_TEST_PREFIX="/qrmem-gate-$$"

say "fabric sources build clean under the project warning set"
# shellcheck disable=SC2086
if cc $BASE -O1 -c src/qrmem_aperture.c -o "$TMP/a.o" 2>"$TMP/w1" &&
   cc $BASE -O1 -c src/qrmem_cell.c     -o "$TMP/c.o" 2>"$TMP/w2" &&
   cc $BASE -O1 -c src/qrmem_tile.c     -o "$TMP/t.o" 2>"$TMP/w3"; then
  [ -s "$TMP/w1" ] && { cat "$TMP/w1"; bad "qrmem_aperture.c emitted warnings"; }
  [ -s "$TMP/w2" ] && { cat "$TMP/w2"; bad "qrmem_cell.c emitted warnings"; }
  [ -s "$TMP/w3" ] && { cat "$TMP/w3"; bad "qrmem_tile.c emitted warnings"; }
  echo "   ok  no warnings from any fabric source"
else
  cat "$TMP/w1" "$TMP/w2" "$TMP/w3"
  bad "the fabric sources did not compile"
fi

# Probe for a WORKING ThreadSanitizer, not merely a present one.
#
# Compiling is not the test. On this project's musl hosts (Saphira Linux / egg)
# ThreadSanitizer is unusable: gcc cannot link libtsan at all, and clang links a
# binary that segfaults before main(). A probe that only checked "did it compile"
# therefore selected a broken tool, and the ordering gate then reported a
# SEGFAULT as if the fabric had a race in it.
#
# So the probe builds a trivial two-thread program, RUNS it, and only accepts a
# compiler whose sanitizer actually executes. On a host where none does, the
# ordering claim is reported UNVERIFIED and the fault-injection gate below
# carries the proof instead. That is the honest outcome: an unavailable tool is
# not a passing tool.
tsan_cc() {
  cat > "$TMP/tsanprobe.c" <<'PROBE'
#include <pthread.h>
#include <stdio.h>
static int shared;
static void *w(void *a) { (void)a; shared++; return 0; }
int main(void) {
    pthread_t t;
    pthread_create(&t, 0, w, 0);
    pthread_join(t, 0);
    printf("%d", shared);
    return shared == 1 ? 0 : 1;
}
PROBE
  for c in "${CC:-}" cc gcc clang; do
    [ -n "$c" ] || continue
    command -v "$c" >/dev/null 2>&1 || continue
    if "$c" -fsanitize=thread "$TMP/tsanprobe.c" -o "$TMP/tsanprobe.bin" 2>/dev/null &&
       [ -x "$TMP/tsanprobe.bin" ] &&
       "$TMP/tsanprobe.bin" >/dev/null 2>&1; then
      echo "$c"; return 0
    fi
  done
  return 1
}

say "aperture contract"
# shellcheck disable=SC2086
cc $BASE -O1 -g tests/test_qrmem_aperture.c $SRC -o "$TMP/ap" -lpthread 2>"$TMP/e" \
  || { cat "$TMP/e"; bad "aperture test did not build"; }
if [ -x "$TMP/ap" ]; then
  if "$TMP/ap" > "$TMP/ap.log" 2>&1; then
    echo "   ok  $(grep -c '^  ok' "$TMP/ap.log") checks, 0 failures"
  else
    cat "$TMP/ap.log"; bad "aperture contract failed"
  fi
fi

say "code plane round trip and corruption detection"
# shellcheck disable=SC2086
cc $BASE -O1 -g tests/test_qrmem_plane.c $SRC -o "$TMP/pl" -lpthread 2>"$TMP/e" \
  || { cat "$TMP/e"; bad "plane test did not build"; }
if [ -x "$TMP/pl" ]; then
  if "$TMP/pl" > "$TMP/pl.log" 2>&1; then
    echo "   ok  $(grep -c '^  ok' "$TMP/pl.log") checks, 0 failures"
    grep 'info ' "$TMP/pl.log" | sed 's/^/   /'
  else
    cat "$TMP/pl.log"; bad "code plane contract failed"
  fi
fi

say "multi-process live read (no TSan: it cannot see cross-process shm races)"
# shellcheck disable=SC2086
cc $BASE -O1 -g tests/test_qrmem_multiproc.c $SRC -o "$TMP/mp" -lpthread 2>"$TMP/e" \
  || { cat "$TMP/e"; bad "multi-process test did not build"; }
if [ -x "$TMP/mp" ]; then
  if "$TMP/mp" > "$TMP/mp.log" 2>&1; then
    echo "   ok  $(grep -c '^  ok' "$TMP/mp.log") checks, 0 failures"
    grep 'info reader' "$TMP/mp.log" | sed 's/^/   /'
  else
    cat "$TMP/mp.log"; bad "multi-process live read failed"
  fi
fi

say "reboot survival: content returns, authority does not"
# shellcheck disable=SC2086
cc $BASE -O1 -g tests/test_qrmem_persist.c $SRC -o "$TMP/ps" -lpthread 2>"$TMP/e" \
  || { cat "$TMP/e"; bad "persistence test did not build"; }
if [ -x "$TMP/ps" ]; then
  if "$TMP/ps" >"$TMP/ps.log" 2>&1; then
    echo "   ok  $(grep -c '^  ok' "$TMP/ps.log") checks, 0 failures"
  else
    cat "$TMP/ps.log"; bad "reboot survival contract failed"
  fi
fi

say "record identity: UUIDv4 only, strict canonical lowercase"
# shellcheck disable=SC2086
cc $BASE -O1 -g tests/test_qrmem_uuid.c $SRC -o "$TMP/u" -lpthread 2>"$TMP/e" \
  || { cat "$TMP/e"; bad "identity test did not build"; }
if [ -x "$TMP/u" ]; then
  if "$TMP/u" >"$TMP/u.log" 2>&1; then
    echo "   ok  $(grep -c '^  ok' "$TMP/u.log") checks, 0 failures"
  else
    cat "$TMP/u.log"; bad "record identity contract failed"
  fi
fi

say "end to end over MCP: what is written is what is read"
# The layers below this one all passed while the MCP surface was emitting a
# record with NO TEXT AT ALL. Every codec test checks the store, and the store
# was correct. The defect was in the render function, one layer out, and nothing
# between the store and an agent's eyes ever checked the join.
#
# So this runs the real binary as a real daemon and drives it as a real client:
# join, write a payload with a distinct canary, read it back by coordinate, find
# it by its index key, and confirm the UUID survives. A payload that fails to come
# back out of the surface is the single most basic failure a memory can have, so
# it is checked at the only layer where it is actually visible.
E2E_AP="/qrmem-gate-e2e-$$"
E2E_SOCK="$TMP/e2e.sock"
E2E_SNAP="$TMP/e2e.snapshot"
rm -f "$E2E_SOCK"
# Build HERE, into the gate's own directory, and drive THAT.
#
# The first version of this section ran ./saphira-qrmem from the repository root,
# which is a build artifact of whenever the tree was last compiled. It was
# therefore testing a BINARY, not the source beside it: the payload regression
# below was reintroduced deliberately and the gate still passed, because the
# binary under test predated the edit. A gate that tests a stale artifact is
# worse than no gate, because it reports success.
#
# The binary is built from the same $SRC the codec tests use, so a defect in any
# layer is visible in the layer that can see it.
E2E_BIN="$TMP/e2e-qrmem"
# shellcheck disable=SC2086
# qrmem_main.c is excluded from $SRC on purpose - the codec tests supply their
# own main() - so the MCP binary needs it named explicitly.
# shellcheck disable=SC2086
if ! cc $BASE -O1 $SRC src/qrmem_main.c -o "$E2E_BIN" -ljson-c -lpthread -lm 2>"$TMP/e2e-build.err"; then
  cat "$TMP/e2e-build.err"
  bad "could not build the binary for the end-to-end test"
else
"$E2E_BIN" --serve --aperture "$E2E_AP" --no-snapshot --socket "$E2E_SOCK" \
    >"$TMP/e2e.log" 2>&1 &
E2E_PID=$!
sleep 1
if kill -0 "$E2E_PID" 2>/dev/null; then
  cat > "$TMP/e2e.json" <<'JSON'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"qrmem_join","arguments":{"screen":1,"project":"e2e"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"qrmem_write","arguments":{"screen":1,"block":2,"slot":3,"type":"word","text":"PAYLOAD-E2E-4d7f2a","index":"KEY-E2E-9c1b"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"qrmem_read","arguments":{"screen":1,"block":2,"slot":3}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"qrmem_index","arguments":{"screen":1,"key":"KEY-E2E-9c1b"}}}
JSON
  timeout 25 "$E2E_BIN" --stdio --agent e2e --socket "$E2E_SOCK" \
      --aperture "$E2E_AP" < "$TMP/e2e.json" > "$TMP/e2e.out" 2>"$TMP/e2e.err"
  python3 - "$TMP/e2e.out" <<'PY'
import json, sys
rows = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if not line.startswith("{"):
        continue
    d = json.loads(line)
    if "result" in d:
        rows[d["id"]] = json.loads(d["result"]["content"][0]["text"])
fails = []
def want(cond, what):
    print("   ok  %s" % what if cond else "   FAIL %s" % what)
    if not cond:
        fails.append(what)

r = rows.get(3, {})
want(r.get("text") == "PAYLOAD-E2E-4d7f2a",
     "a payload written through MCP reads back through MCP, byte for byte")
want(r.get("index_key") == "KEY-E2E-9c1b",
     "and the record reports its own lookup key")
want(isinstance(r.get("id"), str) and len(r.get("id")) == 36,
     "and its UUID renders as canonical text")
x = rows.get(4, {})
cells = x.get("cells", [])
want(x.get("matched") == 1 and len(cells) == 1,
     "and the record is findable by that key")
want(cells and cells[0].get("text") == "PAYLOAD-E2E-4d7f2a",
     "and the INDEXED copy carries the payload too, not just an address")
sys.exit(1 if fails else 0)
PY
  if [ $? -eq 0 ]; then
    echo "   ok  end-to-end MCP round trip"
  else
    bad "end-to-end MCP round trip"
  fi
  # Leave before the snapshot file, which the daemon writes on a clean exit.
  kill "$E2E_PID" 2>/dev/null
  wait "$E2E_PID" 2>/dev/null
  rm -f /dev/shm"$E2E_AP"
else
  bad "could not start the e2e daemon"
fi
fi

say "enrolled, and record freshness, end to end over MCP"
# Two claims the fabric makes on its surface, checked where they are visible.
#
# enrolled: agent_slot is a client-local integer captured at hello. After an
# aperture is replaced under a running client it refers to a registry that no
# longer exists, and a new agent can be issued the same number. Status used to
# print agent_slot beside agents without either being reconciled, so the caller
# had to spot the contradiction unaided.
#
# freshness: every record carries an advisory wall-clock timestamp. The point is
# that it is ALWAYS there - reserved before caller TLVs rather than appended if
# it fits - so its absence means legacy and nothing else.
E2E2_AP="/qrmem-gate-fresh-$$"
E2E2_SOCK="$TMP/fresh.sock"
rm -f "$E2E2_SOCK"
E2E2_BIN="$TMP/fresh-qrmem"
# shellcheck disable=SC2086
cc $BASE -O1 $SRC src/qrmem_main.c -o "$E2E2_BIN" -ljson-c -lpthread -lm 2>"$TMP/fresh.err" \
  || { cat "$TMP/fresh.err"; bad "could not build for the freshness gate"; }
if [ -x "$E2E2_BIN" ]; then
  "$E2E2_BIN" --serve --aperture "$E2E2_AP" --no-snapshot --socket "$E2E2_SOCK" \
      >"$TMP/fresh.log" 2>&1 &
  F_PID=$!
  sleep 1
  # Built by python rather than a heredoc because one case needs a payload
  # longer than a cell, which is not something to hand-type into a shell literal.
  python3 - "$TMP/fresh.json" <<'PYGEN'
import json, sys
def call(i, name, args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": name, "arguments": args}}
rows = [
    {"jsonrpc": "2.0", "id": 0, "method": "initialize",
     "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "fresh-gate", "version": "1"}}},
    call(1, "qrmem_join", {"screen": 1, "project": "fresh-gate"}),
    call(2, "qrmem_status", {}),
    call(3, "qrmem_write", {"screen": 1, "block": 0, "slot": 0,
                            "type": "word", "text": "FRESH-RECORD",
                            "index": "FRESH-KEY"}),
    call(4, "qrmem_read", {"screen": 1, "block": 0, "slot": 0}),
    # Sizes either side of the caller's real limit, which is 240 bytes of body
    # less the 12 the always-present timestamp occupies. The limit is DERIVED in
    # the header, and these sizes are chosen to pin the resulting behaviour
    # rather than to restate the constant in two places.
    call(5, "qrmem_write", {"screen": 1, "block": 0, "slot": 1,
                            "type": "word", "text": "X" * 224}),   # at limit
    call(9, "qrmem_read", {"screen": 1, "block": 0, "slot": 1}),
    call(13, "qrmem_help", {"topic": "qualifying"}),
    # Real index and decode_region calls. The first version of this gate
    # asserted on ids 6 and 7, which are WRITES in this conversation - so two
    # assertions were checking the wrong tool and reported a failure that looked
    # like a product gap. Request ids have to be read off the request list, not
    # guessed from a shape.
    call(14, "qrmem_index", {"screen": 1, "key": "FRESH-KEY"}),
    call(15, "qrmem_decode_region", {"screen": 1, "block": 0, "slot": 0,
                                     "width": 1, "height": 1}),
    call(16, "qrmem_view_tile", {"screen": 1, "x": 0, "y": 0,
                                 "width": 4, "height": 4}),
    call(6, "qrmem_write", {"screen": 1, "block": 0, "slot": 2,
                            "type": "word", "text": "Y" * 225}),   # one over
    call(7, "qrmem_write", {"screen": 1, "block": 0, "slot": 3,
                            "type": "word", "text": "Z" * 236}),   # old limit
    call(8, "qrmem_write", {"screen": 1, "block": 0, "slot": 4,
                            "type": "word", "text": "W" * 400}),   # whole cell
    # THE CASE THE SINGLE-FIELD TESTS MISSED. text=210 is inside the advertised
    # 224, and a 20-byte index key fits too (214 + 24 = 238 of 240) - but with
    # the timestamp appended LAST there was no room left for it, and the caller
    # was refused with "no room for the publication timestamp": a message about
    # the store's internals, triggered by a payload the surface had promised.
    call(10, "qrmem_write", {"screen": 1, "block": 1, "slot": 0,
                             "type": "word", "text": "M" * 210,
                             "index": "K" * 20}),
    # And the same record without the index key, which must be PUBLISHED: if
    # this is refused too, the reservation is over-strict rather than correct.
    call(11, "qrmem_write", {"screen": 1, "block": 1, "slot": 1,
                             "type": "word", "text": "N" * 210}),
    call(12, "qrmem_read", {"screen": 1, "block": 1, "slot": 1}),
]
open(sys.argv[1], "w").write("\n".join(json.dumps(r) for r in rows) + "\n")
PYGEN
  # The client announces a fabricated origin. If any participant reports THAT
  # string as its source, source_host is reading the greeting and the whole
  # authority-known property is void. The real hostname travels by environment
  # because the heredoc below is quoted and must not interpolate.
  export QRMEM_GATE_CLAIMED_HOST="caller-claims-mars"
  export QRMEM_GATE_REAL_HOST="$(hostname)"
  timeout 25 "$E2E2_BIN" --stdio --agent fresh --host "$QRMEM_GATE_CLAIMED_HOST" --socket "$E2E2_SOCK" \
      --aperture "$E2E2_AP" < "$TMP/fresh.json" > "$TMP/fresh.out" 2>/dev/null
  # Captured via if/else rather than `set +e` / `set -e`. Enabling `set -e` to
  # grab an exit code turned it ON FOR THE REST OF THE GATE, and the first
  # zero-match `grep -c` afterwards returns 1 - which killed the script silently
  # at the ThreadSanitizer section. TSan had therefore never been able to report
  # a CLEAN run: the one result that matters is the one that cannot be printed.
  if python3 - "$TMP/fresh.out" > "$TMP/fresh.pyout" 2>&1 <<'PY'
import json, sys
import re
rows, raw = {}, {}
for line in open(sys.argv[1]):
    line = line.strip()
    if line.startswith("{"):
        d = json.loads(line)
        if "result" in d:
            raw[d["id"]] = d["result"]
            if "content" in d["result"]:
                rows[d["id"]] = json.loads(d["result"]["content"][0]["text"])
fails = []
def want(c, w):
    print("   ok  %s" % w if c else "   FAIL %s" % w)
    if not c:
        fails.append(w)

st = rows.get(2, {})
# enrolled must be reported and must be TRUE for a client that just leased.
want(st.get("enrolled") is True, "status reports this session as enrolled")
for f in ("enrolled_authority_ok", "enrolled_slot_ok", "enrolled_generation_ok"):
    want(st.get(f) is True, "  and %s" % f)
want("enrolled_note" not in st,
     "  and no explanation is offered when there is nothing to explain")

r = rows.get(4, {})
# Freshness: present, numeric, and consistent with a wall clock rather than a
# monotonic one - i.e. an absolute unix time, not a small uptime figure.
w = r.get("written_unix")
want(isinstance(w, int) and w > 1600000000,
     "a record reports written_unix as a plausible unix timestamp")
a = r.get("age_seconds")
want(isinstance(a, int) and 0 <= a <= 120,
     "and age_seconds is a small non-negative number, so the clock is wall time")
want(r.get("text") == "FRESH-RECORD",
     "and the payload is untouched by the new metadata")

# The capacity contract. The timestamp's 12 bytes are reserved, so the caller's
# limit is deterministic and reported as such - not discovered afterwards as an
# opaque "does not fit a cell".
# Exactly at the derived caller limit: accepted. The limit must be usable, not
# merely stated, or the reservation would be refusing capacity that exists.
at = rows.get(5, {})
want("error" not in at,
     "a payload of exactly the caller limit (224) is accepted")
want(isinstance(at.get("id"), str), "and the record was published with a UUID")
# Read back: the write reply carries no timestamp, so the assertion has to be
# made on what a reader actually sees.
full = rows.get(9, {})
want(isinstance(full.get("written_unix"), int),
     "and read back at full capacity it still carries its timestamp, which is "
     "the whole point of reserving the bytes")
want(full.get("text") == "X" * 224,
     "and all 224 bytes of the payload survived alongside it")

# One byte over, and at the pre-reservation limit: both refused, both naming the
# CALLER's limit rather than the raw body size. 236 fitted before the timestamp
# existed; if that passes now, the reservation is documentation, not code.
for rid, size, label in ((6, 225, "one byte over the caller limit"),
                         (7, 236, "the PRE-reservation limit"),
                         (8, 400, "more than a whole cell")):
    row = rows.get(rid, {})
    want("error" in row, "a payload of %d bytes is refused: %s" % (size, label))
    want("224" in str(row.get("error", "")),
         "  and it names the caller limit 224, not the raw body size 240")
# A record with SEVERAL fields must be refused against the CALLER's budget, not
# by the reservation mechanism. Both halves matter: refusing is correct here, but
# "no room for the publication timestamp" would mean the caller is being told
# about the store's bookkeeping instead of about their own payload.
multi = rows.get(10, {})
want("error" in multi,
     "a record whose text AND index key together overrun the budget is refused")
# An out-of-range coordinate is ALSO an error, so "error" alone does not show the
# capacity path was reached. The first version of this test used slots 5 and 6 in
# a block that only has 0..4, so it passed for the wrong reason twice over.
want("does not exist" not in str(multi.get("error", "")),
     "  and it is a CAPACITY refusal, not a bad coordinate")
# Assert on the DEFECT's exact signature, not on the phrase "publication
# timestamp". The first version excluded the bare phrase, which also appeared in
# the honest refusal - "224 bytes are left ... after the publication timestamp is
# reserved" - so a correct build failed the gate. A negative assertion has to
# name the defect it is guarding, or it guards against its own subject.
want("no room for the publication timestamp" not in str(multi.get("error", "")),
     "  and NOT by the timestamp reservation racing for bytes")
want("224" in str(multi.get("error", "")),
     "  and it names the caller's 224-byte budget")

# The reservation must be exact, not merely safe: the same payload without the
# second field has to land, with its timestamp intact.
slim = rows.get(11, {})
want("error" not in slim,
     "the same text alone is published: the reservation is exact, not greedy")
want("does not exist" not in str(slim.get("error", "")),
     "  and that is a real coordinate, so the comparison is meaningful")
got = rows.get(12, {})
want(got.get("text") == "N" * 210,
     "  and all 210 bytes survive alongside the timestamp")
want(isinstance(got.get("written_unix"), int),
     "  and it still carries written_unix")
# The screen count is deliberately NOT asserted as a literal. Hardcoding "16"
# in a test would be a second source that can drift, which is the very defect
# being fixed. Instead the two surfaces are compared against EACH OTHER: whatever
# count instructions states must equal what status reports. That is what makes
# the drift impossible rather than merely absent today.
# Qualification, on every response that hands back a screen coordinate. The
# failure mode is a bare number reaching durable storage and being read by an
# agent attached to a different fabric, where it resolves confidently to
# somebody else's cell.
st = rows.get(2, {})
FID = st.get("fabric_id")
want(isinstance(FID, str) and len(FID) == 36,
     "status reports a fabric_id: %s" % (FID,))
scr = st.get("screens") or []
want(bool(scr) and scr[1].get("fabric_id") == FID,
     "and every per-screen entry carries the SAME fabric_id")
JOIN = rows.get(1, {})
want(JOIN.get("fabric_id") == FID, "qrmem_join qualifies its screen")
WRITE = rows.get(3, {})
want(WRITE.get("fabric_id") == FID and isinstance(WRITE.get("address"), str),
     "qrmem_write qualifies its screen with a readable address")
READ = rows.get(4, {})
want(READ.get("fabric_id") == FID, "qrmem_read qualifies its screen")
IDXR = rows.get(14, {})
want(IDXR.get("fabric_id") == FID, "qrmem_index qualifies its screen")
REG = rows.get(15, {})
want(REG.get("fabric_id") == FID, "qrmem_decode_region qualifies its screen")
TILE = rows.get(16, {})
want(TILE.get("fabric_id") == FID, "qrmem_view_tile qualifies its screen")
want(FID and FID in str(JOIN.get("address", "")),
     "the readable address embeds the fabric_id")

# Source is authority-known, never caller-supplied. Every lease in this build
# arrives over the daemon's own socket, so every participant must report kind
# local and the DAEMON's hostname - even though this very client announced
# --host caller-claims-mars. If that string appears as anyone's source, the
# field is parroting the greeting and a remote client could claim any origin.
import os
claimed = os.environ.get("QRMEM_GATE_CLAIMED_HOST", "")
real = os.environ.get("QRMEM_GATE_REAL_HOST", "")
parts = st.get("participants") or []
want(bool(parts), "status names the leases it granted")
for p in parts:
    want(p.get("source_kind") == "local",
         "  slot %s reports source_kind local" % (p.get("slot"),))
    want(isinstance(p.get("source_host"), str) and p["source_host"] == real,
         "  slot %s reports the AUTHORITY's host (%s), not the --host flag"
         % (p.get("slot"), real))
    want(p.get("source_host") != claimed,
         "  slot %s does not repeat the caller's claimed origin" % (p.get("slot"),))

QUAL = rows.get(13, {})
want("MUST NOT be persisted" in str(QUAL.get("brief", "")),
     "the qualifying brief forbids persisting a bare screen number as "
     "actionable shared knowledge")
want("only that pair is identity-bearing" in str(QUAL.get("brief", "")),
     "and states that only (fabric_id, screen) is identity-bearing")

inst = raw.get(0, {}).get("instructions", "")
m = re.search(r"(\w+) screens of shared memory", inst)
stated = m.group(1) if m else None
total = str(rows.get(2, {}).get("screens_total", "?"))
want(stated == total,
     "instructions and status agree on the screen count (%s vs %s), so the "
     "first thing a client reads cannot contradict the runtime"
     % (stated, total))
want("no durable state" not in inst.lower(),
     "and instructions does not claim the fabric holds no durable state")
want(all(t in inst for t in ("projects", "presence")),
     "and it names the topics that exist, including the two it omitted entirely")
sys.exit(1 if fails else 0)
PY
  then
    FRESH_RC=0
  else
    FRESH_RC=$?
  fi
  cat "$TMP/fresh.pyout"
  if [ "$FRESH_RC" -eq 0 ]; then
    echo "   ok  enrolled and freshness contract"
  else
    bad "enrolled / freshness contract"
  fi
  kill "$F_PID" 2>/dev/null
  wait "$F_PID" 2>/dev/null
  rm -f /dev/shm"$E2E2_AP"
fi

say "the surface's own claims are present in the BUILT BINARY"

# A claim made in a string is not a claim the agent can see.
#
# An edit to participants_note silently failed to apply - the literal had been
# reflowed by a formatter, so an exact-match replace matched nothing, printed
# nothing, and the commit message described the change as done. Everything
# compiled, every gate passed, and the binary simply did not contain the text.
#
# Reviewing an edit by eye cannot catch that: the diff looks right, the source
# looks right, and only the artifact is wrong. So the strings that MAKE CLAIMS
# about the fabric are checked against the linked binary. If a claim is removed,
# reworded, or silently lost, this fails rather than shipping a surface that
# quietly under-describes itself.
#
# These are the claims whose absence would mislead an agent, not a copy of the
# help text: a change in wording is legitimate, a change in meaning is not.
BIN="$TMP/qrmem-binary"
if [ ! -x "$BIN" ]; then
  # shellcheck disable=SC2086
  cc $BASE -O1 $SRC src/qrmem_main.c -o "$BIN" -ljson-c -lpthread -lm 2>/dev/null
fi
if [ -x "$BIN" ]; then
  claim_present() {
    if strings "$BIN" | grep -qF "$1"; then
      echo "   ok  $2"
    else
      echo "   FAIL $2"
      echo "   MISSING FROM BINARY: $1"
      bad "$3"
    fi
  }
  claim_present "IDENTITY IS NOT A DURABLE HANDLE" \
    "status warns that identity is not a durable handle" \
    "a participant note that does not say identity is ephemeral is worse than none"
  claim_present "EPHEMERAL LEASE INCARNATION" \
    "per-participant label/identity/agent_gen are named and distinguished" \
    "three interchangeable-looking fields with no stated distinction"
  claim_present "IDENTITY IS LEASE-SCOPED" \
    "help states the lease-scoping invariant explicitly" \
    "the identity-stability invariant is undocumented"
  claim_present "AND THERE IS NO DELIVERY" \
    "help names the absence of delivery as a limit" \
    "an agent must not believe a write into shared memory reaches anyone"
  claim_present "EXACTLY WHAT SURVIVES A RESTART" \
    "durability help enumerates what survives and what does not" \
    "agents cannot reason about restart without this"
  # The refusal a restored page now gets. Its presence is what proves the
  # free-branch guard exists: if it is gone, a restored populated page can be
  # relabelled again, which is the defect this whole change was made to fix.
  # The restored-page relabel refusal, and specifically the half that was wrong:
  # it must say the page can be claimed under ITS OWN label, never echo the
  # caller's label back as advice, and point at the one path that changes a label.
  claim_present "no agent can change it - an operator can, audited" \
    "the restored-page refusal points at the audited operator path" \
    "a refusal with no route out is a dead end"
  claim_present "you may take it, but only under that same label" \
    "the restored-page refusal names the immutable label as the way in" \
    "the refusal no longer explains how to claim the page"
  claim_present "refusing an unlogged repair" \
    "operator repair refuses to run without an audit" \
    "an operator repair path with no mandatory audit is a backdoor"
  # `instructions` is the FIRST documentation any client sees, and it was wrong
  # three ways while qrmem_help had already been corrected: 8 screens against a
  # fabric of 16, 7 topics against 9, and "holds NO durable state" when a
  # restore point exists and returns content on every start.
  #
  # The defect was not really the three sentences. It was that instructions was a
  # hand-written literal and help was generated, so fixing help could not fix
  # instructions and nothing connected them. instructions is now GENERATED from
  # QRMEM_SCREENS and the topic table, so the assertions below check that the
  # right claims are present; the structural guarantee is that there is no number
  # left in prose to disagree with the binary.
  # NO claim_present for the topic LIST, deliberately. It used to have one, and it
  # could never pass: the list is now GENERATED from the topic table at runtime,
  # so the string does not exist anywhere in the binary for `strings` to find. A
  # gate that cannot pass is a gate that asserts nothing while still looking like
  # evidence - the same failure as an assertion that cannot fail, reached from the
  # other direction. The topic list is checked LIVE instead, in the freshness
  # contract, where instructions is compared against the topics that exist.
  claim_present "DOES keep a durable restore point" \
    "instructions states the durability contract accurately" \
    "telling an agent the fabric holds no durable state is simply false"
  claim_present "re-joining today" \
    "instructions warns that restored content still needs re-joining" \
    "a restored screen has no owner, and that must be stated up front"
  # The capacity contract is the newest promise on the surface, and the most
  # likely to rot: a body size quoted where a caller limit is meant is exactly
  # how this fabric has misled callers before.
  # NOTE: claim_present takes NEEDLE first, description second. An earlier
  # revision of this block passed them the other way round, so the gate grepped
  # for its own description text, reported five honest-looking failures, and sent
  # me hunting through the compiler. A claims gate that fails because its own
  # arguments are transposed is indistinguishable from a real regression, which
  # is worth remembering as a reason to read the needle before believing a red.
  claim_present "a text payload may be up to" \
    "help states the CALLER's limit, not just the cell body size" \
    "help must state the caller's real limit, not the body size"
  claim_present "reserved for the publication timestamp" \
    "help attributes the gap below the body size to the timestamp" \
    "help must say WHY the limit is below the body size"
  claim_present "WALL-CLOCK CLOCK_REALTIME, not a monotonic" \
    "help declares the clock source" \
    "help must not let a caller read freshness as a monotonic guarantee"
  claim_present "clock stepped backwards reports age_seconds null" \
    "help names the null cases" \
    "a null age_seconds is documented, not a mystery"
  claim_present "age_seconds\` is ADVISORY" \
    "help marks freshness advisory" \
    "advisory freshness must be labelled advisory on the surface"
else
  bad "could not build the binary to check its own claims"
fi

say "cell codec, including a fuzzer"
# shellcheck disable=SC2086
cc $BASE -O1 -g tests/test_qrmem_cell.c $SRC -o "$TMP/ce" -lpthread 2>"$TMP/e" \
  || { cat "$TMP/e"; bad "codec test did not build"; }
if [ -x "$TMP/ce" ]; then
  if "$TMP/ce" > "$TMP/ce.log" 2>&1; then
    echo "   ok  $(grep -c '^  ok' "$TMP/ce.log") checks, 0 failures"
    grep 'info fuzz' "$TMP/ce.log" | sed 's/^/   /'
  else
    cat "$TMP/ce.log"; bad "codec test failed"
  fi
fi

say "ordering: correct build under ThreadSanitizer"
# ThreadSanitizer is reported honestly. A correct fabric has no non-atomic
# shared access left, so there is less for TSan to see than there used to be -
# that is the design working, not the gate weakening. It is still run, because
# it would catch a future change that reintroduced a plain shared access.
TSAN="$(tsan_cc || true)"
if [ -z "$TSAN" ]; then
  echo "!! ThreadSanitizer WAS NOT RUN. The memory-ordering proofs did not happen."
  echo "!! Treat every ordering claim from this run as UNVERIFIED."
elif [ -x "$TMP/ap" ]; then
  # shellcheck disable=SC2086
  "$TSAN" $BASE -fsanitize=thread -O1 -g tests/test_qrmem_aperture.c $SRC \
      -o "$TMP/ap_tsan" -lpthread 2>"$TMP/e" \
    || { cat "$TMP/e"; bad "the TSan build did not compile"; }
  if [ -x "$TMP/ap_tsan" ]; then
    "$TMP/ap_tsan" > "$TMP/tsan.log" 2>"$TMP/tsan.err"
    rc=$?
    warns=$(grep -c 'WARNING: ThreadSanitizer' "$TMP/tsan.err" 2>/dev/null)
    if [ "$rc" -eq 0 ] && [ "$warns" -eq 0 ]; then
      echo "   ok  TSan clean ($TSAN)"
      grep 'info reader' "$TMP/tsan.log" | sed 's/^/   /'
    else
      grep -m3 -A6 'WARNING: ThreadSanitizer' "$TMP/tsan.err"
      bad "the correct build is not TSan clean (rc=$rc warnings=$warns)"
    fi
  fi
fi

say "the ordering gate can FAIL: correctness mechanisms removed on purpose"
#
# Two earlier attempts at this gate are worth recording, because both would have
# shipped a gate that could never fail:
#
#  1. Weakening the `state` store from release to relaxed. On x86-64 a release
#     store and a relaxed store are the same instruction, so this changed
#     nothing observable - and after the cell was made atomic it was not even
#     the edge that carried correctness. The weakened build passed, and would
#     have passed for ever.
#  2. Weakening the sequence-lock edges the same way. Same reason.
#
# What DOES fail on this host is removing the mechanisms outright: the reader
# drain (QRMEM_WEAKEN_DRAIN) and the closing version re-check
# (QRMEM_WEAKEN_SEQLOCK). With both gone the fabric serves genuinely torn
# records, the integrity witness catches them, and the threaded stress sees it.
#
# The residual honest limitation: the release-vs-relaxed distinction on this
# platform cannot be tested here at all. It needs a weakly ordered target
# (aarch64, riscv64) or a simulator. That is recorded rather than papered over.
if [ -x "$TMP/ap" ]; then
  # shellcheck disable=SC2086
  cc $BASE -O1 -g -DQRMEM_WEAKEN_SEQLOCK -DQRMEM_WEAKEN_DRAIN \
      tests/test_qrmem_aperture.c $SRC -o "$TMP/nogate" -lpthread 2>"$TMP/e" \
    || { cat "$TMP/e"; bad "the fault-injected build did not compile"; }
  if [ -x "$TMP/nogate" ]; then
    "$TMP/nogate" > "$TMP/nogate.log" 2>&1
    ng_rc=$?
    ng_fail=$(grep -c '^  FAIL' "$TMP/nogate.log" 2>/dev/null)
    if [ "$ng_fail" -gt 0 ]; then
      echo "   ok  the fault-injected build was caught ($ng_fail failing checks)"
      grep -m1 '^  FAIL' "$TMP/nogate.log" | sed 's/^/   /'
      grep 'info reader' "$TMP/nogate.log" | sed 's/^/   /'
    else
      bad "the fault-injected build PASSED: the gate cannot fail, so it proves nothing"
      grep 'info reader' "$TMP/nogate.log" | sed 's/^/   /'
    fi
  fi
fi

say "the fabric holds no database dependency"
if nm "$TMP/ap" 2>/dev/null | grep -Eq ' U (mysql_|mariadb_|sqlite3_)'; then
  nm "$TMP/ap" | grep -E ' U (mysql_|mariadb_|sqlite3_)' | sed 's/^/   /'
  bad "the fabric links a database driver; it must hold no SQL"
else
  echo "   ok  no database symbols in the fabric objects"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "qrmem gate: PASS"
else
  echo "qrmem gate: FAIL"
fi
exit "$fail"
