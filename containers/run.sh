#!/bin/sh
# Container scenarios: builds lootr-base and the scenario images, runs lootr
# in each scenario container (as the scenario's user, without network),
# normalizes the JSON report and compares it with the scenario's
# expected.json. Removed before comparing: timestamps, duration, version and
# the attributes `age_days`, `expires_in_hours`, `expires_in_days` (clock) and
# `size` (generated keys differ in size by a few bytes). Fails if the canary
# string shows up in stdout or stderr.
#
# Every scenario also runs in the other output modes (SARIF, Markdown,
# --redact-paths, --summary-only): same exit code, a non-empty report
# without the canary, valid SARIF structure (jq), and no home directory in
# redacted output.
#
# Usage: containers/run.sh [--update] [scenario...]
#   --update     rewrite expected.json from the actual results
#   scenario     names under containers/scenarios/ (default: all)
#
# Scenario images are built with the repository root as build context (so
# they can COPY e.g. examples/); .dockerignore keeps target/ out.
#
# Works with podman or docker (auto-detected; override with
# LOOTR_CONTAINER_ENGINE=docker). Exit code 0 if every scenario passed.

set -eu

cd "$(dirname "$0")/.."

engine=${LOOTR_CONTAINER_ENGINE:-}
if [ -z "$engine" ]; then
    if command -v podman >/dev/null 2>&1; then
        engine=podman
    elif command -v docker >/dev/null 2>&1; then
        engine=docker
    else
        echo "error: neither podman nor docker found" >&2
        exit 2
    fi
fi

update=false
if [ "${1:-}" = "--update" ]; then
    update=true
    shift
fi
if [ $# -eq 0 ]; then
    set -- $(ls containers/scenarios)
fi

# Must match lootr::testing::CANARY.
canary=LOOTRCANARY

echo "==> building lootr-base with $engine"
"$engine" build -q -t lootr-base -f containers/base/Containerfile . >/dev/null

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Runs jq from lootr-base on stdin.
jq_in() {
    "$engine" run --rm -i --network=none --entrypoint jq lootr-base "$@"
}

# Output modes checked besides the JSON report (one per line).
modes="--format sarif
--format sarif --redact-paths
--format sarif --summary-only
--format markdown
--format markdown --redact-paths --summary-only
--format json --redact-paths
--format json --summary-only"

# check_mode <scenario> <image> <expected exit code> <args...>
check_mode() {
    scenario=$1 image=$2 want=$3
    shift 3
    code=0
    "$engine" run --rm --network=none "$image" "$@" >"$tmp/mode.out" 2>"$tmp/mode.err" || code=$?
    if [ "$code" != "$want" ]; then
        cat "$tmp/mode.err"
        echo "FAIL $scenario ($*): exit code $code, expected $want"
        return 1
    fi
    if [ ! -s "$tmp/mode.out" ]; then
        cat "$tmp/mode.err"
        echo "FAIL $scenario ($*): empty report"
        return 1
    fi
    if grep -q "$canary" "$tmp/mode.out" "$tmp/mode.err"; then
        echo "FAIL $scenario ($*): canary found in the output"
        return 1
    fi
    case " $* " in
    *" --redact-paths "*)
        if grep -Eq '/home/|/root/|"/root"' "$tmp/mode.out" "$tmp/mode.err"; then
            grep -En '/home/|/root' "$tmp/mode.out" "$tmp/mode.err" | head -5
            echo "FAIL $scenario ($*): a home directory in redacted output"
            return 1
        fi
        ;;
    esac
    case " $* " in
    *" sarif "*)
        if ! jq_in -e '.version == "2.1.0" and (.runs | length) == 1
            and (.runs[0].tool.driver.rules | type) == "array"
            and ([.runs[0].results[]? | select(.ruleIndex == null or .message.text == null)] | length) == 0' \
            <"$tmp/mode.out" >/dev/null 2>&1; then
            echo "FAIL $scenario ($*): not a valid SARIF log"
            return 1
        fi
        ;;
    *" markdown "*)
        if ! head -1 "$tmp/mode.out" | grep -q '^## lootr report$'; then
            echo "FAIL $scenario ($*): not a Markdown report"
            return 1
        fi
        ;;
    *)
        if ! jq_in -e '.schema_version == 1' <"$tmp/mode.out" >/dev/null 2>&1; then
            echo "FAIL $scenario ($*): not a JSON report"
            return 1
        fi
        ;;
    esac
}

failed=""
for scenario in "$@"; do
    dir=containers/scenarios/$scenario
    if [ ! -f "$dir/Containerfile" ]; then
        echo "FAIL $scenario: no $dir/Containerfile"
        failed="$failed $scenario"
        continue
    fi
    image=lootr-scenario-$scenario
    if ! "$engine" build -q -t "$image" -f "$dir/Containerfile" . >"$tmp/build.txt" 2>&1; then
        cat "$tmp/build.txt"
        echo "FAIL $scenario: image build failed"
        failed="$failed $scenario"
        continue
    fi

    code=0
    "$engine" run --rm --network=none "$image" >"$tmp/out.json" 2>"$tmp/err.txt" || code=$?

    if [ ! -s "$tmp/out.json" ]; then
        cat "$tmp/err.txt"
        echo "FAIL $scenario: empty report (exit code $code)"
        failed="$failed $scenario"
        continue
    fi

    if grep -q "$canary" "$tmp/out.json" "$tmp/err.txt"; then
        echo "FAIL $scenario: canary found in the output"
        failed="$failed $scenario"
        continue
    fi

    if ! jq_in -S --argjson code "$code" \
        '{exit_code: $code, report: (del(.run.started_at, .run.duration_ms, .tool.version)
          | walk(if type == "object" then del(.age_days, .expires_in_hours, .expires_in_days, .size) else . end))}' \
        <"$tmp/out.json" >"$tmp/actual.json" 2>"$tmp/jq.txt"; then
        cat "$tmp/err.txt" "$tmp/jq.txt"
        echo "FAIL $scenario: no JSON report (exit code $code)"
        failed="$failed $scenario"
        continue
    fi

    if [ "$update" = true ]; then
        cp "$tmp/actual.json" "$dir/expected.json"
        echo "updated $scenario"
    elif [ ! -f "$dir/expected.json" ]; then
        echo "FAIL $scenario: no expected.json (run with --update)"
        failed="$failed $scenario"
        continue
    elif ! diff -u "$dir/expected.json" "$tmp/actual.json"; then
        cat "$tmp/err.txt"
        echo "FAIL $scenario: report differs from expected.json"
        failed="$failed $scenario"
        continue
    fi

    mode_failed=false
    while IFS= read -r mode; do
        # Word splitting of $mode is intended (flags without spaces).
        # shellcheck disable=SC2086
        if ! check_mode "$scenario" "$image" "$code" $mode; then
            mode_failed=true
        fi
    done <<MODES
$modes
MODES
    if [ "$mode_failed" = true ]; then
        failed="$failed $scenario"
    elif [ "$update" = false ]; then
        echo "ok   $scenario"
    fi
done

if [ -n "$failed" ]; then
    echo "failed:$failed"
    exit 1
fi
