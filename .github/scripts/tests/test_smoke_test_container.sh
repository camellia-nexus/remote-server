#!/usr/bin/env bash
# ==============================================================================
# Unit tests for smoke-test-container.sh
# ==============================================================================
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
smoke_script="$script_directory/../smoke-test-container.sh"

fail() {
  echo "[test_smoke_test_container] FAILED: $*" >&2
  exit 1
}

# ------------------------------------------------------------------------------
# Test 1: Missing argument fails
# ------------------------------------------------------------------------------
if bash "$smoke_script" >/dev/null 2>&1; then
  fail "smoke-test-container.sh should fail when no image reference is provided"
fi

# ------------------------------------------------------------------------------
# Test Harness with Mock Docker
# ------------------------------------------------------------------------------
fixture="$(mktemp -d "${TMPDIR:-/tmp}/smoke-test-fixture.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir -p "$fixture/bin"

cat > "$fixture/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

raw_args="$*"
log_file="${MOCK_DOCKER_LOG:-/dev/null}"
printf '%s\n' "$raw_args" >> "$log_file"

subcmd="${1:-}"
shift || true

case "$subcmd" in
  network)
    case "${1:-}" in
      create) echo "net-12345" ;;
      rm) ;;
      *) echo "unexpected network subcommand: $1" >&2; exit 1 ;;
    esac
    ;;
  run)
    is_daemon=false
    is_rm=false
    target_name=""
    state_mount=""
    args=("$@")
    i=0
    while [[ $i -lt ${#args[@]} ]]; do
      case "${args[$i]}" in
        -d) is_daemon=true ;;
        --rm) is_rm=true ;;
        --name)
          i=$((i + 1))
          target_name="${args[$i]}"
          ;;
        -v)
          i=$((i + 1))
          if [[ "${args[$i]}" == *":/var/lib/camellia-remote"* ]]; then
            state_mount="${args[$i]%%:*}"
          fi
          ;;
      esac
      i=$((i + 1))
    done

    if [[ "$is_daemon" == true ]]; then
      # Simulating starting Relay or Identity
      if [[ -n "$state_mount" && -d "$state_mount" ]]; then
        # Create id_ed25519 and id_ed25519.pub if relay
        if [[ "$target_name" == *"relay"* ]]; then
          echo "dummy-secret-key" > "$state_mount/id_ed25519"
          chmod 0600 "$state_mount/id_ed25519"
          echo "dummy-public-key" > "$state_mount/id_ed25519.pub"
          chmod 0644 "$state_mount/id_ed25519.pub"
        fi
      fi
      echo "cid-$target_name"
    else
      # One-off command execution (healthcheck, chown, etc.)
      if [[ "$raw_args" == *"healthcheck relay:21117"* ]]; then
        if [[ "${SIMULATE_RELAY_FAIL:-0}" == "1" ]]; then
          exit 1
        fi
        exit 0
      elif [[ "$raw_args" == *"healthcheck --readiness identity:21116"* ]]; then
        if [[ "${SIMULATE_IDENTITY_FAIL:-0}" == "1" ]]; then
          exit 1
        fi
        exit 0
      elif [[ "$raw_args" == *"healthcheck --sqlite"* ]]; then
        exit 0
      fi
      exit 0
    fi
    ;;
  exec)
    cid="${1:-}"
    shift || true
    cmd="$*"
    case "$cmd" in
      "id -u")
        echo "${MOCK_UID:-10001}"
        ;;
      "id -g")
        echo "${MOCK_GID:-10001}"
        ;;
      "touch /test_file")
        if [[ "${SIMULATE_WRITABLE_ROOTFS:-0}" == "1" ]]; then
          exit 0  # Fails smoke test because rootfs was writable!
        fi
        exit 1  # Read-only rootfs rejects touch
        ;;
      "grep -E ^Cap(Eff|Prm):[[:space:]]+0000000000000000 /proc/1/status")
        if [[ "${SIMULATE_CAPS_FAIL:-0}" == "1" ]]; then
          exit 1
        fi
        exit 0
        ;;
      "test -f /usr/local/share/doc/camellia-remote/LICENSE")
        exit 0
        ;;
      "test -f /usr/local/share/doc/camellia-remote/NOTICE")
        exit 0
        ;;
      "test -f /usr/local/share/doc/camellia-remote/SOURCE_PROVENANCE.json")
        exit 0
        ;;
      *)
        echo "unexpected exec cmd: $cmd" >&2
        exit 1
        ;;
    esac
    ;;
  logs)
    echo "mock logs for container ${1:-}"
    ;;
  stop)
    ;;
  inspect)
    echo "0"
    ;;
  rm)
    ;;
  *)
    echo "unexpected docker command: $subcmd $raw_args" >&2
    exit 99
    ;;
esac
SH
chmod +x "$fixture/bin/docker"

# ------------------------------------------------------------------------------
# Test 2: Full Happy Path Execution
# ------------------------------------------------------------------------------
echo "Running Test 2: Happy Path..."
export MOCK_DOCKER_LOG="$fixture/docker_happy.log"
export CAMELLIA_SMOKE_MAX_WAIT=2
PATH="$fixture/bin:$PATH" bash "$smoke_script" "camellia-remote-server:test"

# Verify all mandatory security parameters were passed to docker run
grep -q -- "--read-only" "$MOCK_DOCKER_LOG" || fail "Missing --read-only in container execution"
grep -q -- "--user 10001:10001" "$MOCK_DOCKER_LOG" || fail "Missing --user 10001:10001"
grep -q -- "--cap-drop=ALL" "$MOCK_DOCKER_LOG" || fail "Missing --cap-drop=ALL"
grep -q -- "--security-opt no-new-privileges:true" "$MOCK_DOCKER_LOG" || fail "Missing no-new-privileges"
grep -q -- "--pids-limit 256" "$MOCK_DOCKER_LOG" || fail "Missing --pids-limit 256"
grep -q -- "--tmpfs /tmp:size=16m,mode=1777" "$MOCK_DOCKER_LOG" || fail "Missing /tmp tmpfs"
grep -q -- "camellia-remote-utils healthcheck relay:21117" "$MOCK_DOCKER_LOG" || fail "Missing relay healthcheck"
grep -q -- "camellia-remote-utils healthcheck --readiness identity:21116" "$MOCK_DOCKER_LOG" || fail "Missing identity readiness"
grep -q -- "camellia-remote-utils healthcheck --sqlite" "$MOCK_DOCKER_LOG" || fail "Missing sqlite healthcheck"
grep -q -- "stop -t 15" "$MOCK_DOCKER_LOG" || fail "Missing graceful stop"
grep -q -- "network rm" "$MOCK_DOCKER_LOG" || fail "Missing network cleanup"

# ------------------------------------------------------------------------------
# Test 3: Relay Healthcheck Failure Fails Closed
# ------------------------------------------------------------------------------
echo "Running Test 3: Relay Failure Regression..."
export MOCK_DOCKER_LOG="$fixture/docker_relay_fail.log"
export SIMULATE_RELAY_FAIL=1
if PATH="$fixture/bin:$PATH" bash "$smoke_script" "camellia-remote-server:test" >/dev/null 2>&1; then
  fail "smoke script should have failed when relay healthcheck fails"
fi
unset SIMULATE_RELAY_FAIL
grep -q -- "network rm" "$MOCK_DOCKER_LOG" || fail "Cleanup was not invoked on relay failure"

# ------------------------------------------------------------------------------
# Test 4: Identity Readiness Failure Fails Closed
# ------------------------------------------------------------------------------
echo "Running Test 4: Identity Readiness Regression..."
export MOCK_DOCKER_LOG="$fixture/docker_id_fail.log"
export SIMULATE_IDENTITY_FAIL=1
if PATH="$fixture/bin:$PATH" bash "$smoke_script" "camellia-remote-server:test" >/dev/null 2>&1; then
  fail "smoke script should have failed when identity readiness fails"
fi
unset SIMULATE_IDENTITY_FAIL
grep -q -- "network rm" "$MOCK_DOCKER_LOG" || fail "Cleanup was not invoked on identity failure"

# ------------------------------------------------------------------------------
# Test 5: Root User Regression Fails Closed
# ------------------------------------------------------------------------------
echo "Running Test 5: Root User Regression..."
export MOCK_DOCKER_LOG="$fixture/docker_root_fail.log"
export MOCK_UID=0
if PATH="$fixture/bin:$PATH" bash "$smoke_script" "camellia-remote-server:test" >/dev/null 2>&1; then
  fail "smoke script should have failed when container runs as root"
fi
unset MOCK_UID

# ------------------------------------------------------------------------------
# Test 6: Writable Rootfs Regression Fails Closed
# ------------------------------------------------------------------------------
echo "Running Test 6: Writable Rootfs Regression..."
export MOCK_DOCKER_LOG="$fixture/docker_rootfs_fail.log"
export SIMULATE_WRITABLE_ROOTFS=1
if PATH="$fixture/bin:$PATH" bash "$smoke_script" "camellia-remote-server:test" >/dev/null 2>&1; then
  fail "smoke script should have failed when rootfs is writable"
fi
unset SIMULATE_WRITABLE_ROOTFS

echo "[test_smoke_test_container] All unit tests passed successfully."
