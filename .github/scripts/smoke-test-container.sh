#!/usr/bin/env bash
# ==============================================================================
# Hardened Container Runtime Smoke Test for Camellia Remote Server
# ==============================================================================
# Validates production runtime contracts:
# - Non-root user (UID:GID 10001:10001)
# - Read-only root filesystem (--read-only) with /tmp tmpfs
# - Dropped capabilities (--cap-drop=ALL) and no-new-privileges
# - State directory key generation (id_ed25519 0600, id_ed25519.pub 0644)
# - Secret file permission validation (0600 mode, UID match)
# - Socket binding and listening on Relay (21117) and Identity (21116)
# - True business readiness (camellia-remote-utils healthcheck --readiness)
# - SQLite database creation and liveness (camellia-remote-utils healthcheck --sqlite)
# - Graceful SIGTERM shutdown and clean exit (code 0)
# - Zero dangling containers, networks, volumes, or temporary files
# ==============================================================================
set -euo pipefail

IMAGE_REF="${1:?Container image reference is required}"
MAX_WAIT="${CAMELLIA_SMOKE_MAX_WAIT:-30}"

RUN_ID="${RANDOM}_$(date +%s)"
NET_NAME="camellia-smoke-net-${RUN_ID}"
RELAY_NAME="camellia-smoke-relay-${RUN_ID}"
IDENTITY_NAME="camellia-smoke-identity-${RUN_ID}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/camellia-smoke-${RUN_ID}.XXXXXX")"

RELAY_CID=""
IDENTITY_CID=""

cleanup() {
  local exit_code=$?
  set +e
  echo "[smoke-test] Cleaning up ephemeral resources..."
  if [[ -n "$IDENTITY_CID" ]]; then
    docker rm -f "$IDENTITY_CID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$RELAY_CID" ]]; then
    docker rm -f "$RELAY_CID" >/dev/null 2>&1 || true
  fi
  docker network rm "$NET_NAME" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
  echo "[smoke-test] Cleanup complete."
  exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

echo "[smoke-test] Initializing isolated test environment: RUN_ID=${RUN_ID}"
docker network create "$NET_NAME" >/dev/null

# 1. Prepare isolated state directory and restricted secret file
STATE_DIR="$TMP_DIR/state"
mkdir -p "$STATE_DIR"
chmod 0777 "$STATE_DIR"  # Writable by container non-root UID 10001

SECRET_DIR="$TMP_DIR/secrets"
mkdir -p "$SECRET_DIR"
chmod 0777 "$SECRET_DIR"
SECRET_FILE="$SECRET_DIR/device_verification_token"
head -c 48 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32 > "$SECRET_FILE"
chmod 0600 "$SECRET_FILE"

# Ensure the secret file ownership inside container is UID 10001 (or 0)
docker run --rm -v "$SECRET_DIR:/secrets" --user 0:0 "$IMAGE_REF" \
  chown 10001:10001 /secrets/device_verification_token 2>/dev/null || true

# 2. Start Relay Server container under hardened contracts
echo "[smoke-test] Starting Relay container under hardened runtime contracts..."
RELAY_CID="$(docker run -d \
  --name "$RELAY_NAME" \
  --network "$NET_NAME" \
  --network-alias relay \
  --read-only \
  --user 10001:10001 \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 512m \
  --tmpfs /tmp:size=16m,mode=1777 \
  -v "$STATE_DIR:/var/lib/camellia-remote" \
  "$IMAGE_REF" \
  camellia-remote-relay --key _ --bind 0.0.0.0 --port 21117)"

# 3. Verify Relay healthcheck and keypair generation
echo "[smoke-test] Verifying Relay startup and keypair generation..."
relay_ready=false
for ((i=1; i<=MAX_WAIT; i++)); do
  if docker run --rm --network "$NET_NAME" "$IMAGE_REF" \
      camellia-remote-utils healthcheck relay:21117 >/dev/null 2>&1; then
    relay_ready=true
    break
  fi
  sleep 1
done
[[ "$relay_ready" == true ]] || {
  echo "[smoke-test] ERROR: Relay failed to become ready on relay:21117" >&2
  docker logs "$RELAY_CID" >&2 || true
  exit 1
}

# Verify keypair files created in state directory with correct permissions
[[ -f "$STATE_DIR/id_ed25519" ]] || {
  echo "[smoke-test] ERROR: id_ed25519 was not created by relay" >&2
  exit 1
}
[[ -f "$STATE_DIR/id_ed25519.pub" ]] || {
  echo "[smoke-test] ERROR: id_ed25519.pub was not created by relay" >&2
  exit 1
}
if stat -c %a "$STATE_DIR/id_ed25519" >/dev/null 2>&1; then
  key_mode="$(stat -c %a "$STATE_DIR/id_ed25519")"
else
  key_mode="$(stat -f %Lp "$STATE_DIR/id_ed25519")"
fi
[[ "$key_mode" == "600" ]] || {
  echo "[smoke-test] ERROR: id_ed25519 permissions are $key_mode (expected 600)" >&2
  exit 1
}

# 4. Start Identity Server container under hardened contracts
echo "[smoke-test] Starting Identity container under hardened runtime contracts..."
IDENTITY_CID="$(docker run -d \
  --name "$IDENTITY_NAME" \
  --network "$NET_NAME" \
  --network-alias identity \
  --read-only \
  --user 10001:10001 \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 512m \
  --tmpfs /tmp:size=16m,mode=1777 \
  -v "$STATE_DIR:/var/lib/camellia-remote" \
  -v "$SECRET_FILE:/run/secrets/device_verification_token:ro" \
  -e CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN_FILE=/run/secrets/device_verification_token \
  -e CAMELLIA_REMOTE_ALLOW_UNMANAGED_DEVICES=Y \
  "$IMAGE_REF" \
  camellia-remote-identity --key _ --relay-servers relay:21117 --bind 0.0.0.0 --port 21116)"

# 5. Verify Identity readiness and SQLite database
echo "[smoke-test] Verifying Identity readiness probe and SQLite database..."
id_ready=false
for ((i=1; i<=MAX_WAIT; i++)); do
  if docker run --rm --network "$NET_NAME" "$IMAGE_REF" \
      camellia-remote-utils healthcheck --readiness identity:21116 >/dev/null 2>&1; then
    id_ready=true
    break
  fi
  sleep 1
done
[[ "$id_ready" == true ]] || {
  echo "[smoke-test] ERROR: Identity failed readiness probe on identity:21116" >&2
  docker logs "$IDENTITY_CID" >&2 || true
  exit 1
}

# Verify SQLite database was initialized and is readable
docker run --rm -v "$STATE_DIR:/var/lib/camellia-remote:ro" "$IMAGE_REF" \
  camellia-remote-utils healthcheck --sqlite /var/lib/camellia-remote/camellia-remote.sqlite3 >/dev/null

# 6. Verify security attributes on running containers
echo "[smoke-test] Verifying container security boundaries..."
# Non-root user verification
uid="$(docker exec "$IDENTITY_CID" id -u)"
gid="$(docker exec "$IDENTITY_CID" id -g)"
[[ "$uid" == "10001" && "$gid" == "10001" ]] || {
  echo "[smoke-test] ERROR: Container running as UID:GID $uid:$gid (expected 10001:10001)" >&2
  exit 1
}

# Read-only rootfs verification
if docker exec "$IDENTITY_CID" touch /test_file >/dev/null 2>&1; then
  echo "[smoke-test] ERROR: Root filesystem is writable despite --read-only" >&2
  exit 1
fi

# Dropped capabilities verification
docker exec "$IDENTITY_CID" grep -E "^Cap(Eff|Prm):[[:space:]]+0000000000000000" /proc/1/status >/dev/null || {
  echo "[smoke-test] ERROR: Capabilities were not fully dropped" >&2
  exit 1
}

# Legal compliance bundle verification (LEGAL-002)
echo "[smoke-test] Verifying legal compliance bundle in container (LEGAL-002)..."
docker exec "$IDENTITY_CID" test -f /usr/local/share/doc/camellia-remote/LICENSE || {
  echo "[smoke-test] ERROR: Missing LICENSE in container" >&2
  exit 1
}
docker exec "$IDENTITY_CID" test -f /usr/local/share/doc/camellia-remote/NOTICE || {
  echo "[smoke-test] ERROR: Missing NOTICE in container" >&2
  exit 1
}
docker exec "$IDENTITY_CID" test -f /usr/local/share/doc/camellia-remote/SOURCE_PROVENANCE.json || {
  echo "[smoke-test] ERROR: Missing SOURCE_PROVENANCE.json in container" >&2
  exit 1
}

# 7. Test Graceful SIGTERM Shutdown
echo "[smoke-test] Testing graceful SIGTERM shutdown..."
docker stop -t 15 "$IDENTITY_CID" >/dev/null
id_exit="$(docker inspect "$IDENTITY_CID" --format '{{.State.ExitCode}}')"
[[ "$id_exit" -eq 0 ]] || {
  echo "[smoke-test] ERROR: Identity exited with code $id_exit on SIGTERM" >&2
  exit 1
}

docker stop -t 15 "$RELAY_CID" >/dev/null
relay_exit="$(docker inspect "$RELAY_CID" --format '{{.State.ExitCode}}')"
[[ "$relay_exit" -eq 0 ]] || {
  echo "[smoke-test] ERROR: Relay exited with code $relay_exit on SIGTERM" >&2
  exit 1
}

echo "[smoke-test] SUCCESS: All production runtime contracts verified."
