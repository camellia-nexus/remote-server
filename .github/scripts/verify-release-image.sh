#!/usr/bin/env bash
set -euo pipefail

reference="${1:?image@digest is required}"
version="${2:?stable version is required}"
revision="${3:?source revision is required}"

[[ "$reference" =~ @sha256:[0-9a-f]{64}$ ]]
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]

index_json="$(docker buildx imagetools inspect --raw "$reference")"
jq -e '
  [
    .manifests[]? |
    select(.platform.os == "linux")
  ] as $platforms |
  ($platforms | length) == 2 and
  ($platforms | map(.platform.architecture) | sort) == ["amd64", "arm64"] and
  all($platforms[];
    .digest | type == "string" and test("^sha256:[0-9a-f]{64}$")
  )
' <<< "$index_json" >/dev/null

repository="${reference%@*}"
for architecture in amd64 arm64; do
  platform_digest="$(
    jq -er --arg architecture "$architecture" '
      [
        .manifests[] |
        select(
          .platform.os == "linux" and
          .platform.architecture == $architecture
        ) |
        .digest
      ] |
      if length == 1 then .[0] else error("platform digest mismatch") end
    ' <<< "$index_json"
  )"
  platform_reference="$repository@$platform_digest"
  docker pull --platform "linux/$architecture" "$platform_reference"
  image_id="$(docker image inspect --format '{{.Id}}' "$platform_reference")"
  local_tag="remote-server-release-verify:$architecture"
  docker tag "$image_id" "$local_tag"
  identity_version="$(docker run --rm --platform "linux/$architecture" \
    --entrypoint camellia-remote-identity "$local_tag" --version)"
  relay_version="$(docker run --rm --platform "linux/$architecture" \
    --entrypoint camellia-remote-relay "$local_tag" --version)"
  image_version="$(docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' \
    "$local_tag")"
  image_revision="$(docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "$local_tag")"
  image_source="$(docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.source" }}' \
    "$local_tag")"
  [[ "$identity_version" == "camellia-remote-identity $version" ]]
  [[ "$relay_version" == "camellia-remote-relay $version" ]]
  [[ "$image_version" == "$version" ]]
  [[ "$image_revision" == "$revision" ]]
  [[ "$image_source" == "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" ]]
  [[ "$(docker image inspect --format '{{.Config.User}}' "$local_tag")" == "10001:10001" ]]

  # Execute short-lived hardened container runtime integration check
  if [[ -z "${DOCKER_CALLS:-}" && "${CAMELLIA_SKIP_SMOKE_TEST:-0}" != "1" ]]; then
    script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    "$script_directory/smoke-test-container.sh" "$local_tag"
  fi
done
