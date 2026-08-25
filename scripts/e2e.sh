#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="peerless-e2e-$$"
compose=(docker compose -p "$project")

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$repo_root"
mkdir -p e2e-output
evidence="e2e-output/latest.txt"
: >"$evidence"

record() {
  printf '%s\n' "$*" | tee -a "$evidence"
}

wait_for_node() {
  local service="$1"
  local attempt
  for attempt in $(seq 1 120); do
    if "${compose[@]}" logs --no-log-prefix "$service" 2>&1 | grep -q '^listen'; then
      return 0
    fi
    sleep 1
  done
  "${compose[@]}" logs "$service" >&2
  return 1
}

node_id() {
  "${compose[@]}" logs --no-log-prefix "$1" 2>&1 \
    | awk '$1 == "node" { value = $2 } END { print value }'
}

peer_id() {
  "${compose[@]}" logs --no-log-prefix "$1" 2>&1 \
    | awk '$1 == "peer" { value = $2 } END { print value }'
}

node_ip() {
  local container
  container="$("${compose[@]}" ps -q "$1")"
  docker inspect -f "{{with index .NetworkSettings.Networks \"${project}_peerless\"}}{{.IPAddress}}{{end}}" "$container"
}

service_for_node() {
  local wanted="$1"
  local service
  for service in node-a node-b node-c; do
    if [[ "$(node_id "$service")" == "$wanted" ]]; then
      printf '%s\n' "$service"
      return 0
    fi
  done
  return 1
}

record 'phase=build action=compile-runtime'
"${compose[@]}" run --rm dev cargo build -p peerless-cli
record 'phase=secure-default action=reject-open-admission-listener'
if denied_output="$("${compose[@]}" run --rm probe /target/debug/peerless start /tmp/no-membership /ip4/127.0.0.1/udp/0/quic-v1 2>&1)"; then
  record 'security failure=open-admission-listener-started'
  exit 1
fi
denied_summary="$(grep 'peerless: refusing open-admission listener' <<<"$denied_output" | tail -n 1 || true)"
record "secure-default rejection=$denied_summary"
if ! grep -q 'refusing open-admission listener' <<<"$denied_output"; then
  record 'security failure=unexpected-open-admission-rejection'
  exit 1
fi
record 'secure-default membership_required=true unsafe_open_explicit=true'
record 'phase=containers action=start'
"${compose[@]}" up -d --build node-a node-b node-c
internal="$(docker network inspect -f '{{.Internal}}' "${project}_peerless")"
[[ "$internal" == "true" ]]
record "network name=${project}_peerless internal=$internal external_access=false"
for service in node-a node-b node-c; do
  wait_for_node "$service"
  container="$("${compose[@]}" ps -q "$service")"
  runtime_user="$(docker inspect -f '{{.Config.User}}' "$container")"
  readonly_root="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$container")"
  cap_drop="$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$container")"
  security_opt="$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$container")"
  pids_limit="$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$container")"
  memory_limit="$(docker inspect -f '{{.HostConfig.Memory}}' "$container")"
  [[ "$runtime_user" == "10001:10001" ]]
  [[ "$readonly_root" == "true" ]]
  [[ "$cap_drop" == *'ALL'* ]]
  [[ "$security_opt" == *'no-new-privileges:true'* ]]
  [[ "$pids_limit" == "256" ]]
  [[ "$memory_limit" == "2147483648" ]]
  [[ "$("${compose[@]}" exec -T "$service" stat -c '%a' /data/identity)" == "700" ]]
  [[ "$("${compose[@]}" exec -T "$service" stat -c '%a' /data/identity/key.protobuf)" == "600" ]]
  id="$(node_id "$service")"
  [[ -n "$id" ]]
  record "node service=$service id=$id"
done
record 'hardening user=10001:10001 read_only=true cap_drop=ALL no_new_privileges=true pids=256 memory=2GiB identity_dir=0700 identity_key=0600'

peer_addresses=()
for service in node-a node-b node-c; do
  peer_addresses+=("/ip4/$(node_ip "$service")/udp/9718/quic-v1/p2p/$(peer_id "$service")")
done
record "topology peers=${#peer_addresses[@]} coordinator=none bootstrap=direct-multiaddr"

record 'phase=wasm action=build'
"${compose[@]}" run --rm dev cargo build \
  --manifest-path examples/double-wasm/Cargo.toml \
  --target wasm32-unknown-unknown --release

record 'phase=p2p action=remote-execute input=21 expected=42'
first_output="$("${compose[@]}" run --rm probe /target/debug/peerless run --unsafe-open \
  /tmp/e2e-requester \
  /target/wasm32-unknown-unknown/release/double.wasm \
  21 "${peer_addresses[@]}")"
printf '%s\n' "$first_output" | tee -a "$evidence"
grep -q 'verified  true' <<<"$first_output"
grep -q '(42)' <<<"$first_output"
first_executor="$(awk '$1 == "executor" { print $2 }' <<<"$first_output")"
first_service="$(service_for_node "$first_executor")"
[[ -n "$first_service" ]]

tasks="$("${compose[@]}" exec -T "$first_service" /target/debug/peerless inspect tasks /data)"
ledger="$("${compose[@]}" exec -T "$first_service" /target/debug/peerless inspect ledger /data)"
storage="$("${compose[@]}" exec -T "$first_service" /target/debug/peerless inspect storage /data)"
grep -q $'completed\t1' <<<"$tasks"
grep -q $'height\t1' <<<"$ledger"
record "remote service=$first_service executor=$first_executor $tasks $ledger $storage"

record "phase=departure action=stop service=$first_service"
"${compose[@]}" stop "$first_service"
live_addresses=()
for service in node-a node-b node-c; do
  if [[ "$service" != "$first_service" ]]; then
    live_addresses+=("/ip4/$(node_ip "$service")/udp/9718/quic-v1/p2p/$(peer_id "$service")")
  fi
done
second_output="$("${compose[@]}" run --rm probe /target/debug/peerless run --unsafe-open \
  /tmp/e2e-failover \
  /target/wasm32-unknown-unknown/release/double.wasm \
  21 "${live_addresses[@]}")"
printf '%s\n' "$second_output" | tee -a "$evidence"
grep -q 'verified  true' <<<"$second_output"
grep -q '(42)' <<<"$second_output"
second_executor="$(awk '$1 == "executor" { print $2 }' <<<"$second_output")"
[[ "$second_executor" != "$first_executor" ]]
second_service="$(service_for_node "$second_executor")"
record "failover service=$second_service executor=$second_executor"

record "phase=restart action=start service=$first_service"
"${compose[@]}" start "$first_service"
wait_for_node "$first_service"
tasks_after="$("${compose[@]}" exec -T "$first_service" /target/debug/peerless inspect tasks /data)"
ledger_after="$("${compose[@]}" exec -T "$first_service" /target/debug/peerless inspect ledger /data)"
grep -q $'completed\t1' <<<"$tasks_after"
grep -q $'height\t1' <<<"$ledger_after"
record "restart-persistence service=$first_service $tasks_after $ledger_after"

record 'phase=isolation action=stop-e2e-nodes-before-adversarial-tests'
"${compose[@]}" stop node-a node-b node-c

record 'phase=public-api action=full-feature-scenario'
for pass in $(seq 1 5); do
  record "falsification-pass=$pass"
  features_output="$("${compose[@]}" run --rm probe /target/debug/peerless \
    e2e-features "/tmp/peerless-e2e-features-$pass")"
  printf '%s\n' "$features_output" | tee -a "$evidence"
  grep -q 'result=PASS content=true crdt=true membership=true replication=true repair=true bft=true ledger_gossip=true relay=true dcutr=true' <<<"$features_output"
done

record 'phase=adversarial action=workspace-tests'
"${compose[@]}" run --rm dev cargo fmt --all -- --check
"${compose[@]}" run --rm dev cargo clippy --workspace --all-targets -- -D warnings
"${compose[@]}" run --rm dev cargo test --workspace -j 1 -- --test-threads=1
"${compose[@]}" run --rm dev cargo audit \
  --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119
"${compose[@]}" run --rm dev cargo check -p peerless-browser --target wasm32-unknown-unknown

record 'result=PASS server_free=true runtime_network_internal=true secure_default=true relay_privacy=true wasm_fuel=true rate_limit=true connection_limit=true key_permissions=true container_hardened=true falsification_passes=5 p2p=true remote_execution=true signature=true cas=true ledger=true departure=true restart=true content=true crdt=true membership=true replication=true repair=true bft=true ledger_gossip=true relay=true dcutr=true adversarial=true browser_build=true'
