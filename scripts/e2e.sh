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
record 'phase=containers action=start'
"${compose[@]}" up -d --build node-a node-b node-c
for service in node-a node-b node-c; do
  wait_for_node "$service"
  id="$(node_id "$service")"
  [[ -n "$id" ]]
  record "node service=$service id=$id"
done

record 'phase=wasm action=build'
"${compose[@]}" run --rm dev cargo build \
  --manifest-path examples/double-wasm/Cargo.toml \
  --target wasm32-unknown-unknown --release

record 'phase=p2p action=remote-execute input=21 expected=42'
first_output="$("${compose[@]}" run --rm dev cargo run -p peerless-cli -- run \
  /tmp/e2e-requester \
  /target/wasm32-unknown-unknown/release/double.wasm \
  21)"
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
second_output="$("${compose[@]}" run --rm dev cargo run -p peerless-cli -- run \
  /tmp/e2e-failover \
  /target/wasm32-unknown-unknown/release/double.wasm \
  21)"
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
  features_output="$("${compose[@]}" run --rm dev cargo run -p peerless-cli -- \
    e2e-features "/tmp/peerless-e2e-features-$pass")"
  printf '%s\n' "$features_output" | tee -a "$evidence"
  grep -q 'result=PASS content=true crdt=true membership=true replication=true repair=true bft=true ledger_gossip=true relay=true dcutr=true' <<<"$features_output"
done

record 'phase=adversarial action=workspace-tests'
"${compose[@]}" run --rm dev cargo fmt --all -- --check
"${compose[@]}" run --rm dev cargo clippy --workspace --all-targets -- -D warnings
"${compose[@]}" run --rm dev cargo test --workspace -- --test-threads=1
"${compose[@]}" run --rm dev cargo check -p peerless-browser --target wasm32-unknown-unknown

record 'result=PASS falsification_passes=5 p2p=true remote_execution=true signature=true cas=true ledger=true departure=true restart=true content=true crdt=true membership=true replication=true repair=true bft=true ledger_gossip=true relay=true dcutr=true adversarial=true browser_build=true'
