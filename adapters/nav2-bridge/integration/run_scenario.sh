#!/usr/bin/env bash
# Layer 3: the bridge against a real ROS 2 action server, without Gazebo or Nav2.
#
#   ./run_scenario.sh <scenario> <lease-ttl-ms> <server-seconds> [normal|reject] [kill-after-s]
#
# Examples:
#   ./run_scenario.sh allowed   60000  8                 goal runs to SUCCEEDED
#   ./run_scenario.sh expiry     6000 40                 authority lapses mid-goal
#   ./run_scenario.sh supersede 60000 40                 a newer lease lapses the old one
#   ./run_scenario.sh allowed   60000 40 normal 8        the server dies mid-goal
#   ./run_scenario.sh expiry    12000 40 normal 6        cancel while disconnected
#   ./run_scenario.sh allowed   60000 10 reject          the server refuses the goal
set -e
. /opt/ros/jazzy/setup.sh
export PATH=/root/.cargo/bin:$PATH
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/target}
SCENARIO=${1:-expiry}
TTL=${2:-6000}
SERVER_SECONDS=${3:-40}
SERVER_MODE=${4:-normal}
KILL_AFTER=${5:-0}
HERE=$(cd "$(dirname "$0")" && pwd)

cd "$HERE/.."
cargo build --quiet 2>&1 | tail -5

python3 "$HERE/fake_nav2_server.py" "$SERVER_SECONDS" "$SERVER_MODE" &
SERVER=$!
sleep 4

if [ "$KILL_AFTER" != "0" ]; then
  ( sleep "$KILL_AFTER"; echo "[harness] killing the action server"; kill -9 $SERVER ) &
fi

"$CARGO_TARGET_DIR/debug/kern-nav2-demo" "$SCENARIO" --ttl-ms "$TTL" --x-mm 6000 --run-for-s 40 || true
kill $SERVER 2>/dev/null || true
wait 2>/dev/null || true
