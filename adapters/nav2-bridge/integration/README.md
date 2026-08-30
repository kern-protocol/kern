# Layer 3 integration harness

Runs the real bridge — `r2r`, a real ROS 2 action client, a real spin thread —
against a real `rclpy` `NavigateToPose` action server. No Gazebo, no Nav2, no
robot, so it is fast and deterministic enough to run on every change to the
bridge.

`fake_nav2_server.py` also subscribes to `/speed_limit`, so a run shows whether
the authorized speed bound actually reached a subscriber *before* the goal was
sent. That check is not decoration: it caught a real defect, where an unmatched
publisher silently dropped the limit and the adapter reported it as applied.

## With Docker, on any machine

```bash
docker build -t kern-phase6 adapters/nav2-bridge/integration
docker run --rm -v "$PWD":/work -w /work kern-phase6 \
  bash adapters/nav2-bridge/integration/run_scenario.sh expiry 6000 40
```

## On a machine with ROS 2 Jazzy

```bash
source /opt/ros/jazzy/setup.bash
adapters/nav2-bridge/integration/run_scenario.sh expiry 6000 40
```

## What each scenario shows

| command | what it proves |
|---|---|
| `allowed 60000 8` | speed limit published, then goal accepted, feedback → Running, SUCCEEDED → Completed |
| `expiry 6000 40` | authority lapses while Running, cancel requested, CANCELED → Cancelled |
| `supersede 60000 40` | a newer lease lapses the old execution and does not adopt it |
| `allowed 60000 40 normal 8` | a dead action server becomes `Unknown{Result}`, never `Failed` |
| `expiry 12000 40 normal 6` | cancelling into a dead server becomes `RequestUnknown` |
| `allowed 60000 10 reject` | an explicitly refused goal becomes `NotStarted(Rejected(Refused))` |
