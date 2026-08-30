#!/bin/bash
# Stage 3: the real Kern bridge against the live Gazebo + Nav2 stack.
#   SCENARIO  allowed | expiry | supersede
#   TTL_MS    lease lifetime
#   KILL_BT   seconds after start to deactivate bt_navigator (0 = never)
#   PAUSE_GZ  seconds after start to pause Gazebo (0 = never)
. /opt/ros/jazzy/setup.sh
mkdir -p /ws/src && cp -r /work/ros2/kern_nav2_demo /ws/src/ 2>/dev/null
cd /ws && colcon build --packages-select kern_nav2_demo > /tmp/colcon.log 2>&1
. /ws/install/setup.sh
export GZ_SIM_RESOURCE_PATH=/ws/install/kern_nav2_demo/share/kern_nav2_demo/worlds
export PATH=/root/.cargo/bin:$PATH
export CARGO_TARGET_DIR=/tmp/target
# r2r generates bindings for every message package it can see. With the whole
# Nav2 + Gazebo stack installed that is thousands of types, and rustc runs out
# of memory on a small machine. Only these are needed for NavigateToPose.
export IDL_PACKAGE_FILTER="builtin_interfaces;std_msgs;geometry_msgs;action_msgs;unique_identifier_msgs;nav_msgs;geographic_msgs;nav2_msgs"

cd /work/adapters/nav2-bridge && cargo build 2>&1 | tail -4

ros2 launch kern_nav2_demo kern_demo.launch.py headless:='-s --headless-rendering' \
  > /tmp/launch.log 2>&1 &
# Ready means the two things a submission actually needs: the action server,
# and a controller subscribed to the speed-limit topic. Anything less and the
# adapter correctly refuses to send a goal.
for i in $(seq 1 40); do
  HAVE_ACTION=$(ros2 action list 2>/dev/null | grep -c navigate_to_pose)
  HAVE_SPEED=$(ros2 topic info /speed_limit 2>/dev/null | grep -c "Subscription count: [1-9]")
  if [ "$HAVE_ACTION" -ge 1 ] && [ "$HAVE_SPEED" -ge 1 ]; then
    echo "[harness] stack ready (action server + speed-limit subscriber)"; break
  fi
  sleep 5
done
sleep 5
echo "===== lifecycle before Kern ====="
ros2 node list | grep -E "bt_navigator$|controller_server|amcl|map_server|ros_gz_bridge|base_link_to_lidar" | sort

python3 /scratch/cmd_recorder.py 120 > /tmp/cmd.log 2>&1 &
python3 /scratch/odom_recorder.py 120 > /tmp/odom.log 2>&1 &

if [ "${KILL_BT:-0}" != "0" ]; then
  ( sleep "$KILL_BT"
    if [ "${KILL_MODE:-deactivate}" = "kill" ]; then
      echo "[harness] SIGKILL on the Nav2 component container (no result can be sent)"
      pkill -9 -f component_container_isolated
    else
      echo "[harness] deactivating bt_navigator (action server aborts the goal)"
      ros2 lifecycle set /bt_navigator deactivate > /dev/null 2>&1
    fi ) &
fi
if [ "${PAUSE_GZ:-0}" != "0" ]; then
  ( sleep "$PAUSE_GZ"
    echo "[harness] /clock before pause: $(ros2 topic echo /clock --once 2>/dev/null | tr -d '\n' | tail -c 60)"
    echo "[harness] pausing Gazebo simulation time"
    gz service -s /world/kern_corridor/control --reqtype gz.msgs.WorldControl \
      --reptype gz.msgs.Boolean --timeout 3000 --req 'pause: true' > /dev/null 2>&1
    sleep 6
    echo "[harness] /clock  after pause: $(timeout 5 ros2 topic echo /clock --once 2>/dev/null | tr -d '\n' | tail -c 60)"
    sleep 6
    echo "[harness] /clock  6s later   : $(timeout 5 ros2 topic echo /clock --once 2>/dev/null | tr -d '\n' | tail -c 60)" ) &
fi

echo "===== KERN ====="
/tmp/target/debug/kern-nav2-demo "${SCENARIO:-expiry}" --ttl-ms "${TTL_MS:-12000}" \
  --x-mm 6000 --speed-mm-s 300 --run-for-s "${RUN_FOR:-70}" --authority-watch-s "${WATCH:-0}" || true

echo "===== /cmd_vel samples: $(wc -l < /tmp/cmd.log) ====="
head -3 /tmp/cmd.log
awk 'NR % 10 == 1' /tmp/cmd.log | tail -30
echo "===== /odom timeline ====="
cat /tmp/odom.log | tail -40
echo "===== last /cmd_vel samples ====="
tail -6 /tmp/cmd.log
pkill -9 -f "gz sim"; pkill -9 -f ros2; exit 0
