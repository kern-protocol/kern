#!/bin/bash
# Stage 1: launch the real launch file, then look at what actually came up.
set -x
. /opt/ros/jazzy/setup.sh
mkdir -p /ws/src
cp -r /work/ros2/kern_nav2_demo /ws/src/
cd /ws && colcon build --packages-select kern_nav2_demo > /tmp/colcon.log 2>&1
tail -3 /tmp/colcon.log
. /ws/install/setup.sh

export GZ_SIM_RESOURCE_PATH=/ws/install/kern_nav2_demo/share/kern_nav2_demo/worlds
ros2 launch kern_nav2_demo kern_demo.launch.py headless:='-s --headless-rendering' \
  > /tmp/launch.log 2>&1 &
LAUNCH=$!
sleep 75

set +x
echo "===== NODES ====="
ros2 node list 2>&1 | sort
echo "===== TOPICS ====="
ros2 topic list 2>&1 | sort
echo "===== TF FRAMES (raw /tf sample) ====="
timeout 5 ros2 topic echo /tf --once 2>&1 | head -20
echo "===== /tf_static ====="
timeout 5 ros2 topic echo /tf_static --once 2>&1 | head -20
echo "===== /scan ====="
timeout 8 ros2 topic echo /scan --once --field header 2>&1 | head -10
echo "===== /odom ====="
timeout 8 ros2 topic echo /odom --once --field header 2>&1 | head -10
echo "===== /map ====="
timeout 8 ros2 topic echo /map --once --field info 2>&1 | head -12
echo "===== TF CHAIN ====="
timeout 8 ros2 run tf2_ros tf2_echo map base_link --ros-args -p use_sim_time:=true 2>&1 | head -12
echo "===== TF odom->base_link ====="
timeout 8 ros2 run tf2_ros tf2_echo odom base_link --ros-args -p use_sim_time:=true 2>&1 | head -12
echo "===== LIFECYCLE ====="
for n in map_server amcl controller_server planner_server behavior_server bt_navigator velocity_smoother; do
  echo -n "$n: "; timeout 5 ros2 lifecycle get /$n 2>&1 | head -1
done
echo "===== LAUNCH LOG ERRORS ====="
grep -aiE "error|fail|not found|exception|traceback" /tmp/launch.log | head -40
kill $LAUNCH 2>/dev/null
sleep 3
pkill -9 -f "gz sim" 2>/dev/null
pkill -9 -f ros2 2>/dev/null
exit 0
