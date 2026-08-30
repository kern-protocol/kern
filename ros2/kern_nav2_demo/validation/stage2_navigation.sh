#!/bin/bash
# Stage 2: ordinary navigation, and the speed bound at the controller.
. /opt/ros/jazzy/setup.sh
mkdir -p /ws/src && cp -r /work/ros2/kern_nav2_demo /ws/src/ 2>/dev/null
cd /ws && colcon build --packages-select kern_nav2_demo > /tmp/colcon.log 2>&1
. /ws/install/setup.sh
export GZ_SIM_RESOURCE_PATH=/ws/install/kern_nav2_demo/share/kern_nav2_demo/worlds

ros2 launch kern_nav2_demo kern_demo.launch.py headless:='-s --headless-rendering' \
  > /tmp/launch.log 2>&1 &
sleep 75
echo "===== lifecycle ====="
for n in controller_server bt_navigator; do echo -n "$n: "; ros2 lifecycle get /$n; done
echo "===== probe: ${PROBE_ARGS} ====="
python3 /scratch/nav_probe.py ${PROBE_ARGS}
echo "===== NAV2 LOG (tail) ====="
grep -aiE "abort|fail|stuck|recovery|error|collision|timed out" /tmp/launch.log | tail -30
pkill -9 -f "gz sim"; pkill -9 -f ros2; exit 0
