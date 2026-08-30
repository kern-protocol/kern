# kern_nav2_demo

Gazebo Harmonic world, differential-drive robot, and Nav2 configuration for the
Kern Phase 6 demonstration: **a navigation goal that outlives the capability
lease that authorized it.**

Target stack: Ubuntu 24.04, ROS 2 Jazzy, Nav2 Jazzy, Gazebo Harmonic. Gazebo
Classic is not supported and is not used.

## What is in here

```text
worlds/kern_corridor.sdf     20 x 10 m, a 2 m corridor, two static obstacles
worlds/kern_bot/             diff drive + planar lidar + odometry + TF
maps/kern_corridor.pgm|yaml  occupancy map, generated to match the world exactly
params/kern_nav2_params.yaml Nav2 deviations from default; carries speed_limit_topic
launch/kern_demo.launch.py   Gazebo + ros_gz_bridge + robot_state_publisher + Nav2
```

The robot starts at `(-8, 0)`. The demo drives it to `(6, 0)` — about 14 m, which
at the authorized 0.3 m/s is roughly 45 seconds of motion. That is what makes a
six-second lease expire while the robot is still moving.

## Build and run

```bash
# 1. build the ROS package
mkdir -p ~/kern_ws/src && cd ~/kern_ws/src
ln -s /path/to/kern-protocol/ros2/kern_nav2_demo .
cd ~/kern_ws
source /opt/ros/jazzy/setup.bash
colcon build --packages-select kern_nav2_demo
source install/setup.bash

# 2. world + robot + Nav2  (drop `headless:=''` for the Gazebo GUI)
ros2 launch kern_nav2_demo kern_demo.launch.py headless:='' rviz:=true

# 3. the Kern side, in another shell
source /opt/ros/jazzy/setup.bash
cd /path/to/kern-protocol/adapters/nav2-bridge
cargo run --bin kern-nav2-demo -- expiry --ttl-ms 6000 --x-mm 6000
```

Scenarios: `allowed`, `expiry`, `supersede`.

## Where Kern's speed bound is applied

`controller_server.speed_limit_topic: /speed_limit`.

The adapter publishes `nav2_msgs/msg/SpeedLimit` with `percentage: false` and the
authorized bound in m/s **before** each goal is sent, and clears it with `0.0`
(Nav2's "no limit") once no goal can still be running under it.
`controller_server` hands the value to the controller plugin's `setSpeedLimit`.

If that publish does not succeed, the adapter sends **no goal** and Kern records
`NotStarted(Rejected(Unavailable))`. An authorized `max_speed_mm_s` that nothing
applies is never accepted.

This is a commanded bound at the Nav2 controller. It is not a guarantee about
wheel speed, motor current, or braking.

## What the demo proves, and what it does not

It proves that authority and execution stay separate through a real long-running
executor: authority can lapse while a goal is still running, Kern will ask Nav2
to cancel, and Kern records the difference between *requested*, *acknowledged*,
and *confirmed*.

It does not make Kern a safety system. Kern does not provide certified collision
avoidance, motor power removal, braking guarantees, emergency-stop guarantees,
SIL or PL compliance, or safe torque off. Nav2, the controller, and the hardware
remain responsible for what the machine physically does. After a cancellation
request the robot keeps moving until Nav2's own controller stops it — that
interval is real, and the demo shows it rather than hiding it.
