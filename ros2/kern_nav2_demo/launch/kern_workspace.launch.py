"""Gazebo Harmonic + Nav2 for the heterogeneous Kern validation.

Starts, in one command:

  * Gazebo Harmonic with worlds/kern_workspace.sdf: the Phase 6 corridor and
    the kern_bot mobile robot, plus a conveyor and a two-joint arm placed
    outside the navigable lane
  * ros_gz_bridge for /clock, /cmd_vel, /odom, /scan, /tf, /joint_states, and
    the two workstations' command and joint-state topics
  * a static transform for the lidar frame
  * Nav2 with params/kern_nav2_params.yaml and maps/kern_corridor.yaml

The occupancy map is the Phase 6 map, unchanged. The two workstations sit where
it already marks the floor occupied, so Nav2 plans exactly the paths it always
did and the new machines are simply not on them.

It does not start Kern. The Kern side is a separate process, so that authority
can be seen arriving and lapsing independently of any machine:

    cargo run --bin kern-hetero-demo -- --scenario all
"""

import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, IncludeLaunchDescription, SetEnvironmentVariable
from launch.conditions import IfCondition
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import LaunchConfiguration, PathJoinSubstitution
from launch_ros.actions import Node
from launch_ros.substitutions import FindPackageShare


def generate_launch_description():
    package = get_package_share_directory("kern_nav2_demo")
    world = os.path.join(package, "worlds", "kern_workspace.sdf")
    params = os.path.join(package, "params", "kern_nav2_params.yaml")
    map_yaml = os.path.join(package, "maps", "kern_corridor.yaml")
    rviz_config = os.path.join(package, "rviz", "kern_demo.rviz")

    headless = LaunchConfiguration("headless")
    use_rviz = LaunchConfiguration("rviz")

    # The included model lives beside the world file.
    resource_path = SetEnvironmentVariable(
        "GZ_SIM_RESOURCE_PATH", os.path.join(package, "worlds")
    )

    gazebo = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            PathJoinSubstitution(
                [FindPackageShare("ros_gz_sim"), "launch", "gz_sim.launch.py"]
            )
        ),
        launch_arguments={
            # -r runs the world immediately; -s is server-only for CI.
            "gz_args": [world, " -r ", headless],
        }.items(),
    )

    bridge = Node(
        package="ros_gz_bridge",
        executable="parameter_bridge",
        name="ros_gz_bridge",
        output="screen",
        arguments=[
            "/clock@rosgraph_msgs/msg/Clock[gz.msgs.Clock",
            "/cmd_vel@geometry_msgs/msg/Twist]gz.msgs.Twist",
            "/odom@nav_msgs/msg/Odometry[gz.msgs.Odometry",
            "/scan@sensor_msgs/msg/LaserScan[gz.msgs.LaserScan",
            "/tf@tf2_msgs/msg/TFMessage[gz.msgs.Pose_V",
            "/joint_states@sensor_msgs/msg/JointState[gz.msgs.Model",
            # The conveyor: one prismatic joint, commanded and observed. Kern
            # never publishes here directly; the adapter does, below the
            # authority boundary.
            "/conveyor_01/belt_cmd@std_msgs/msg/Float64]gz.msgs.Double",
            "/conveyor_01/joint_state@sensor_msgs/msg/JointState[gz.msgs.Model",
            # The arm: two revolute joints, likewise.
            "/robotic_arm_01/shoulder_cmd@std_msgs/msg/Float64]gz.msgs.Double",
            "/robotic_arm_01/elbow_cmd@std_msgs/msg/Float64]gz.msgs.Double",
            "/robotic_arm_01/joint_state@sensor_msgs/msg/JointState[gz.msgs.Model",
        ],
        parameters=[{"use_sim_time": True}],
    )

    # The lidar's frame, as Gazebo names it. `robot_state_publisher` is
    # deliberately not used: it parses URDF, and sdformat_urdf refuses a <model>
    # carrying a <pose>. The robot has exactly one frame Nav2 needs beyond what
    # DiffDrive already publishes, so a static transform is the honest amount of
    # machinery. Its translation matches the <sensor> pose in kern_bot/model.sdf.
    lidar_tf = Node(
        package="tf2_ros",
        executable="static_transform_publisher",
        name="base_link_to_lidar",
        output="screen",
        parameters=[{"use_sim_time": True}],
        arguments=[
            "--x", "0.16", "--y", "0", "--z", "0.12",
            "--roll", "0", "--pitch", "0", "--yaw", "0",
            "--frame-id", "base_link",
            "--child-frame-id", "kern_bot/base_link/lidar",
        ],
    )

    nav2 = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            PathJoinSubstitution(
                [FindPackageShare("nav2_bringup"), "launch", "bringup_launch.py"]
            )
        ),
        launch_arguments={
            "use_sim_time": "true",
            "params_file": params,
            "map": map_yaml,
            "autostart": "true",
        }.items(),
    )

    rviz = Node(
        package="rviz2",
        executable="rviz2",
        arguments=["-d", rviz_config],
        parameters=[{"use_sim_time": True}],
        condition=IfCondition(use_rviz),
        output="screen",
    )

    return LaunchDescription(
        [
            DeclareLaunchArgument(
                "headless",
                default_value="-s",
                description="'-s' for server only, '' for the Gazebo GUI.",
            ),
            DeclareLaunchArgument(
                "rviz", default_value="false", description="Start RViz."
            ),
            resource_path,
            gazebo,
            bridge,
            lidar_tf,
            nav2,
            rviz,
        ]
    )
