#!/usr/bin/env python3
"""Send one NavigateToPose goal and measure what the robot was commanded to do.

Records the final commanded velocity on /cmd_vel — the topic the simulator's
DiffDrive actually consumes — so a speed bound can be checked against the
controller's output rather than against a wish.
"""
import argparse
import math
import time

import rclpy
from rclpy.action import ActionClient
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy

from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
from nav2_msgs.action import NavigateToPose
from nav2_msgs.msg import SpeedLimit


class Probe(Node):
    def __init__(self, args):
        super().__init__("kern_nav_probe")
        self.args = args
        self.max_cmd = 0.0
        self.samples = []
        self.first_pose = None
        self.last_pose = None
        self.result_status = None
        sensor_qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE)
        self.create_subscription(Twist, "/cmd_vel", self.on_cmd, sensor_qos)
        self.create_subscription(Odometry, "/odom", self.on_odom, sensor_qos)
        self.speed_pub = self.create_publisher(SpeedLimit, "/speed_limit", 10)
        self.client = ActionClient(self, NavigateToPose, "/navigate_to_pose")

    def on_cmd(self, msg):
        speed = abs(msg.linear.x)
        self.max_cmd = max(self.max_cmd, speed)
        self.samples.append(speed)

    def on_odom(self, msg):
        p = msg.pose.pose.position
        if self.first_pose is None:
            self.first_pose = (p.x, p.y)
        self.last_pose = (p.x, p.y)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--x", type=float, default=6.0)
    parser.add_argument("--y", type=float, default=0.0)
    parser.add_argument("--speed-limit", type=float, default=0.0)
    parser.add_argument("--duration", type=float, default=60.0)
    args = parser.parse_args()

    rclpy.init()
    node = Probe(args)

    node.get_logger().info("waiting for the action server")
    node.client.wait_for_server()

    if args.speed_limit > 0.0:
        deadline = time.time() + 5.0
        while node.speed_pub.get_subscription_count() == 0 and time.time() < deadline:
            rclpy.spin_once(node, timeout_sec=0.1)
        matched = node.speed_pub.get_subscription_count()
        node.speed_pub.publish(
            SpeedLimit(percentage=False, speed_limit=args.speed_limit)
        )
        print(f"[probe] speed limit {args.speed_limit} m/s published, "
              f"{matched} subscriber(s)", flush=True)
        for _ in range(10):
            rclpy.spin_once(node, timeout_sec=0.05)

    goal = NavigateToPose.Goal()
    goal.pose.header.frame_id = "map"
    goal.pose.pose.position.x = args.x
    goal.pose.pose.position.y = args.y
    goal.pose.pose.orientation.w = 1.0

    send = node.client.send_goal_async(goal)
    rclpy.spin_until_future_complete(node, send)
    handle = send.result()
    if not handle.accepted:
        print("[probe] GOAL REJECTED", flush=True)
        return
    print("[probe] GOAL ACCEPTED", flush=True)

    result_future = handle.get_result_async()
    start = time.time()
    last_report = 0.0
    while time.time() - start < args.duration:
        rclpy.spin_once(node, timeout_sec=0.1)
        if result_future.done():
            node.result_status = result_future.result().status
            break
        elapsed = time.time() - start
        if elapsed - last_report >= 5.0:
            last_report = elapsed
            pose = node.last_pose or (float("nan"),) * 2
            print(f"[probe] t={elapsed:5.1f}s pose=({pose[0]:6.3f}, {pose[1]:6.3f}) "
                  f"max_cmd={node.max_cmd:.3f} m/s", flush=True)

    moving = [s for s in node.samples if s > 0.01]
    travelled = 0.0
    if node.first_pose and node.last_pose:
        travelled = math.dist(node.first_pose, node.last_pose)
    print("[probe] ================ SUMMARY ================", flush=True)
    print(f"[probe] start pose      : {node.first_pose}", flush=True)
    print(f"[probe] final pose      : {node.last_pose}", flush=True)
    print(f"[probe] distance moved  : {travelled:.3f} m", flush=True)
    print(f"[probe] cmd_vel samples : {len(node.samples)} "
          f"({len(moving)} above 0.01 m/s)", flush=True)
    print(f"[probe] MAX commanded   : {node.max_cmd:.4f} m/s", flush=True)
    if args.speed_limit > 0.0:
        verdict = "WITHIN BOUND" if node.max_cmd <= args.speed_limit + 1e-3 else "EXCEEDED BOUND"
        print(f"[probe] bound {args.speed_limit:.3f} m/s -> {verdict}", flush=True)
    print(f"[probe] action status   : {node.result_status}", flush=True)


if __name__ == "__main__":
    main()
