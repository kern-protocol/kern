#!/usr/bin/env python3
"""A minimal NavigateToPose action server, standing in for Nav2.

Real ROS 2 action semantics — goal acceptance, feedback, cancellation, terminal
results — without Gazebo or the Nav2 stack. It also watches /speed_limit, so a
run proves the adapter really publishes the authorized bound before the goal.
"""
import sys
import time

import rclpy
from rclpy.action import ActionServer, CancelResponse, GoalResponse
from rclpy.callback_groups import ReentrantCallbackGroup
from rclpy.executors import MultiThreadedExecutor
from rclpy.node import Node
from nav2_msgs.action import NavigateToPose
from nav2_msgs.msg import SpeedLimit


class FakeNav2(Node):
    def __init__(self, duration, reject):
        super().__init__("fake_nav2")
        self.duration = duration
        self.reject = reject
        self.group = ReentrantCallbackGroup()
        self.server = ActionServer(
            self,
            NavigateToPose,
            "/navigate_to_pose",
            execute_callback=self.execute,
            goal_callback=self.on_goal,
            cancel_callback=self.on_cancel,
            callback_group=self.group,
        )
        self.create_subscription(SpeedLimit, "/speed_limit", self.on_speed_limit, 10)

    def on_speed_limit(self, msg):
        print(f"[server] speed_limit percentage={msg.percentage} value={msg.speed_limit}",
              flush=True)

    def on_goal(self, goal):
        pose = goal.pose.pose.position
        if self.reject:
            print("[server] goal REJECTED", flush=True)
            return GoalResponse.REJECT
        print(f"[server] goal ACCEPTED x={pose.x:.3f} y={pose.y:.3f}", flush=True)
        return GoalResponse.ACCEPT

    def on_cancel(self, goal):
        print("[server] cancel request ACCEPTED", flush=True)
        return CancelResponse.ACCEPT

    def execute(self, handle):
        deadline = time.time() + self.duration
        feedback = NavigateToPose.Feedback()
        while time.time() < deadline:
            if handle.is_cancel_requested:
                handle.canceled()
                print("[server] result CANCELED", flush=True)
                return NavigateToPose.Result()
            feedback.number_of_recoveries = 0
            handle.publish_feedback(feedback)
            time.sleep(0.25)
        handle.succeed()
        print("[server] result SUCCEEDED", flush=True)
        return NavigateToPose.Result()


def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
    reject = len(sys.argv) > 2 and sys.argv[2] == "reject"
    rclpy.init()
    node = FakeNav2(duration, reject)
    executor = MultiThreadedExecutor()
    executor.add_node(node)
    print("[server] ready", flush=True)
    try:
        executor.spin()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
