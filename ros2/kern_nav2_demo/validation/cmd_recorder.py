#!/usr/bin/env python3
"""Logs /cmd_vel with wall-clock timestamps, so motion can be correlated with
Kern's authority transitions."""
import sys, time
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist

class Rec(Node):
    def __init__(self):
        super().__init__("cmd_recorder")
        self.t0 = time.monotonic()
        self.create_subscription(Twist, "/cmd_vel", self.on_cmd, 10)
    def on_cmd(self, msg):
        print(f"{time.monotonic()-self.t0:7.2f}s cmd_vel.linear.x={msg.linear.x:+.3f} "
              f"angular.z={msg.angular.z:+.3f}", flush=True)

def main():
    rclpy.init()
    node = Rec()
    end = time.monotonic() + float(sys.argv[1] if len(sys.argv) > 1 else 90)
    while time.monotonic() < end:
        rclpy.spin_once(node, timeout_sec=0.2)

main()
