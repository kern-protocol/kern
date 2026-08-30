#!/usr/bin/env python3
"""Logs /odom position with wall-clock timestamps. The gz bridge survives a
Nav2 crash, so this shows what the machine did after Kern lost sight of it."""
import sys, time
import rclpy
from rclpy.node import Node
from nav_msgs.msg import Odometry

class Rec(Node):
    def __init__(self):
        super().__init__("odom_recorder")
        self.t0 = time.monotonic()
        self.last = 0.0
        self.create_subscription(Odometry, "/odom", self.on_odom, 10)
    def on_odom(self, msg):
        now = time.monotonic() - self.t0
        if now - self.last < 1.0:
            return
        self.last = now
        p = msg.pose.pose.position
        v = msg.twist.twist.linear.x
        print(f"{now:7.2f}s odom x={p.x:7.3f} y={p.y:7.3f} vx={v:+.3f}", flush=True)

rclpy.init()
node = Rec()
end = time.monotonic() + float(sys.argv[1] if len(sys.argv) > 1 else 90)
while time.monotonic() < end:
    rclpy.spin_once(node, timeout_sec=0.2)
