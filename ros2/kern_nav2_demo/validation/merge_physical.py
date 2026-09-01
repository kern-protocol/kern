#!/usr/bin/env python3
"""Merge ROS observations into the evaluation record the Kern binary just wrote.

The Kern process records what Kern knows. Velocity and odometry come from topics
it does not subscribe to, so they are captured by the harness and merged here,
into the last record of the JSONL file.

Every merged value is named for exactly what it is. `max_commanded_speed_m_s`
stays the authorized bound the adapter applied; the observed peak is recorded
separately as `observed_max_cmd_vel_m_s`, and neither is a wheel measurement.
An absent observation is written as null, never as zero.
"""
import json
import re
import sys

CMD = re.compile(r"([0-9.]+)s cmd_vel\.linear\.x=([+-]?[0-9.]+)")
# The recorder prints a sign only for negatives, so the sign is optional.
ODOM = re.compile(r"([0-9.]+)s odom x=\s*([+-]?[0-9.]+) y=\s*([+-]?[0-9.]+)")


def read_cmd(path):
    samples = []
    try:
        for line in open(path):
            m = CMD.search(line)
            if m:
                samples.append((float(m.group(1)), float(m.group(2))))
    except OSError:
        pass
    return samples


def read_odom(path):
    points = []
    try:
        for line in open(path):
            m = ODOM.search(line)
            if m:
                points.append((float(m.group(1)), float(m.group(2)), float(m.group(3))))
    except OSError:
        pass
    return points


def count_speed_limits(path):
    try:
        return sum(1 for line in open(path) if line.strip().startswith("speed_limit:"))
    except OSError:
        return None


def main():
    record_path, cmd_path, odom_path, speed_path = sys.argv[1:5]
    try:
        lines = [line for line in open(record_path).read().splitlines() if line.strip()]
    except OSError:
        print("merge_physical: no record file yet", file=sys.stderr)
        return
    if not lines:
        return

    record = json.loads(lines[-1])
    cmd = read_cmd(cmd_path)
    odom = read_odom(odom_path)
    nonzero = [(t, v) for t, v in cmd if abs(v) > 1e-6]

    physical = {
        "cmd_vel_samples": len(cmd),
        "cmd_vel_nonzero_samples": len(nonzero),
        "observed_max_cmd_vel_m_s": round(max((abs(v) for _, v in cmd), default=0.0), 4)
        if cmd
        else None,
        "first_nonzero_cmd_vel_s": nonzero[0][0] if nonzero else None,
        "last_nonzero_cmd_vel_s": nonzero[-1][0] if nonzero else None,
        "odom_samples": len(odom),
        "odom_displacement_m": round(
            ((odom[-1][1] - odom[0][1]) ** 2 + (odom[-1][2] - odom[0][2]) ** 2) ** 0.5, 4
        )
        if len(odom) >= 2
        else None,
        "speed_limit_publications": count_speed_limits(speed_path),
        "note": "commanded velocity and odometry as observed on ROS topics; not wheel measurements",
    }
    record["physical"] = physical
    if physical["last_nonzero_cmd_vel_s"] is not None:
        record["timing"]["last_nonzero_cmd_vel_at_ms"] = int(
            physical["last_nonzero_cmd_vel_s"] * 1000
        )
    if physical["speed_limit_publications"] is not None:
        record["execution"]["speed_limit_events"] = physical["speed_limit_publications"]

    lines[-1] = json.dumps(record)
    with open(record_path, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"merge_physical: {physical}")


if __name__ == "__main__":
    main()
