# kern-nav2-bridge

The ROS 2 half of the Kern Nav2 adapter: a `Nav2Backend` implemented over
`nav2_msgs/action/NavigateToPose` with `r2r`.

## Why this crate is outside the Kern workspace

`r2r` generates its message bindings at build time from a sourced ROS 2
installation, so it cannot build on a machine without ROS. Keeping it out of the
workspace means:

* `cargo fmt`, `cargo clippy --all-targets --all-features`, `cargo test
  --all-features`, and `cargo build --no-default-features` stay runnable on any
  machine, with no ROS installed;
* no ROS dependency can drift into `kern-execution`, which stays `no_std`.

Everything ROS-free — the unit conversion, the failure mapping, the observation
state machine, the speed-bound rule — lives in `crates/kern-execution-nav2` and
is covered by those gates. This crate is the transport only.

## Build

```bash
source /opt/ros/jazzy/setup.bash          # provides AMENT_PREFIX_PATH for r2r
cd adapters/nav2-bridge
cargo build --release
```

Requires `libclang` (`sudo apt install clang libclang-dev`) for `r2r`'s bindgen
step, and `ros-jazzy-nav2-msgs`.

On a machine with the whole Nav2 and Gazebo stack installed, constrain the
message generation or `rustc` will run out of memory generating bindings for
every package on `AMENT_PREFIX_PATH`:

```bash
export IDL_PACKAGE_FILTER="builtin_interfaces;std_msgs;geometry_msgs;action_msgs;unique_identifier_msgs;nav_msgs;geographic_msgs;nav2_msgs"
```

`geographic_msgs` is required because `nav2_msgs` references `GeoPose`.

## Run

```bash
# with kern_nav2_demo already launched (Gazebo + Nav2)
cargo run --bin kern-nav2-demo -- expiry    --ttl-ms 6000 --x-mm 6000
cargo run --bin kern-nav2-demo -- allowed   --ttl-ms 120000
cargo run --bin kern-nav2-demo -- supersede --ttl-ms 120000
```

## Threading

```text
Kern thread                         worker thread
  Nav2Backend method   --cmd-->     SyncSender, capacity 1
                       <-reply--    reply channel, 2 s deadline
  poll_event()         <--------    Mutex<EventQueue>, bounded
                                    r2r node spin + action futures
```

No Tokio. The worker drives futures with `now_or_never` between `spin_once`
calls, so nothing async escapes into Kern's synchronous traits. Every Kern-side
call has a deadline; a deadline that elapses becomes `Unknown`, never a claim
about the robot. A panic in the worker is caught at the thread boundary and
surfaces as lost events, which Kern reads as loss of knowledge.

## Verification status

Compiled and run against ROS 2 Jazzy with `r2r` 0.9.5, first against an `rclpy`
`NavigateToPose` server (`integration/`) and then against the full Gazebo
Harmonic + Nav2 stack (`ros2/kern_nav2_demo/validation/`). Verified live:
authorized navigation to completion, lease expiry mid-navigation with
cancellation confirmed, supersession, a killed action server becoming
`Unknown{Result}`, cancellation into a dead server becoming `RequestUnknown`,
and the authorized speed bound reaching the controller before every goal.
