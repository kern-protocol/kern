# Nav2 Integration

This documents the implemented robotics edge: the Nav2 executor, the `r2r`
(ROS 2) bridge adapter, and the Gazebo demo. The split enforces the
`AGENT.md` §17 rule — ROS, Gazebo, Nav2, and vendor logic live in adapters,
never in the core authority model.

```text
kern-execution            ROS-free Executor trait + governor
    |
    | SemanticCommand
    v
kern-execution-nav2       Nav2Executor<B: Nav2Backend>   (ROS-free)
    |                     + FakeNav2Backend (deterministic, ROS-free)
    v
adapters/nav2-bridge      RosNav2Backend : Nav2Backend    (r2r, ROS 2)
    |                     + kern-nav2-demo binary
    v
ROS 2 / Nav2 / Gazebo
```

`kern-execution-nav2` has **no ROS dependency**. All `r2r` lives in
`adapters/nav2-bridge`, which is excluded from the Cargo workspace because it
links against a sourced ROS installation and cannot build on a machine without
ROS. The Gazebo world and Nav2 parameters live in `ros2/kern_nav2_demo`, an
`ament_cmake` package.

## 1. The `navigate` capability (`kern-execution-nav2::capability`)

```text
NAVIGATE = "navigate"
params:
  DESTINATION_X_MM   Scalar (mm)
  DESTINATION_Y_MM   Scalar (mm)
  YAW_MDEG           Scalar (millidegrees)
  MAX_SPEED_MM_S     Scalar (mm/s)
```

`navigate_schema` is a frozen 4-parameter `CapabilitySchema`. `NavigateRequest`
is the i64 integer nav command extracted from a `SemanticCommand` via
`NavigateRequest::from_command`, which re-checks `capability == navigate`, the
four scalar params present, and `max_speed_mm_s > 0` (refusal ->
`CommandError`).

> **Status note (`AGENT.md` §18):** the café mobile robot reference domain lists
> `navigate, wait, return_to_base, speak`. Only `navigate` is implemented. The
> authority dimensions `destination` and `max_speed` and `lease lifetime` are
> modeled; `zone` and `mission` are not modeled as capability parameters (the
> costmap/map and policy numeric bounds approximate zoning). The robot-arm and
> rail/conveyor reference domains are not implemented. The generic lease model
> is preserved: no `RobotLease`/`Nav2Lease` type exists; `navigate_schema` is a
> domain-specific schema over the generic `CapabilityLease`.

## 2. The unit boundary (`kern-execution-nav2::units`)

The int→float boundary is here, at the adapter edge — never in `kern-core`:

```text
mm_to_m, mm_s_to_m_s, mdeg_to_rad, yaw_quaternion
```

`kern-core` compares `i64` scalars; floats exist only in the conversion to ROS
messages. `yaw_quaternion` produces `(qz, qw)` for a heading.

## 3. The backend transport trait (`kern-execution-nav2::backend`)

```rust
pub trait Nav2Backend {
    fn declaration(&self) -> &BackendDeclaration;
    fn apply_speed_limit(&mut self, mm_s: Option<f64>) -> SpeedLimitOutcome; // Applied | NotDelivered | Unknown
    fn send_goal(&mut self, goal: &Nav2Goal) -> SendGoal;   // Accepted | Rejected | Unknown
    fn cancel_goal(&mut self, op: Nav2OperationId) -> CancelSend; // Accepted | AlreadyTerminal | Rejected | Unknown | Disconnected
    fn poll_event(&mut self) -> BackendPoll;                // Event | Idle | Disconnected | EventsLost
    fn shutdown(&mut self);
}
```

`Nav2OperationId` wraps a goal UUID `[u8; 16]`. `Nav2Goal` carries `frame_id`,
x/y/yaw/qz/qw, `max_speed_m_s`, and an `ExecutionId` for correlation only (never
authority). Backend methods take **no `Result`**: uncertainty is classified into
`Rejected`/`Unknown`/`Disconnected`, not propagated as an error. `BackendEvent`
is `Feedback | Succeeded | Aborted | Canceled`.

## 4. `Nav2Executor` (`kern-execution-nav2::executor`)

`Nav2Executor<B: Nav2Backend>` implements `Executor` + `ExecutorObservations`
over a generic transport. One goal at a time (Nav2 replaces; the speed limit is
controller-wide).

### submit

1. `NavigateRequest::from_command` — re-checks capability and params. Refusal ->
   `SubmitOutcome::Rejected(InvalidCommand)`.
2. `has_live_operation() || !make_room()` -> `Rejected(Busy)`.
3. `backend.apply_speed_limit(...)` **before** the goal exists. `NotDelivered`/
   `Unknown` -> clear and `Rejected(Unavailable)`, **no goal sent**. `Applied` ->
   `speed_limit_applied = true`.
4. Convert int→float via `units` into a `Nav2Goal`.
5. `backend.send_goal`:
   - `Accepted { operation }` -> track, return `Accepted`.
   - `Rejected { reason }` -> clear the limit, `Rejected`.
   - `Unknown` -> **the limit stays applied** (never remove a bound from a
     possibly-live operation), return `Unknown`.

### on_authority_lapse

Only `LapseAction::Cancel` is supported (the declaration sets
`LapseActionSet::none().with(Cancel)`; Hold/Terminate are unsupported). Maps to
`backend.cancel_goal`. `Unknown`/`Disconnected` -> `Unknown` (uncertainty, never
a refusal). An untracked goal -> `Unknown` (no claim about an unseen machine).

### poll_observation

Drains `backend.poll_event`. `BackendEvent` maps to `ObservedReport`:
`Succeeded -> Completed`, `Aborted -> Failed(OperationFailed)` (a machine
attempt, not a transport fault), `Canceled -> Cancelled`, `Feedback -> Running`.
`Disconnected`/`EventsLost` -> `ObservationPoll::Disconnected` (loss of
knowledge, never a failure claim). Terminal events clear the speed limit when no
live operation remains.

### Declaration

`accept_implies_running = false` (Nav2 goal acceptance is not motion; first
feedback = Running), `echoes_execution_id = false` (Nav2 mints its own UUIDs;
there is no field for a Kern id), `ordering = Sequenced` (adapter-local sequence
per operation). `ExecutorReconcile`/`ExecutorQuery` are deliberately
unimplemented for Nav2.

## 5. `FakeNav2Backend` (`kern-execution-nav2::fake`)

A deterministic, ROS-free `Nav2Backend` for tests and the demo without a robot.
Default: connected, `ControllerSpeedLimit`, confirms cancellation, reports
terminal results. It **scripts every fault the contract admits** rather than
provoking them on real hardware:

- `script_send` / `script_cancel` / `script_speed_limit` — queue the next
  outcome.
- `emit(BackendEvent)` — feed Feedback/Succeeded/Aborted/Canceled.
- `disconnect` / `reconnect` — toggle the link.
- `fail_worker` — `worker_failed`; `poll_event` returns `EventsLost` (a dead
  worker is reported before queued events).
- `with_queue_capacity` + `EventQueue` overflow -> `dropped` counter;
  `poll_event` reports `EventsLost` once.
- Public fields for assertions: `sent`, `cancelled`, `speed_limits` (None =
  clear), `shutdowns`.
- `sim_time_ms` is deliberately **inert** — Kern never reads sim time; authority
  lifetime runs on the enforcer's monotonic clock alone.

This is the deterministic simulator requirement of `AGENT.md` §13, served at the
adapter layer.

## 6. `RosNav2Backend` (`adapters/nav2-bridge`)

Implements `Nav2Backend` over `r2r`. Threading keeps the Kern side synchronous
and the ROS state on a worker thread:

- **Kern thread**: synchronous `RosNav2Backend` handle.
- **Worker thread**: owns all ROS state (`r2r` types are `!Send` and never cross
  threads). Commands arrive via a `sync_channel(1)` with a bounded reply channel
  and `COMMAND_TIMEOUT = 2s`; elapsed -> `Unknown`. Events return via a shared
  `Mutex<EventQueue>` (bounded, drop-newest). A worker panic sets a
  `worker_failed` atomic -> `BackendPoll::EventsLost`.

### Worker loop

`Context::create`, `Node::create`, a `NavigateToPose` action client, and a
`SpeedLimit` publisher on `/speed_limit`. Each iteration: `inbox.recv_timeout`
(10ms spin slice), dispatch `Command::{SpeedLimit, SendGoal, Cancel, Shutdown}`,
`node.spin_once`, drain feedback and results into the queue. On exit, publishes
`SpeedLimit { speed_limit: 0.0 }` to restore the controller.

### Availability is debounced, not guessed

The action server's reachability is re-checked every `AVAILABILITY_INTERVAL`
(500ms) with a `AVAILABILITY_BUDGET` (200ms) spin budget. A single slow poll is
not a dead server — on a loaded machine one check can exceed its budget while
Nav2 is healthy, and reporting that as a disconnect would turn every hiccup into
an execution Kern says it can no longer see. The link is called lost only after
`AVAILABILITY_MISSES` (3) consecutive misses.

`server_is_available` resolves the `is_available` future against the budget.
An earlier version of this file checked exactly that the future could be created
and reported a killed server as healthy — a false claim that Kern can still see
an operation. The budget-elapsed check is what makes absence provable.

### Speed-limit delivery is proven, not assumed

`publish_speed_limit` refuses to report `Applied` when no subscriber is there. A
ROS publisher accepts a message whether or not any subscriber has been
discovered, and an unmatched publish is silently dropped — reporting that as
`Applied` would let a goal run with an authorized bound that never reached the
controller, which is the one failure this phase forbids outright. So the worker
checks `get_inter_process_subscription_count`; if zero, it waits up to
`SUBSCRIBER_WAIT` (1s) for a subscriber, and returns `NotDelivered` if none
appears. The executor then sends **no goal** and Kern records
`NotStarted(Rejected(Unavailable))`. An authorized `max_speed_mm_s` that nothing
applies is never accepted.

This proves that *a* subscriber to the configured topic exists and that the
message was handed to a reliable publisher. It does not prove the subscriber is
`controller_server`, and not that any wheel turned more slowly: the topic name is
configuration, and the bound is a command to a controller.

### send_goal

`is_available` wait (1.5s); absent -> `Rejected(Unavailable)` (provably nothing
sent). Build `NavigateToPose::Goal` from `pose_stamped(goal)` with an empty
behavior tree. `send_goal_request` then `await_with_spin` (1.5s):
`Ok((handle, ...))` -> `Nav2OperationId::from_uuid(*handle.uuid.as_bytes())`,
track, `Accepted`. `Err` -> `Rejected(Refused)`. Timeout -> `Unknown`.

### Feedback, not acceptance, is "running"

`drain` reads the first credible feedback as the only signal that the operation
is running — goal acceptance is not. A `reported_feedback` flag ensures one
`Running` event per tracked goal. A result that resolves maps `ResultStatus`
(`Succeeded`/`Aborted`/`Canceled`/`Unknown`) to a `BackendEvent`.

`pose_stamped` is the single Kern-goal -> ROS-message conversion site.

## 7. The speed-limit seam

The `max_speed` authority dimension is enforced on the `/speed_limit` topic,
consumed by `nav2_controller` and passed to the controller plugin's
`setSpeedLimit`. This is a **commanded controller speed limit**, not a
wheel-speed guarantee. The `SpeedLimit` message uses `percentage: false`
(absolute m/s, not a percentage of an unknown maximum). The lease bound is
applied on top of the vehicle's own ceiling; the `velocity_smoother` max is set
at/above the controller ceiling so the smoother is not a hidden second bound.

## 8. The `kern-nav2-demo` binary (`adapters/nav2-bridge/src/main.rs`)

The demo wires the full Kern side in one process. This is a **demo topology,
not a deployment** — the issuer key lives in the edge process, which is
explicitly disclaimed.

- `UptimeClock` — process `Instant` (not ROS/Gazebo sim time).
- `OsChallenges` — CSPRNG `ChallengeSource` via `getrandom`.
- `Ed25519Signer` from `DEV_SEED = [7u8; 32]`; `TrustStore` authorizes
  `issuer_dev` / `dev-1`.
- `EnforcerStore` — session, trust, clock, challenges, 2s challenge TTL,
  capacity 4/4.
- `LeaseIssuer` — `SystemClock`, `CountingNonces`, `SequentialLeaseIds::starting_at(1)`.
- `RosNav2Backend::start` — connects to `/navigate_to_pose` by default.
- `Nav2Executor::new(backend, Nav2Config { frame "map", capacity 8 })`.
- `ExecutionGovernor` — `capacity 4, journal_capacity 128, lapse_action: Cancel,
  startup_policy: ReportOnly, observation_budget 16`.

### The policy

`CapabilityRegistry` registers `navigate_schema` for `cafe_bot_01`. A
`Policy::new("delivery")` selects `planner_a` / `cafe_bot_01` / `navigate` with
`MAX_SPEED_MM_S at_most 400`, destination X/Y in `[-20000, 20000]` mm, yaw in
`[-180000, 180000]` mdeg. `Authority::evaluate` -> `AuthorizedOperation::from_evaluation`.

### install

`store.mint_challenge` -> `re_authorize` (re-runs policy so issuance signs an
`AuthorizedOperation`, not a proposal) -> `issuer.issue_v2(..., Ttl, &ticket)` ->
`encode_v2` -> `store.install`.

### The loop

`governor.prepare(&store, &handle, &operation)` -> `prepared.submit(&store, &mut adapter)`
-> receipt. Then until `run_for` (default 90s) or terminal:
`governor.tick_observed`, print `render_execution(record, ...)`, flag a
`session_mismatch` as a wiring fault. Sleep 100ms between ticks.

### Scenarios

```text
allowed    lease long enough; operation completes under authority
expiry     lease shorter than the drive; authority lapses mid-navigation
supersede  a second lease installed into the same slot while the first runs
```

Defaults: scenario `expiry`, TTL 6000ms, x=6000mm, y=0, yaw=0, speed 300mm/s,
action `/navigate_to_pose`.

Flags: `--ttl-ms`, `--x-mm`, `--y-mm`, `--yaw-mdeg`, `--speed-mm-s`, `--action`,
`--run-for-s`, and `--authority-watch-s`.

### Authority lifetime is watched against process uptime

With `--authority-watch-s N`, after the execution ends the binary keeps calling
`store.check_authority(&handle)` against process monotonic uptime for N seconds.
This is the concrete demonstration of `AGENT.md` §7: lease lifetime is measured
against `std::time::Instant`, never ROS or Gazebo simulation time. If the
simulator is paused, `/clock` stops but the authority deadline does not — a
paused simulator cannot freeze a lease. The validation harness exercises this
with `PAUSE_GZ`.

The binary exits by printing: *"Kern requested what it could and recorded what
it saw. It makes no claim about whether the machine physically stopped."*

## 9. The Gazebo demo package (`ros2/kern_nav2_demo`)

`kern_demo.launch.py` starts the **robot side only**; Kern is a separate
process (`cargo run --bin kern-nav2-demo -- expiry --ttl-ms 6000`):

1. Gazebo Harmonic via `ros_gz_sim/gz_sim.launch.py` with
   `worlds/kern_corridor.sdf`, `-r`, headless by default (server-only for CI).
2. `ros_gz_bridge` `parameter_bridge` bridging `/clock`, `/cmd_vel`, `/odom`,
   `/scan`, `/tf`, `/joint_states`; `use_sim_time := true`.
3. `robot_state_publisher` from `worlds/kern_bot/model.sdf` (diff-drive
   `kern_bot`).
4. Nav2 via `nav2_bringup/bringup_launch.py` with
   `params/kern_nav2_params.yaml`, `map := maps/kern_corridor.yaml`,
   `autostart := true`, `use_sim_time := true`.
5. `rviz2` with `rviz/kern_demo.rviz`, gated by a launch arg (default off).

`params/kern_nav2_params.yaml`: amcl (initial pose x=-8.0), map_server
(`kern_corridor.yaml`), controller_server with `speed_limit_topic: /speed_limit`
(the Kern seam) and `FollowPath = RegulatedPurePursuitController`
(`desired_linear_vel: 0.4`, the vehicle ceiling), local/global costmaps
(`robot_radius 0.26`, scan obstacle layer), planner_server `NavfnPlanner`,
behavior_server, bt_navigator, `velocity_smoother`
(`max_velocity: [0.4, 0.0, 2.0]`), lifecycle autostart.

### The world and the map are one geometry

`maps/generate_map.py` regenerates `kern_corridor.pgm` from the same numbers as
`kern_corridor.sdf` — a 20 x 10 m world, a 2 m corridor (±1.5 m lane), two static
obstacles. The occupancy map and the simulated world must agree. They disagreed
once: the SDF corridor walls left a 0.2 m gap where the map said 2 m, and Nav2
planned happily through a wall the robot then drove into. The geometry now lives
in one place and the map is regenerated rather than hand-edited. The robot starts
at `(-8, 0)`; the demo drives it to `(6, 0)` — about 14 m, which at the authorized
0.3 m/s is roughly 45 s of motion, so a 6 s lease expires while the robot is
still moving.

## 10. Integration harness (Layer 3, `adapters/nav2-bridge/integration/`)

The bridge runs against a **real** `r2r` ROS 2 action client and a real spin
thread, but a **fake** `rclpy` `NavigateToPose` action server — no Gazebo, no
Nav2, no robot. Fast and deterministic enough to run on every change to the
bridge.

- `fake_nav2_server.py` — a minimal `NavigateToPose` server with goal
  acceptance, feedback, cancellation, and terminal results. It also subscribes
  to `/speed_limit`, so a run proves the authorized speed bound reached a
  subscriber **before** the goal was sent. That check caught a real defect: an
  unmatched publisher silently dropped the limit and the adapter reported it as
  applied.
- `run_scenario.sh` — `run_scenario.sh <scenario> <lease-ttl-ms>
  <server-seconds> [normal|reject] [kill-after-s]`. Drives the bridge through a
  scenario and optionally kills the action server mid-goal.
- `Dockerfile` — `ros:jazzy-ros-base` + Rust + `nav2-msgs`, for the Layer 3
  harness on any machine.
- `Dockerfile.sim` — the full simulation environment (ROS 2 Jazzy + Gazebo
  Harmonic + Nav2 + `ros_gz` + software rendering via `llvmpipe`), used by the
  validation harness.

| command | what it proves |
| --- | --- |
| `allowed 60000 8` | speed limit published, then goal accepted, feedback -> Running, SUCCEEDED -> Completed |
| `expiry 6000 40` | authority lapses while Running, cancel requested, CANCELED -> Cancelled |
| `supersede 60000 40` | a newer lease lapses the old execution and does not adopt it |
| `allowed 60000 40 normal 8` | a dead action server becomes `Unknown{Result}`, never `Failed` |
| `expiry 12000 40 normal 6` | cancelling into a dead server becomes `RequestUnknown` |
| `allowed 60000 10 reject` | an explicitly refused goal becomes `NotStarted(Rejected(Refused))` |

## 11. Validation harness — Phase 6 acceptance (`ros2/kern_nav2_demo/validation/`)

The scripts that accepted Phase 6. They run the real launch file, the real Nav2
stack, and the real Kern bridge inside a container built from `Dockerfile.sim`.

- `stage1_launch_check.sh` — launches the demo, then enumerates nodes, topics,
  `/tf` and `/tf_static`, `/scan`, `/odom`, `/map`, the `map -> base_link` and
  `odom -> base_link` TF chains, and the Nav2 lifecycle states. Proves the stack
  actually comes up and the TF chain is real.
- `stage2_navigation.sh` — ordinary navigation via `nav_probe.py`, and the speed
  bound at the controller. Proves the robot drives and the authorized bound
  reaches the controller.
- `stage3_kern_e2e.sh` — the real Kern bridge against the live Gazebo + Nav2
  stack. Runs `SCENARIO` (`allowed` / `expiry` / `supersede`) with `TTL_MS` and
  `RUN_FOR`, records `/cmd_vel` and `/odom`, and injects faults:
  - `KILL_BT` + `KILL_MODE=kill` — `SIGKILL` the Nav2 component container so no
    result can be sent -> `Unknown{Result}`.
  - `KILL_BT` + `KILL_MODE=deactivate` — **not** a disconnect test. Deactivating
    `bt_navigator` makes the action server abort its goal and tell the client,
    so Kern records `Failed`, correctly.
  - `PAUSE_GZ` — pauses Gazebo `/clock` mid-run; authority lifetime, measured
    against process uptime, is unaffected. `WATCH` keeps checking
    `check_authority` after the execution ends.
- `cmd_recorder.py`, `odom_recorder.py`, `nav_probe.py` — record `/cmd_vel`,
  `/odom`, and drive a probe goal.

`stage3` sets `IDL_PACKAGE_FILTER` for the bridge build: `r2r` otherwise
generates bindings for every message package on `AMENT_PREFIX_PATH`, which with
the full Nav2 + Gazebo stack is enough to run `rustc` out of memory on a small
machine.

## 12. How it is tested

- `crates/kern-execution-nav2/tests/governor.rs` — the Nav2 executor under the
  governor: submit, speed-limit-before-goal, lapse -> cancel, observation
  mapping, expiry mid-navigation.
- `crates/kern-execution-nav2/tests/mapping.rs` — int→float unit conversion,
  `NavigateRequest` extraction, command-digest stability.
- `crates/kern-execution-nav2/examples/demo.rs`, `harness.rs` — runnable
  ROS-free demos using `FakeNav2Backend`.
- The `r2r` bridge is not unit-tested in the workspace (it needs ROS). It is
  exercised by the Layer 3 integration harness (§10) against a fake `rclpy`
  action server, and by the Phase 6 validation harness (§11) against the live
  Gazebo + Nav2 stack.