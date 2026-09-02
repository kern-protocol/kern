# Heterogeneous physical-system validation

> Kern applies capability-scoped authority across heterogeneous AI-controlled
> physical systems. Authority for one machine does not automatically authorize
> another machine or another capability.

That is the whole claim. Not universal robot safety, not industrial
certification, not safe human-robot collaboration, not guaranteed emergency
stopping, and not deterministic physical stopping. Kern governs authority; it
does not certify physical safety.

## Three machines, one architecture

| machine | `DeviceId` | capability | adapter | Gazebo |
|---|---|---|---|---|
| cafe delivery robot | `cafe_robot` | `navigate(destination_x_mm, destination_y_mm, yaw_mdeg, max_speed_mm_s)` | `kern-execution-nav2` | DiffDrive base under Nav2 |
| conveyor workstation | `conveyor_01` | `transfer_item(destination_station, max_speed_mm_s)` | `kern-execution-conveyor` | one prismatic joint |
| robotic arm | `robotic_arm_01` | `pick_and_place(source_zone, destination_zone)` | `kern-execution-arm` | two revolute joints |

Every one of them reaches the simulator the same way:

```text
natural-language instruction
  -> a live model, through the Phase 7 OpenAI-compatible provider
  -> UNTRUSTED bytes
  -> strict local parser
  -> a *logical* target name
  -> trusted DeviceRouter -> DeviceId
  -> CapabilityRegistry::resolve -> CapabilitySchema::normalize
  -> Authority::decide -> AuthorizedOperation
  -> mint_challenge -> issue_v2 -> install -> LeaseHandle
  -> that machine's own ExecutionGovernor and adapter
  -> ROS 2 -> Gazebo
```

Nothing in that chain is machine-specific until the last two steps.

## Why the machines are not motors

Each machine exposes a *semantic* operation, and deliberately not the actuator
underneath it:

- The conveyor exposes a **transfer to a named station**, not a direction, a
  duration, a velocity setpoint, or a PWM value. A transfer is the thing a
  policy can bound; a motor command is not.
- The arm exposes a **task between two named zones**, not a joint angle, a
  trajectory, or a torque. Zone names become joint poses only through trusted
  adapter configuration, which is the one place a joint angle appears at all.

Both parameters of `pick_and_place` are symbols, so the authorized set of zones
*is* the authorized workspace, expressed with the constraint algebra that
already existed. No new algebra, no new lease version, no new wire format.

## Three authority slots

An authority slot is `(issuer, subject, device, capability)`. Three distinct
`DeviceId`s therefore give three structurally separate authorities, and the
registry gives each machine exactly one capability:

```text
cafe_robot      -> navigate         only
conveyor_01     -> transfer_item    only
robotic_arm_01  -> pick_and_place   only
```

A crossed pairing — `cafe_robot` + `pick_and_place`, `conveyor_01` + `navigate`,
`robotic_arm_01` + `transfer_item` — fails at `CapabilityRegistry::resolve`,
before any policy is consulted. That is an *unknown operation* rather than a
forbidden one, which is the honest distinction, and the model cannot broaden it.

## Three policies, not one

```text
cafe_robot      max_speed_mm_s in [1, 400]
                destination_x_mm in [-7000, 7000]
                destination_y_mm in [-1000, 1000]
                yaw_mdeg in [-180000, 180000]

conveyor_01     max_speed_mm_s in [1, 300]
                destination_station in {station_a, station_b}

robotic_arm_01  source_zone      in {pickup_zone, serving_tray}
                destination_zone in {pickup_zone, serving_tray}
```

Collapsing these into one permissive grant would make "the planner may operate
robots" the unit of authority, which is precisely the shape Kern exists to
refuse.

The speed bounds are two-sided. Phase 8 recorded that an upper-bound-only policy
authorizes a zero or negative speed, which the adapter then refuses one layer
lower; the heterogeneous world closes that in the *policy*, where it belongs.
The Phase 8 `corridor` world is left exactly as it was, so the evidence that
recorded the gap stays valid.

## Device targeting

A model may write `"target": "conveyor_01"`. That string is a **request**, not a
selection. It becomes a `DeviceId` only by being found in a `DeviceRouter` the
host built, and a name that is not in the router resolves to nothing at all —
no fallback, no fuzzy match, no construction of a `DeviceId` from model text.

`DeviceId::new` accepts any string, so without this boundary a model could name
a machine nobody configured. With it, the set of reachable machines is exactly
the set the host enumerated. Routing is still not authorization: resolving a
name says which machine the proposal is *about*.

## The proposal contract, extended

```json
{
  "target": "conveyor_01",
  "capability": "transfer_item",
  "arguments": { "destination_station": "station_b", "max_speed_mm_s": 200 },
  "reason": "Move the package to station B"
}
```

Two deliberate extensions to the Phase 7 contract, both reported as such:

1. **`target` is a new, optional key.** A response omitting it is still valid and
   uses the host's own device, which is the Phase 7 behaviour unchanged.
2. **An argument value may be a JSON string as well as an integer.** The parser
   has not met a schema and cannot know which domain a parameter wants, so it
   accepts either and lets `CapabilitySchema::normalize` refuse the mismatch. A
   quoted `"6000"` offered for a scalar parameter is therefore a *domain*
   rejection one stage later rather than a parse rejection — still before
   policy, still before any authority exists. The containment property is
   unchanged; only the stage that reports the refusal moved.

Everything else is still refused: unknown targets, unknown capabilities, unknown
arguments, missing fields, extra fields, floats, booleans, nulls, nested
objects, integers outside `i64`, more than one operation, and every reserved
authority field (`ttl`, `issuer`, `key_id`, `nonce`, `challenge`,
`enforcer_session`, `lease_id`, `policy_id`, `execution_id`).

## The world

`ros2/kern_nav2_demo/worlds/kern_workspace.sdf` is the Phase 6 corridor,
unchanged, plus the two workstations at `y = ±3` — inside the corridor-wall `x`
range where `maps/kern_corridor.pgm` already marks the floor occupied. Nav2
plans exactly the paths it always did, and the map did not have to be
regenerated.

```text
  table_1                     corridor (y in [-1.5, 1.5])              table_3
     |                                                                    |
  [conveyor_01 at (-2, +3)]  ------  cafe_robot  ------>  goal at x = 6000
  [robotic_arm_01 at (-2, -3)]
```

## What "completed" means for each machine

- **Cafe robot**: Nav2's own action result. Kern reports what the action server
  reported.
- **Conveyor and arm**: the commanded setpoint reached its target **and** the
  observed joint settled within tolerance of it for 400 ms. The second half is
  what makes it evidence rather than an assertion — without the joint-state
  subscription it would only say the adapter finished publishing.

Tolerances are per machine: 20 mm for the belt, 0.06 rad (about 3.4°) for the
arm. The arm's is wider because a revolute joint holding a pose against gravity
sits at a steady-state error the position controller does not remove. A
tolerance tighter than the controller's own error would mean the arm never
settles and every motion ends as a fault, which would be a statement about the
tolerance rather than about the machine.

None of this is a claim about a package or a cup. Kern observes what the
simulator reports about a *joint*, and says no more than that.

## Reproduction

```bash
docker build -t kern-sim -f adapters/nav2-bridge/integration/Dockerfile.sim \
  adapters/nav2-bridge/integration

docker run --rm \
  -e SCENARIOS="cafe conveyor arm cafe_denied conveyor_denied arm_denied injection cross concurrent" \
  -e KERN_MODEL_PROVIDER=ollama-cloud \
  -e OLLAMA_API_KEY \
  -e KERN_MODEL_ID=nemotron-3-super \
  -v "$PWD":/work -v "$PWD/ros2/kern_nav2_demo/validation":/scratch -w /work \
  kern-sim bash /scratch/stage6_heterogeneous.sh
```

The model runs in Ollama Cloud over HTTPS; `-e OLLAMA_API_KEY` passes the host's
key through without putting it on a command line. The container needs outbound
HTTPS and nothing else — no GPU, no weights, no local daemon.

Long scenarios are better run a few at a time: each brings the whole stack up
once, and `concurrent` needs the corridor clear.

Offline, with no simulator and no network:

```bash
cargo test -p kern-execution-conveyor -p kern-execution-arm
cargo test -p kern-eval --test heterogeneous
```

## Limitations

- The conveyor "package" is the prismatic joint's child link, so moving the
  joint moves the package by construction. There is no grasping, no friction
  transport, and no failure mode where the package stays behind.
- The arm does not grasp anything. `pick_and_place` moves the arm through the
  source pose and then the destination pose; the cup is scenery. A real gripper,
  and the failure modes that come with one, are not modelled.
- The arm is two revolute joints with no wrist and no collision-aware planning.
  It reaches poses, not points in a workspace.
- Speed bounds are *commanded* limits: a Nav2 controller speed limit, a belt
  setpoint rate, an arm joint setpoint rate. None is a measurement of a wheel,
  a belt surface, or a joint.
- The live model's output is not reproducible, and the sample here is a handful
  of runs. It is integration evidence, not a statistical claim.
