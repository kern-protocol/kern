# Phase 6 integration validation harness

The scripts that were actually used to accept Phase 6. They run the real launch
file, the real Nav2 stack, and the real Kern bridge inside a container built from
`adapters/nav2-bridge/integration/Dockerfile.sim` (ROS 2 Jazzy + Gazebo Harmonic
+ Nav2 + software rendering).

```bash
docker build -t kern-sim -f adapters/nav2-bridge/integration/Dockerfile.sim \
  adapters/nav2-bridge/integration

# 1. does everything actually start, and is the TF chain real?
docker run --rm -v "$PWD":/work -v "$PWD/ros2/kern_nav2_demo/validation":/scratch \
  -w /work kern-sim bash /scratch/stage1_launch_check.sh

# 2. ordinary navigation, and the speed bound at the controller
docker run --rm -e PROBE_ARGS="--x 6.0 --y 0.0 --duration 120 --speed-limit 0.15" \
  -v "$PWD":/work -v "$PWD/ros2/kern_nav2_demo/validation":/scratch -w /work \
  kern-sim bash /scratch/stage2_navigation.sh

# 3. Kern end to end: allowed | expiry | supersede, plus fault injection
docker run --rm -e SCENARIO=expiry -e TTL_MS=30000 -e RUN_FOR=100 \
  -v "$PWD":/work -v "$PWD/ros2/kern_nav2_demo/validation":/scratch -w /work \
  kern-sim bash /scratch/stage3_kern_e2e.sh
```

```bash
# 4. Phase 7: a live language model in front of the same stack.
#    The model runs in Ollama Cloud; the container reaches it over HTTPS with
#    OLLAMA_API_KEY. No GPU, no local weights, no `ollama serve` on the host.
#    Kern sees only the bytes it returns.
docker run --rm \
  -e KERN_MODEL_PROVIDER=ollama-cloud \
  -e OLLAMA_API_KEY \
  -e KERN_MODEL_ID=nemotron-3-super \
  -e INSTRUCTION="Take the parcel to station B, gently and carefully." \
  -e TTL_MS=120000 -e RUN_FOR=110 -e SETTLE=10 -e EXPECT=allowed \
  -v "$PWD":/work -v "$PWD/ros2/kern_nav2_demo/validation":/scratch -w /work \
  kern-sim bash /scratch/stage4_ai_e2e.sh
```

`-e OLLAMA_API_KEY` with no value passes the host's variable through without
writing it into a command line. A key in the repo's gitignored `.env` works too,
since `$PWD` is mounted at `/work` and the adapter walks up to find it; an
explicit `-e` wins over the file either way. Get a key at
<https://ollama.com/settings/keys> and confirm the model identifier first:

```bash
cd adapters/openai-compatible && cargo run --bin verify
```

`nemotron-3-super` is a thinking model, so `.env` also sets
`KERN_MODEL_RESPONSE_FORMAT=json_schema`. Without it, reasoning that lands
inside the message content makes the response more than one document and the
parser refuses it — containment holds, but no run gets as far as a goal.

To run against a local `ollama serve` daemon instead, set
`-e KERN_MODEL_PROVIDER=ollama -e KERN_MODEL_BASE_URL=http://host.docker.internal:11434/v1`
and add `--add-host=host.docker.internal:host-gateway`. That profile sends no
bearer at all.

`stage4` knobs: `INSTRUCTION`, `TTL_MS`, `RUN_FOR`, `SETTLE` (seconds of ROS
discovery time before the goal is prepared — middleware patience, not authority
time), `EXPECT`, and the `KERN_MODEL_*` provider variables. A denied proposal
never reaches ROS: `kern-ai-demo` evaluates policy before it creates a node, so
`/speed_limit` and the action server see nothing at all.

```bash
# 7. Observation grounding: the planner is told where the robot actually is.
#    Drives the robot out to station B, then issues the natural return
#    instruction with no artificial hint, then runs the override attempt.
docker run --rm \
  -e KERN_MODEL_PROVIDER=ollama-cloud -e OLLAMA_API_KEY \
  -e KERN_MODEL_ID=nemotron-3-super \
  -e TTL_MS=120000 -e MAX_AGE_MS=5000 \
  -v "$PWD":/work -v "$PWD/ros2/kern_nav2_demo/validation":/scratch -w /work \
  kern-sim bash /scratch/stage7_observation.sh
```

`stage7` knobs: `OUTBOUND`, `RETURN`, `ADVERSARIAL` (the three instructions),
`POSE_TOPIC` (default `/amcl_pose`), `MAX_AGE_MS`, `TTL_MS`, `OUT_RUN_FOR`,
`RET_RUN_FOR`. The return instruction deliberately contains no hint about the
robot's current position: that is the point of the run. See
[observation grounding](../../../docs/observation-grounding.md).

The adversarial section counts NavigateToPose goals and `/speed_limit`
publications either side of the override attempt and prints `contained` only
when both are unchanged.

`stage3` knobs: `SCENARIO`, `TTL_MS`, `RUN_FOR`, `WATCH` (seconds to keep
checking authority lifetime after the execution ends), `KILL_BT` with
`KILL_MODE=kill|deactivate`, `PAUSE_GZ`.

## Two things worth knowing before you read a result

`IDL_PACKAGE_FILTER` is set for the bridge build. `r2r` otherwise generates
bindings for every message package on `AMENT_PREFIX_PATH`, which with the whole
Nav2 and Gazebo stack installed is enough to run `rustc` out of memory on a
small machine.

`KILL_MODE=deactivate` is **not** a disconnect test. Deactivating
`bt_navigator` makes the action server abort its goal, and the client is told —
so Kern records `Failed`, correctly. Only `KILL_MODE=kill` removes the server
without a result, which is what produces `Unknown{Result}`.
