# Process Crash Tracer

This Linux eBPF program watches process exits and writes a JSON report for each qualifying crash. It records the process ID, user ID, process name, exit status, signal, timestamp, cgroup when available, and up to the last 10 failed `openat` and `connect` calls.

The tracer is system-wide while it is running; it is not limited to Docker or Kubernetes containers. It reports an exit when the process has a signal number greater than zero or an exit code greater than one. A normal exit and exit code `1` are ignored.

## Requirements

- Linux with BPF support, kernel BTF, syscall and scheduler tracepoints, ring-buffer support, and BPF v3 atomic operations. Linux 5.12 or newer is generally required.
- Go 1.25 or newer.
- Clang, LLVM tools, and libbpf headers for generating the eBPF object.

On Ubuntu, the build tools can be installed with:

```bash
sudo apt install clang llvm libbpf-dev
```

## Build

Run these commands from the project directory:

```bash
go generate
go build -o tracer
```

`go generate` compiles `bpf/trace.c` and refreshes the generated Go bindings and embedded BPF object.

## Run

Start the tracer from the project directory:

```bash
sudo ./tracer
```

It attaches to the `openat`, `connect`, and process-exit tracepoints. Leave it running while the applications you want to observe are running. Press `Ctrl+C` to stop it.

Each qualifying event is printed as JSON and saved as a separate file under `crash-reports/`. File names contain the UTC timestamp, process name, crash name, and PID. For example:

```text
crash-reports/20261117T204711.585051317Z_MainThread_SIGSEGV_pid27652.json
```

The directory is private (`0700`) and report files are private (`0600`). When launched with `sudo`, new reports are assigned to the user who invoked `sudo`, so they can be opened without root access.

## Run in Docker

Create a host directory for persistent reports:

```bash
mkdir -p "$PWD/crashes"
```

Assuming the image `ebpf-blackbox-recorder:latest` is already built, run it from the project directory:

```bash
docker run -d \
  --name ebpf-blackbox \
  --restart unless-stopped \
  --privileged \
  --pid=host \
  -e CRASH_REPORT_DIR=/app/crashes \
  -e CRASH_REPORT_UID="$(id -u)" \
  -e CRASH_REPORT_GID="$(id -g)" \
  -v "$PWD/crashes:/app/crashes" \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  ebpf-blackbox-recorder:latest
```

Reports are written to `./crashes` on the host. The UID and GID options make the files accessible to the user who started Docker. To follow tracer logs, run `docker logs -f ebpf-blackbox`; stop it with `docker stop ebpf-blackbox`.

The tracer does not use the Docker socket or host networking, so neither needs to be mounted or enabled. `--privileged` grants broad access to the host kernel; use this only with a trusted image on a machine you control.

## Try a local crash

Run the tracer in one terminal. In another terminal, run this test on a development machine:

```bash
node -e '
const fs = require("node:fs");
const net = require("node:net");

try {
  fs.readFileSync("/tmp/tracer-test-missing-file");
} catch (_) {}

const client = net.connect(59999, "127.0.0.1");
client.on("error", () => {
  process.kill(process.pid, "SIGSEGV");
});
'
```

This deliberately terminates the Node process with `SIGSEGV` and may create a core dump. Do not run it in production or against a process you need to keep alive.

## Report fields

- `crash_name`: signal name such as `SIGSEGV`, or `exit-code-N`.
- `occurred_at`: UTC timestamp in RFC 3339 format.
- `failed_calls`: up to 10 recorded failed `openat` or `connect` calls, including the negative return value and errno.
- `cgroup`: best-effort data from `/proc/<pid>/cgroup`; it may be omitted if the process has already disappeared.

The syscall history is diagnostic data. Reports can include file paths, IP addresses, and process metadata; keep the report directory access restricted.

## Limitations

- Only `openat` and `connect` are recorded; other syscalls are not included.
- A process may exit before its cgroup can be read. The crash report is still saved, but the `cgroup` field may be absent.
- The tracer must be running before the process exits. It does not report crashes that happened earlier.
