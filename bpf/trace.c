#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define HISTORY_SIZE 10
#define PATH_SIZE 128
#define AF_INET 2
#define AF_INET6 10

enum syscall_kind {
    SYSCALL_OPENAT = 1,
    SYSCALL_CONNECT = 2,
};

struct syscall_record {
    __u32 syscall;
    __s32 ret;
    __u16 family;
    __u16 port;
    __u8 address[16];
    char path[PATH_SIZE];
};

struct pending_call {
    struct syscall_record record;
};

struct process_history {
    __u32 next;
};

struct history_key {
    __u32 tgid;
    __u32 slot;
};

struct history_value {
    __u32 sequence;
    struct syscall_record record;
};

struct crash_event {
    __u32 pid;
    __u32 uid;
    __s32 exit_status;
    __u32 history_count;
    __u64 timestamp_ns;
    char comm[16];
    struct syscall_record history[HISTORY_SIZE];
};

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct pending_call);
} pending_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct process_history);
} process_histories SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 81920);
    __type(key, struct history_key);
    __type(value, struct history_value);
} history_records SEC(".maps");

static const struct process_history empty_history = {};

static __always_inline void remember_failure(__u32 kind, __s64 ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)id;
    __u32 tgid = id >> 32;
    struct pending_call *pending = bpf_map_lookup_elem(&pending_calls, &tid);
    if (!pending)
        return;

    if (ret < 0) {
        struct process_history *history =
            bpf_map_lookup_elem(&process_histories, &tgid);
        if (!history) {
            bpf_map_update_elem(&process_histories, &tgid, &empty_history,
                                BPF_NOEXIST);
            history = bpf_map_lookup_elem(&process_histories, &tgid);
        }

        if (history) {
            pending->record.syscall = kind;
            pending->record.ret = (__s32)ret;
            __u32 sequence = __sync_fetch_and_add(&history->next, 1);
            struct history_key key = {
                .tgid = tgid,
                .slot = sequence % HISTORY_SIZE,
            };
            struct history_value value = {
                .sequence = sequence,
                .record = pending->record,
            };
            bpf_map_update_elem(&history_records, &key, &value, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&pending_calls, &tid);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct pending_call pending = {};

    pending.record.syscall = SYSCALL_OPENAT;
    bpf_probe_read_user_str(pending.record.path, sizeof(pending.record.path),
                            (const char *)ctx->args[1]);
    bpf_map_update_elem(&pending_calls, &tid, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    remember_failure(SYSCALL_OPENAT, ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct pending_call pending = {};
    const struct sockaddr *user_addr = (const struct sockaddr *)ctx->args[1];

    pending.record.syscall = SYSCALL_CONNECT;
    bpf_probe_read_user(&pending.record.family, sizeof(pending.record.family),
                        user_addr);

    if (pending.record.family == AF_INET) {
        struct sockaddr_in addr = {};
        if (!bpf_probe_read_user(&addr, sizeof(addr), user_addr)) {
            pending.record.port = addr.sin_port;
            __builtin_memcpy(pending.record.address, &addr.sin_addr,
                             sizeof(addr.sin_addr));
        }
    } else if (pending.record.family == AF_INET6) {
        struct sockaddr_in6 addr = {};
        if (!bpf_probe_read_user(&addr, sizeof(addr), user_addr)) {
            pending.record.port = addr.sin6_port;
            __builtin_memcpy(pending.record.address, &addr.sin6_addr,
                             sizeof(addr.sin6_addr));
        }
    }

    bpf_map_update_elem(&pending_calls, &tid, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_exit_connect(struct trace_event_raw_sys_exit *ctx)
{
    remember_failure(SYSCALL_CONNECT, ctx->ret);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u32 pid = BPF_CORE_READ(task, pid);
    __u32 tgid = BPF_CORE_READ(task, tgid);
    __s32 status = BPF_CORE_READ(task, exit_code);

    if (pid != tgid)
        return 0;

    struct crash_event *event = 0;
    if (status != 0)
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (event) {
        volatile __u8 *event_bytes = (volatile __u8 *)event;
        for (__u32 i = 0; i < sizeof(*event); i++)
            event_bytes[i] = 0;

        event->pid = tgid;
        event->uid = bpf_get_current_uid_gid();
        event->exit_status = status;
        event->timestamp_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(event->comm, sizeof(event->comm));

        struct process_history *history =
            bpf_map_lookup_elem(&process_histories, &tgid);
        if (history) {
            __u32 next = history->next;
            __u32 count = next < HISTORY_SIZE ? next : HISTORY_SIZE;
            __u32 start = next - count;
            event->history_count = count;
#pragma unroll
            for (__u32 i = 0; i < HISTORY_SIZE; i++) {
                if (i < count) {
                    __u32 sequence = start + i;
                    struct history_key key = {
                        .tgid = tgid,
                        .slot = sequence % HISTORY_SIZE,
                    };
                    struct history_value *value =
                        bpf_map_lookup_elem(&history_records, &key);
                    if (value && value->sequence == sequence)
                        event->history[i] = value->record;
                }
            }
        }

        bpf_ringbuf_submit(event, 0);
    }

#pragma unroll
    for (__u32 i = 0; i < HISTORY_SIZE; i++) {
        struct history_key key = {
            .tgid = tgid,
            .slot = i,
        };
        bpf_map_delete_elem(&history_records, &key);
    }
    bpf_map_delete_elem(&process_histories, &tgid);
    return 0;
}
