// SPDX-License-Identifier: GPL-2.0
// AIShields Protect - Linux eBPF Kernel Monitor
// Monitors AI API connections, process execution, file access, and network sends.
// Compile with: clang -O2 -target bpf -c aishields_monitor.bpf.c -o aishields_monitor.bpf.o

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 64
#define MAX_PATH_LEN 256
#define MAX_TARGETS  64
#define RINGBUF_SIZE (1 << 20) /* 1MB ring buffer */

enum event_type {
    EVENT_CONNECT   = 1,
    EVENT_EXEC      = 2,
    EVENT_FILE_OPEN = 3,
    EVENT_SENDTO    = 4,
};

enum action {
    ACTION_MONITOR = 0,
    ACTION_BLOCK   = 1,
};

struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 event_type;
    __u32 action;
    __u32 ret_code;
    char  comm[MAX_COMM_LEN];
    union {
        struct {
            __u32 dst_addr;    /* IPv4 destination */
            __u16 dst_port;
            __u16 family;
            __u8  dst_addr6[16]; /* IPv6 destination */
        } connect;
        struct {
            char filename[MAX_PATH_LEN];
        } exec;
        struct {
            char path[MAX_PATH_LEN];
            __u32 flags;
        } file_open;
        struct {
            __u32 dst_addr;
            __u16 dst_port;
            __u32 size;
        } sendto;
    };
};

/* Ring buffer for events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/* Configuration: target IP addresses to monitor (IPv4 in network byte order) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TARGETS);
    __type(key, __u32);    /* IPv4 address */
    __type(value, __u8);   /* action: 0=monitor, 1=block */
} target_ips SEC(".maps");

/* Configuration: target ports to monitor */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u16);    /* port number */
    __type(value, __u8);   /* action */
} target_ports SEC(".maps");

/* Configuration: sensitive file paths to monitor */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, __u8);   /* action */
} sensitive_paths SEC(".maps");

/* Configuration: AI process names to track */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[MAX_COMM_LEN]);
    __type(value, __u8);
} ai_processes SEC(".maps");

/* Per-PID tracking: count of bytes sent to AI endpoints */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);    /* PID */
    __type(value, __u64);  /* total bytes sent */
} pid_ai_bytes SEC(".maps");

/* Stats counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void increment_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in *addr;
    struct sockaddr_in6 *addr6;
    __u16 family;
    __u32 dst_addr = 0;
    __u16 dst_port = 0;

    /* Read sockaddr from userspace */
    addr = (struct sockaddr_in *)ctx->args[1];
    bpf_probe_read_user(&family, sizeof(family), &addr->sin_family);

    if (family == AF_INET) {
        bpf_probe_read_user(&dst_addr, sizeof(dst_addr), &addr->sin_addr.s_addr);
        bpf_probe_read_user(&dst_port, sizeof(dst_port), &addr->sin_port);
        dst_port = __builtin_bswap16(dst_port);
    } else if (family == AF_INET6) {
        addr6 = (struct sockaddr_in6 *)addr;
        bpf_probe_read_user(&dst_port, sizeof(dst_port), &addr6->sin6_port);
        dst_port = __builtin_bswap16(dst_port);
    } else {
        return 0;
    }

    /* Check if destination is a monitored AI endpoint */
    __u8 *ip_action = bpf_map_lookup_elem(&target_ips, &dst_addr);
    __u8 *port_action = bpf_map_lookup_elem(&target_ports, &dst_port);

    if (!ip_action && !port_action)
        return 0;

    /* Emit event */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = EVENT_CONNECT;
    e->action = (ip_action && *ip_action == ACTION_BLOCK) ? ACTION_BLOCK : ACTION_MONITOR;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->connect.dst_addr = dst_addr;
    e->connect.dst_port = dst_port;
    e->connect.family = family;

    if (family == AF_INET6) {
        bpf_probe_read_user(e->connect.dst_addr6, 16, &addr6->sin6_addr);
    }

    bpf_ringbuf_submit(e, 0);
    increment_stat(0); /* connect events */
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx)
{
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    /* Check if process is an AI tool */
    __u8 *action = bpf_map_lookup_elem(&ai_processes, comm);

    /* Always log execve for AI processes; also capture the filename */
    const char *filename = (const char *)ctx->args[0];

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = EVENT_EXEC;
    e->action = action ? *action : ACTION_MONITOR;
    __builtin_memcpy(e->comm, comm, MAX_COMM_LEN);
    bpf_probe_read_user_str(e->exec.filename, MAX_PATH_LEN, filename);

    bpf_ringbuf_submit(e, 0);
    increment_stat(1); /* exec events */
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    char path[MAX_PATH_LEN] = {};
    const char *user_path = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];

    bpf_probe_read_user_str(path, MAX_PATH_LEN, user_path);

    /* Check if path is in sensitive paths map */
    __u8 *action = bpf_map_lookup_elem(&sensitive_paths, path);
    if (!action)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = EVENT_FILE_OPEN;
    e->action = *action;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memcpy(e->file_open.path, path, MAX_PATH_LEN);
    e->file_open.flags = flags;

    bpf_ringbuf_submit(e, 0);
    increment_stat(2); /* file open events */
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx)
{
    __u32 size = (__u32)ctx->args[2];
    struct sockaddr_in *addr = (struct sockaddr_in *)ctx->args[4];

    if (!addr)
        return 0;

    __u16 family;
    bpf_probe_read_user(&family, sizeof(family), &addr->sin_family);
    if (family != AF_INET)
        return 0;

    __u32 dst_addr;
    __u16 dst_port;
    bpf_probe_read_user(&dst_addr, sizeof(dst_addr), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&dst_port, sizeof(dst_port), &addr->sin_port);
    dst_port = __builtin_bswap16(dst_port);

    /* Check if sending to monitored IP */
    __u8 *action = bpf_map_lookup_elem(&target_ips, &dst_addr);
    if (!action)
        return 0;

    /* Track per-PID bytes sent to AI endpoints */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *bytes = bpf_map_lookup_elem(&pid_ai_bytes, &pid);
    if (bytes) {
        __sync_fetch_and_add(bytes, size);
    } else {
        __u64 initial = size;
        bpf_map_update_elem(&pid_ai_bytes, &pid, &initial, BPF_ANY);
    }

    /* Emit event for large payloads (potential DLP concern) */
    if (size > 4096) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        e->timestamp_ns = bpf_ktime_get_ns();
        e->pid = pid;
        e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        e->event_type = EVENT_SENDTO;
        e->action = *action;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        e->sendto.dst_addr = dst_addr;
        e->sendto.dst_port = dst_port;
        e->sendto.size = size;

        bpf_ringbuf_submit(e, 0);
        increment_stat(3); /* sendto events */
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
