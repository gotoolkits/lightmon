// +build ignore

#include "vmlinux_compact_common.h"

#if defined(__TARGET_ARCH_arm64)
#include "vmlinux_compact_arm64.h"
#elif defined(__TARGET_ARCH_x86)
#include "vmlinux_compact_amd64.h"
#endif

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define TASK_COMM_LEN 16
#define AF_UNIX 1
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10

struct ipv4_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
    u16 pad;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} ipv4_events SEC(".maps");

struct ipv6_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
    unsigned __int128 daddr;
    u16 dport;
    u16 pad;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} ipv6_events SEC(".maps");

struct other_socket_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
    u16 pad;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} other_socket_events SEC(".maps");

struct sys_enter_connect_args {
    __u64 pad[2];        
    __u64 sockfd;      
    const struct sockaddr *addr; 
    __u64 addrlen; 
};

SEC("tracepoint/syscalls/sys_enter_connect")
int TraceTcpEvent(struct sys_enter_connect_args *ctx) {
    if (!ctx || !ctx->addr)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct sockaddr *address;
    if (bpf_probe_read(&address, sizeof(address), &ctx->addr) < 0)
        return 0;

    u16 address_family = 0;
    if (bpf_probe_read(&address_family, sizeof(address_family), &address->sa_family) < 0)
        return 0;

    if (address_family == AF_INET) {
        struct ipv4_event_t data4 = {0};
        data4.pid = pid;
        data4.uid = uid;
        data4.af = address_family;
        data4.ts_us = bpf_ktime_get_ns() / 1000;

        struct sockaddr_in *daddr = (struct sockaddr_in *)address;
        if (bpf_probe_read(&data4.daddr, sizeof(data4.daddr), &daddr->sin_addr.s_addr) < 0)
            return 0;

        u16 dport = 0;
        if (bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port) < 0)
            return 0;

        data4.dport = bpf_ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        if (data4.dport != 0) {
            bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &data4, sizeof(data4));
        }
    }
    else if (address_family == AF_INET6) {
        struct ipv6_event_t data6 = {0};
        data6.pid = pid;
        data6.uid = uid;
        data6.af = address_family;
        data6.ts_us = bpf_ktime_get_ns() / 1000;

        struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;
        if (bpf_probe_read(&data6.daddr, sizeof(data6.daddr), &daddr6->sin6_addr.in6_u.u6_addr32) < 0)
            return 0;

        u16 dport6 = 0;
        if (bpf_probe_read(&dport6, sizeof(dport6), &daddr6->sin6_port) < 0)
            return 0;

        data6.dport = bpf_ntohs(dport6);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));

        if (data6.dport != 0) {
            bpf_perf_event_output(ctx, &ipv6_events, BPF_F_CURRENT_CPU, &data6, sizeof(data6));
        }
    }
    else if (address_family != AF_UNIX && address_family != AF_UNSPEC) {
        struct other_socket_event_t socket_event = {0};
        socket_event.pid = pid;
        socket_event.uid = uid;
        socket_event.af = address_family;
        socket_event.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_get_current_comm(&socket_event.task, sizeof(socket_event.task));
        bpf_perf_event_output(ctx, &other_socket_events, BPF_F_CURRENT_CPU, &socket_event, sizeof(socket_event));
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";