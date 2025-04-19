// +build ignore

#include "vmlinux_compact_common.h"

struct trace_event_raw_inet_sock_set_state {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

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
#define IPPROTO_TCP 6

#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

struct ipv4_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 oldstate;
    u8 newstate;
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
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u8 oldstate;
    u8 newstate;
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

SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_event(struct trace_event_raw_inet_sock_set_state *ctx) {
    
    // bpf_printk("protocol:%d newstate:%d",ctx->protocol,ctx->newstate);
    // Track only TCP
    if (ctx->protocol != IPPROTO_TCP)
        return 0;
    
    // Track only ESTABLISHED and CLOSE connection states
    if (ctx->newstate != TCP_ESTABLISHED && ctx->newstate != TCP_CLOSE)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    if (ctx->family == AF_INET) {
        struct ipv4_event_t data4 = {0};
        data4.pid = pid;
        data4.uid = uid;
        data4.af = ctx->family;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.oldstate = ctx->oldstate;
        data4.newstate = ctx->newstate;
        data4.saddr = *(u32 *)ctx->saddr;
        data4.daddr = *(u32 *)ctx->daddr;
        
        data4.sport = bpf_ntohs(ctx->sport);
        data4.dport = bpf_ntohs(ctx->dport);
        
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        bpf_perf_event_output(ctx, &ipv4_events, BPF_F_CURRENT_CPU, &data4, sizeof(data4));
    }
    else if (ctx->family == AF_INET6) {
        struct ipv6_event_t data6 = {0};
        data6.pid = pid;
        data6.uid = uid;
        data6.af = ctx->family;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        data6.oldstate = ctx->oldstate;
        data6.newstate = ctx->newstate;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr), ctx->saddr_v6);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr), ctx->daddr_v6);
        
        data6.sport = bpf_ntohs(ctx->sport);
        data6.dport = bpf_ntohs(ctx->dport);
        
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        bpf_perf_event_output(ctx, &ipv6_events, BPF_F_CURRENT_CPU, &data6, sizeof(data6));
    }
    else if (ctx->family != AF_UNIX && ctx->family != AF_UNSPEC) {
        struct other_socket_event_t socket_event = {0};
        socket_event.pid = pid;
        socket_event.uid = uid;
        socket_event.af = ctx->family;
        socket_event.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_get_current_comm(&socket_event.task, sizeof(socket_event.task));
        bpf_perf_event_output(ctx, &other_socket_events, BPF_F_CURRENT_CPU, &socket_event, sizeof(socket_event));
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";