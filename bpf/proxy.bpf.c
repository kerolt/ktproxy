//go:ignore

// #include "vmlinux.h"

#include <linux/bpf.h>
#include <linux/netfilter_ipv4.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define TARGET_SERVER_PORT 8000

typedef struct {
    __u32 src_addr;
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
} Socket;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);     // 内核为每个socket分配的唯一标识符（cookie）
    __type(value, Socket);  // cookie对应的socket源端口
    __uint(max_entries, 20000);
} sockets_map SEC(".maps");

typedef struct {
    __u16 port;
    __u64 pid;
} ProxyConfig;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, ProxyConfig);
    __uint(max_entries, 1);  // map只存储一个配置对象时，通常使用0作为该对象的索引
} proxy_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u64);
    __uint(max_entries, 20000);
} ports_map SEC(".maps");

// 拦截 connect，当客户端连接到目标服务器 8000 端口时触发，这时转发到代理服务器上去
SEC("cgroup/connect4")
int handle_cg_connect(struct bpf_sock_addr* ctx) {
    if (ctx->user_family != AF_INET || ctx->protocol != IPPROTO_TCP) {
        return 1;  // 只处理 IPv4 TCP 连接
    }

    // BPF 编程中，当 map 只存储一个配置对象时，通常使用 key = 0 作为该对象的索引
    // 用户空间程序在初始化时会将配置写入 proxy_config_map[0]
    // 内核空间的 BPF 程序始终从 proxy_config_map[0] 读取配置
    __u32 key = 0;
    ProxyConfig* cfg = bpf_map_lookup_elem(&proxy_config_map, &key);
    if (!cfg) {
        // 如果bpf_map_lookup_elem返回 NULL，说明：
        // 用户空间程序还没有初始化，或者配置 Map 创建失败
        return 1;
    }
    if ((bpf_get_current_pid_tgid() >> 32) == cfg->pid) {
        return 1;
    }

    __u32 dst_addr = bpf_ntohl(ctx->user_ip4);
    __u16 dst_port = bpf_ntohl(ctx->user_port) >> 16;

    if (dst_port != TARGET_SERVER_PORT) {
        return 1;  // 只处理目标端口为 8000 的连接
    }

    __u64 cookie = bpf_get_socket_cookie(ctx);
    Socket sock = {.dst_addr = dst_addr, .dst_port = dst_port};
    bpf_map_update_elem(&sockets_map, &cookie, &sock, 0);

    ctx->user_ip4 = bpf_htonl(0x7f000001);        // 设置代理地址为 127.0.0.1
    ctx->user_port = bpf_htonl(cfg->port << 16);  // 设置代理端口

    bpf_printk("Proxying connection to port %u via port %u\n", dst_port, cfg->port);
    return 1;
}

// 记录连接建立后的客户端源端口信息
SEC("sockops")
int handle_sockops(struct bpf_sock_ops* ctx) {
    if (ctx->family != AF_INET) {
        return 0;  // 只处理 IPv4 TCP 连接
    }

    // 连接建立后
    if (ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        // Socket cookie 是一个 64 位的唯一标识符（__u64），由内核在创建 socket 时自动分配。
        // Socket 的文件描述符（fd）在用户空间有效，但在内核的不同上下文中可能不同，
        // 而 Cookie 提供了一个跨内核上下文的稳定标识符
        __u64 cookie = bpf_get_socket_cookie(ctx);
        Socket* sock = bpf_map_lookup_elem(&sockets_map, &cookie);
        if (sock) {
            __u16 src_port = ctx->local_port;
            // 让代理服务器能够通过源端口找到原始目标信息
            bpf_map_update_elem(&ports_map, &src_port, &cookie, 0);
            bpf_printk("Original socket from port %u\n", src_port);
        }
    }

    return 0;
}

// 当代理服务器调用 getsockopt(SO_ORIGINAL_DST) 时触发
//
// 通过源端口反向查找到原始的目标地址和端口，让代理服务器知道客户端真正想要连接的目标
SEC("cgroup/getsockopt")
int handle_getsockopt(struct bpf_sockopt* ctx) {
    if (ctx->optname != SO_ORIGINAL_DST || ctx->sk->family != AF_INET || ctx->sk->protocol != IPPROTO_TCP) {
        return 1;  // 只处理 IPv4 TCP 连接的 SO_ORIGINAL_DST 选项
    }

    // 这里容易搞混，在代理服务器的视角下
    // ctx->sk->src_port: 本地端口（网络字节序）
    // ctx->sk->dst_port: 远程端口（网络字节序）
    // 因此应用服务所用的端口在代理服务器端看起来是 ctx->sk->dst_port
    __u16 src_port = bpf_ntohs(ctx->sk->dst_port);
    __u64* cookie = bpf_map_lookup_elem(&ports_map, &src_port);
    if (!cookie) {
        return 1;
    }

    Socket* sock = bpf_map_lookup_elem(&sockets_map, cookie);
    if (!sock) {
        return 1;
    }
    if (sock->dst_port != TARGET_SERVER_PORT) {
        return 1;  // 只处理目标端口为 8000 的连接
    }

    struct sockaddr_in* sa = ctx->optval;
    if ((void*)(sa + 1) > ctx->optval_end) {
        bpf_printk("Out of bounds access in getsockopt\n");
        return 1;
    }
    ctx->optlen = sizeof(struct sockaddr_in);         // 设置选项长度为 sockaddr_in 结构体的大小
    sa->sin_family = ctx->sk->family;                 // 设置地址族
    sa->sin_addr.s_addr = bpf_htonl(sock->dst_addr);  // 设置目标 IP 地址
    sa->sin_port = bpf_htons(sock->dst_port);         // 设置目标端口
    ctx->retval = 0;

    bpf_printk("Redirecting connection to original destination\n");

    return 1;
}
