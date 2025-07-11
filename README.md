# KTProxy - 基于 eBPF 的透明代理

> **Learn from [https://github.com/dorkamotorka/transparent-proxy-ebpf](https://github.com/dorkamotorka/transparent-proxy-ebpf)**

一个使用 eBPF 技术实现的透明代理服务器，可以在内核层面拦截和重定向 TCP 连接，实现无感知的流量代理。

## 项目特性

- **内核级别拦截**：使用 eBPF 在内核层面拦截 TCP 连接
- **透明代理**：客户端无需配置，自动重定向到代理服务器
- **原始目标恢复**：通过 `SO_ORIGINAL_DST` 获取客户端真实要连接的目标
- **高性能**：避免用户空间和内核空间的频繁切换
- **零配置**：客户端应用无需修改即可使用

## 技术架构

### eBPF 程序组件

1. **cgroup/connect4**：拦截客户端的 `connect()` 系统调用，重定向到代理服务器
2. **sockops**：在连接建立后记录端口映射信息
3. **cgroup/getsockopt**：处理代理服务器的 `SO_ORIGINAL_DST` 查询，返回原始目标

### 工作流程

```text
客户端应用 → connect(目标服务器) → eBPF拦截 → 重定向到代理服务器
     ↓
代理服务器 → getsockopt(SO_ORIGINAL_DST) → 获取原始目标 → 连接真实目标
     ↓
建立双向数据转发通道
```

## 项目结构

```text
├── main.go              # 主程序入口
├── bpf/
│   └── proxy.bpf.c      # eBPF 程序源码
├── testserver/
│   └── main.go          # 测试服务器
├── go.mod               # Go 模块定义
└── README.md            # 项目文档
```

## 环境要求

- Linux 内核版本 ≥ 4.15（支持 eBPF cgroup 程序）
- Go 1.19+
- clang/LLVM（用于编译 eBPF 程序）
- libbpf 开发库（eBPF 程序运行时库）
- 管理员权限（加载 eBPF 程序需要）

### 安装依赖

#### Fedora/RHEL/CentOS

```bash
sudo dnf install -y clang llvm kernel-devel kernel-headers libbpf libbpf-devel glibc-devel
```

> PS：暂时只在自己的电脑 Fedora42 上运行过

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/kerolt/ktproxy.git
cd ktproxy
```

### 2. 编译项目

```bash
go generate  # 编译 eBPF 程序
go build -o ktproxy main.go
```

### 3. 启动测试服务器

```bash
# 终端1：启动测试服务器（监听 8080 端口）
go run server/server.go
```

### 4. 启动透明代理

```bash
# 终端2：启动透明代理（需要管理员权限）
sudo ./ktproxy
```

### 5. 测试透明代理

```bash
# 终端3：测试连接
curl http://localhost:8080
```

## 工作原理

### 1. 连接拦截

当客户端应用调用 `connect()` 系统调用时，eBPF 程序 `handle_cg_connect` 会：

- 记录原始目标地址和端口
- 将连接重定向到代理服务器
- 存储 socket cookie 和目标信息的映射

### 2. 连接建立

连接建立后，eBPF 程序 `handle_sockops` 会：

- 记录客户端源端口和 socket cookie 的映射
- 为后续的目标查询做准备

### 3. 目标恢复

代理服务器调用 `getsockopt(SO_ORIGINAL_DST)` 时，eBPF 程序 `handle_getsockopt` 会：

- 通过客户端端口查找 socket cookie
- 通过 socket cookie 查找原始目标信息
- 返回原始目标地址和端口

### 4. 数据转发

代理服务器建立到真实目标的连接后，进行双向数据转发。

## 调试和日志

### 查看 eBPF 日志

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 查看代理日志

程序运行时会输出详细的连接信息：

```text
=== New Connection ===
Proxy Server: 127.0.0.1:8999
Client: 127.0.0.1:45678
Connecting to target 127.0.0.1:8080
Proxy connection established, from 127.0.0.1:45678 to 127.0.0.1:8080
```

### 监控连接状态

```bash
ss -tulpn | grep :8999
```

### 查看 eBPF 程序状态

```bash
sudo bpftool prog list
sudo bpftool map list
```

## 常见错误

1. **Permission denied**
   - 确保以管理员权限运行
   - 检查 eBPF 内核支持：`grep CONFIG_BPF /boot/config-$(uname -r)`

2. **Program load failed**
   - 检查内核版本是否支持 cgroup eBPF
   - 确保安装了必要的内核头文件

3. **Connection refused**
   - 检查代理服务器是否正确启动
   - 确认端口没有被占用
