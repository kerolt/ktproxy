package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" bpf bpf/proxy.bpf.c

const SO_ORIGINAL_DST = 80
const CGROUP_PATH = "/sys/fs/cgroup"

type SockAddrIn struct {
	SinFamily uint16  // 2
	SinPort   [2]byte // 2
	SinAddr   [4]byte // 4
	pad       [8]byte // 8
}

func getsockopt(sockfd int, level int, optname int, optval *SockAddrIn, optlen *uint32) error {
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(sockfd), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(optval)), uintptr(unsafe.Pointer(optlen)), 0)
	if e != 0 {
		return e
	}
	return nil
}

func handleConnect(conn net.Conn) {
	defer conn.Close()

	// 显示代理服务器接收到的连接信息
	localAddr := conn.LocalAddr()   // 代理服务器的地址:端口
	remoteAddr := conn.RemoteAddr() // 客户端的地址:端口

	log.Printf("=== New Connection ===")
	log.Printf("Proxy Server: %s", localAddr.String())
	log.Printf("Client: %s", remoteAddr.String())

	// 获取具体的端口号
	var clientPort int
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		clientPort = tcpAddr.Port
	} else {
		log.Fatalf("Failed to get client port: %v", remoteAddr)
	}

	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		log.Printf("Failed to get syscall connection: %v", err)
		return
	}

	// 通过getsockopt将sockaddr_in数据保存到originDst中
	var originDst SockAddrIn
	rawConn.Control(func(fd uintptr) {
		optlen := uint32(unsafe.Sizeof(originDst))
		err := getsockopt(int(fd), syscall.SOL_TCP, SO_ORIGINAL_DST, &originDst, &optlen)
		if err != nil {
			log.Printf("Failed to getsockopt: %v", err)
			return
		}
	})

	targetAddr := net.IP(originDst.SinAddr[:]).String()
	targetPort := binary.BigEndian.Uint16(originDst.SinPort[:]) // 需要转换字节序
	targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetAddr, targetPort), 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to origin target: %v", err)
		return
	}
	defer targetConn.Close()

	// 显示代理服务器到目标服务器的连接信息
	proxyToTargetLocal := targetConn.LocalAddr()   // 代理服务器向目标服务器连接时使用的端口
	proxyToTargetRemote := targetConn.RemoteAddr() // 目标服务器的地址:端口

	log.Printf("Proxy->Target Local: %s", proxyToTargetLocal.String())
	log.Printf("Proxy->Target Remote: %s", proxyToTargetRemote.String())

	if tcpAddr, ok := proxyToTargetLocal.(*net.TCPAddr); ok {
		log.Printf("Proxy outgoing port: %d", tcpAddr.Port)
	}

	log.Printf("Flow: Client:%d -> Proxy:8999 -> Target:%d", clientPort, targetPort)
	log.Printf("=== Connection Established ===\n\n")

	// 双向数据转发
	go func() {
		_, err := io.Copy(targetConn, conn)
		if err != nil {
			log.Printf("Error copying data from client to target: %v", err)
		}
	}()
	_, err = io.Copy(conn, targetConn)
	if err != nil {
		log.Printf("Error copying data from client to target: %v", err)
	}
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock limit: %v", err)
	}

	var proxyObjs bpfObjects
	if err := loadBpfObjects(&proxyObjs, nil); err != nil {
		log.Printf("Failed to load BPF objects: %v", err)
	}
	defer proxyObjs.Close()

	// 挂载 handle_cg_connect
	connnectLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    CGROUP_PATH,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: proxyObjs.HandleCgConnect,
	})
	if err != nil {
		log.Printf("Failed to attach [handle_cg_connect] to cgroup: %v", err)
	}
	defer connnectLink.Close()

	// 挂载 handle_sockops
	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    CGROUP_PATH,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: proxyObjs.HandleSockops,
	})
	if err != nil {
		log.Printf("Failed to attach [handle_sockops] to cgroup: %v", err)
	}
	defer sockopsLink.Close()

	// 挂载 handle_getsockopt
	getsockoptLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    CGROUP_PATH,
		Attach:  ebpf.AttachCGroupGetsockopt,
		Program: proxyObjs.HandleGetsockopt,
	})
	if err != nil {
		log.Printf("Failed to attach [handle_getsockopt] to cgroup: %v", err)
	}
	defer getsockoptLink.Close()

	// 设置 ProxyConfigMap，{key: 0, value: {port: 8999, pid: current_pid}}
	var key uint32 = 0
	proxyCfg := bpfProxyConfig{
		Port: 8999,
		Pid:  uint64(os.Getpid()),
	}
	err = proxyObjs.ProxyConfigMap.Update(&key, &proxyCfg, ebpf.UpdateAny)
	if err != nil {
		log.Printf("Failed to update proxy config map: %v", err)
	}

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyCfg.Port)
	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}

	log.Printf("Proxy server listening on %s", proxyAddr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnect(conn)
	}
}
