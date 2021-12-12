# 使用 Go 对接 iptables-nfqueue 的例子

之前写的 `iptables-nfqueue` 的例子引用的库有点问题，换了一个库。

> 源代码：[github.com/Asphaltt/learn-by-example/nfqueue](https://github.com/Asphaltt/learn-by-example/tree/main/nfqueue)

## 例子的效果

使用 `iptables NFQUEUE` 监听新建 tcp 连接：

```bash
./nfqueue-example
tcp connect: 113.81.xx.yy:19885 -> 10.7.xxx.yyy:22
tcp connect: 157.245.xx.yy:46131 -> 10.7.xxx.yyy:2060
tcp connect: 113.81.xx.yy:19907 -> 10.7.xxx.yyy:8080
tcp connect: 113.81.xx.yy:19918 -> 10.7.xxx.yyy:443
tcp connect: 113.81.xx.yy:19918 -> 10.7.xxx.yyy:443
tcp connect: 113.81.xx.yy:19918 -> 10.7.xxx.yyy:443
tcp connect: 46.101.xx.yy:48780 -> 10.7.xxx.yyy:5537
tcp connect: 89.248.xx.yy:54067 -> 10.7.xxx.yyy:309
```

## 简洁的代码

使用了 [go-nfqueue](https://github.com/florianl/go-nfqueue) 纯 Go 实现的 `nfnetlink` 库，不依赖 `libnetfilter_queue` Linux 系统库，编译后即可使用。

从 `iptables-nfqueue` 中接收 tcp 连接的 **SYN** 包，并从 **SYN** 包中解析得到源 IP 地址、源 tcp 端口、目的 IP 地址、目的 tcp 端口等信息。

```go
type packet []byte

func (p packet) srcIP() net.IP {
	return net.IP(p[12:16])
}

func (p packet) dstIP() net.IP {
	return net.IP(p[16:20])
}

func (p packet) srcPort() uint16 {
	tcphdr := p[20:]
	return binary.BigEndian.Uint16(tcphdr[:2])
}

func (p packet) dstPort() uint16 {
	tcphdr := p[20:]
	return binary.BigEndian.Uint16(tcphdr[2:4])
}

func handlePacket(q *nfqueue.Nfqueue, a nfqueue.Attribute) int {
	if a.Payload != nil && len(*a.Payload) != 0 {
		pkt := packet(*a.Payload)
		fmt.Printf("tcp connect: %s:%d -> %s:%d\n", pkt.srcIP(), pkt.srcPort(), pkt.dstIP(), pkt.dstPort())
	}
	_ = q.SetVerdict(*a.PacketID, nfqueue.NfAccept)
	return 0
}

func main() {
	cfg := nfqueue.Config{
		NfQueue:     1,
		MaxQueueLen: 2,
		Copymode:    nfqueue.NfQnlCopyPacket,
	}

	nfq, err := nfqueue.Open(&cfg)
	if err != nil {
		fmt.Println("failed to open nfqueue, err:", err)
		return
	}

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	if err := nfq.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		return handlePacket(nfq, a)
	}, func(e error) int {
		return 0
	}); err != nil {
		fmt.Println("failed to register handlers, err:", err)
		return
	}

	select {}
}
```

使用的 `iptables` 规则如下：

```bash
iptables -t raw -I PREROUTING -p tcp --syn -j NFQUEUE --queue-num=1 --queue-bypass
```

在 `raw` 表 `PREROUTING` 链上匹配 tcp 连接的 **SYN** 包。

## `iptables NFQUEUE`

> ### NFQUEUE
>
> This target passes the packet to userspace using the **nfnetlink_queue** handler. The packet is put into the queue identified by its 16-bit queue number. Userspace can inspect and modify the packet if desired. Userspace must then drop or reinject the packet into the kernel. Please see libnetfilter_queue for details. **nfnetlink_queue** was added in Linux 2.6.14. The **queue-balance** option was added in Linux 2.6.31, **queue-bypass** in 2.6.39.
>
> - **--queue-num** *value*
>
>   This specifies the QUEUE number to use. Valid queue numbers are 0 to 65535. The default value is 0.
>
> 
>
> - **--queue-balance** *value*:*value*
>
>   This specifies a range of queues to use. Packets are then balanced across the given queues. This is useful for multicore systems: start multiple instances of the userspace program on queues x, x+1, .. x+n and use "--queue-balance *x*:*x+n*". Packets belonging to the same connection are put into the same nfqueue.
>
> 
>
> - **--queue-bypass**
>
>   By default, if no userspace program is listening on an NFQUEUE, then all packets that are to be queued are dropped. When this option is used, the NFQUEUE rule behaves like ACCEPT instead, and the packet will move on to the next table.
>
> 
>
> - **--queue-cpu-fanout**
>
>   Available starting Linux kernel 3.10. When used together with **--queue-balance** this will use the CPU ID as an index to map packets to the queues. The idea is that you can improve performance if there's a queue per CPU. This requires **--queue-balance** to be specified.

> Doc: [iptables-extensions](https://ipset.netfilter.org/iptables-extensions.man.html)