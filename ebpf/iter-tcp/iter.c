//go:build ignore

#include "bpf_all.h"

SEC("iter/tcp")
int iter_tcp(struct bpf_iter__tcp *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct sock_common *skc = ctx->sk_common;
	struct tcp_sock *tp;
	struct sock *sk;
	struct sk_buff_head *queue;
	struct sk_buff *skb;
	struct socket *sock;
	struct file *file;
	struct pid *pid;
	int qlen, cnt = 0, cnt_pp = 0;
	int pid_nr = 0;

	if (!skc)
		return 0;

	tp = bpf_skc_to_tcp_sock(skc);
	if (!tp)
		return 0;

	sk   = (struct sock *)tp;
	queue = &sk->sk_receive_queue;

	qlen = BPF_CORE_READ(queue, qlen);

	skb = (struct sk_buff *)BPF_CORE_READ(queue, next);
	for (int i = 0; i < 100 && skb != (struct sk_buff *)queue; i++) {
		cnt++;
		cnt_pp += BPF_CORE_READ_BITFIELD_PROBED(skb, pp_recycle);

		skb = (struct sk_buff *)BPF_CORE_READ(skb, next);
	}

        if (cnt == 0)
                return 0;

	// Get process info
	sock = BPF_CORE_READ(sk, sk_socket);
	if (sock) {
		file = BPF_CORE_READ(sock, file);
		if (file) {
			pid = BPF_CORE_READ(file, f_owner.pid);
			if (pid) {
				pid_nr = BPF_CORE_READ(pid, numbers[0].nr);
			}
		}
	}

	BPF_SEQ_PRINTF(seq, "state=%d src=%pI4:%u dst=%pI4:%u pid=%d\n",
		       skc->skc_state,
		       &skc->skc_rcv_saddr, skc->skc_num,
		       &skc->skc_daddr, bpf_ntohs(skc->skc_dport),
		       pid_nr);

	BPF_SEQ_PRINTF(seq, "  rx_queue: qlen=%d iterated=%d (pp_recycle=%d)\n",
		       qlen, cnt, cnt_pp);

	return 0;
}