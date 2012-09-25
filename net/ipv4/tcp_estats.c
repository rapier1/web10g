/*
 * net/ipv4/tcp_estats.c
 *
 * Implementation of TCP ESTATS MIB (RFC 4898)
 *
 * Authors:
 *   John Estabrook <jestabro@ncsa.illinois.edu>
 *   Andrew K. Adams <akadams@psc.edu>
 *   John Heffner <jheffner@psc.edu>
 *   Matt Mathis <mathis@psc.edu>
 *   Jeff Semke <semke@psc.edu>
 *
 * The Web10Gig project.  See http://www.web10gig.org
 *
 * Copyright © 2011, Pittsburgh Supercomputing Center (PSC) and
 * National Center for Supercomputing Applications (NCSA).
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <net/tcp_estats.h>
#include <net/tcp.h>
#include <asm/atomic.h>
#include <asm/byteorder.h>

#define ESTATS_INF32	0xffffffff

int tcp_estats_enabled __read_mostly = 0;

struct idr tcp_estats_idr;
static int next_id = 1;
DEFINE_SPINLOCK(tcp_estats_idr_lock);

int tcp_estats_wq_enabled __read_mostly = 0;
struct workqueue_struct *tcp_estats_wq = NULL;
void (*create_notify_func)(struct work_struct *work);
void (*establish_notify_func)(struct work_struct *work);
void (*destroy_notify_func)(struct work_struct *work);
unsigned long persist_delay = 0;

EXPORT_SYMBOL(tcp_estats_idr);
EXPORT_SYMBOL(tcp_estats_idr_lock);
EXPORT_SYMBOL(tcp_estats_wq_enabled);
EXPORT_SYMBOL(tcp_estats_wq);
EXPORT_SYMBOL(create_notify_func);
EXPORT_SYMBOL(establish_notify_func);
EXPORT_SYMBOL(destroy_notify_func);
EXPORT_SYMBOL(persist_delay);

/* This is missing in idr.c until v2.6.35, although
 * listed as exported in idr.h.
 */
EXPORT_SYMBOL(idr_get_next);

/* Called whenever a TCP/IPv4 sock is created.
 * net/ipv4/tcp_ipv4.c: tcp_v4_syn_recv_sock,
 *			tcp_v4_init_sock
 * Allocates a stats structure and initializes values.
 */
int tcp_estats_create(struct sock *sk, enum tcp_estats_addrtype addrtype)
{
	struct tcp_estats *stats;
	struct tcp_estats_directs *vars;
	struct tcp_sock *tp = tcp_sk(sk);
        int ret;

	if (!tcp_estats_enabled) {
		stats = NULL;
		return -1;
	}

	stats = kzalloc(sizeof(struct tcp_estats), gfp_any());
	if (!stats)
		return -ENOMEM;

	tp->tcp_stats = stats;
	vars = &stats->estats_vars;

        stats->tcpe_cid = -1;
        stats->queued = 0;

	stats->estats_vars.LocalAddressType = addrtype;

	sock_hold(sk);
	stats->estats_sk = sk;
        stats->uid = sock_i_uid(sk);
	atomic_set(&stats->estats_users, 0);

	stats->estats_limstate = TCP_ESTATS_SNDLIM_STARTUP;
	stats->estats_start_ts = stats->estats_limstate_ts =
	    stats->estats_current_ts = ktime_get();
	do_gettimeofday(&stats->estats_start_tv);

	vars->ActiveOpen = !in_interrupt();

	vars->SndMax = tp->snd_nxt;
	vars->SndInitial = tp->snd_nxt;

	vars->MinRTT = vars->MinRTO = vars->MinMSS = vars->MinSsthresh =
	    ESTATS_INF32;

	tcp_estats_use(stats);

        if (tcp_estats_wq_enabled) {

                tcp_estats_use(stats);
                stats->queued = 1;
                stats->tcpe_cid = 0;
                INIT_WORK(&stats->create_notify, create_notify_func);
                ret = queue_work(tcp_estats_wq, &stats->create_notify);
        }

	return 0;
}

void tcp_estats_destroy(struct sock *sk)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;

	if (stats == NULL)
		return;

	/* Attribute final sndlim time. */
	tcp_estats_update_sndlim(tcp_sk(stats->estats_sk),
				 stats->estats_limstate);

        if (tcp_estats_wq_enabled && stats->queued) {
                INIT_DELAYED_WORK(&stats->destroy_notify,
                        destroy_notify_func);
                queue_delayed_work(tcp_estats_wq, &stats->destroy_notify,
                        persist_delay);

        }
	tcp_estats_unuse(stats);
}

/* Do not call directly.  Called from tcp_estats_unuse(). */
void tcp_estats_free(struct tcp_estats *stats)
{
	sock_put(stats->estats_sk);
	kfree(stats);
}
EXPORT_SYMBOL(tcp_estats_free);

/* Called when a connection enters the ESTABLISHED state, and has all its
 * state initialized.
 * net/ipv4/tcp_input.c: tcp_rcv_state_process,
 *			 tcp_rcv_synsent_state_process
 * Here we link the statistics structure in so it is visible in the /proc
 * fs, and do some final init.
 */
void tcp_estats_establish(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_directs *vars = &stats->estats_vars;

	if (stats == NULL)
		return;

	/* Let's set these here, since they can't change once the
	 * connection is established.
	 */
	vars->LocalPort = inet->num;
	vars->RemPort = ntohs(inet->dport);

	if (vars->LocalAddressType == TCP_ESTATS_ADDRTYPE_IPV4) {
		memcpy(&vars->LocalAddress, &inet->rcv_saddr, 4);
		memcpy(&vars->RemAddress, &inet->daddr, 4);
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (vars->LocalAddressType == TCP_ESTATS_ADDRTYPE_IPV6) {
		memcpy(&vars->LocalAddress, &(inet6_sk(sk)->saddr), 16);
		memcpy(&vars->RemAddress, &(inet6_sk(sk)->daddr), 16);
	}
#endif
	else {
		printk(KERN_ERR "TCP ESTATS: LocalAddressType not valid.\n");
	}
	((char *)&vars->LocalAddress)[16] = ((char *)&vars->RemAddress)[16] =
	    vars->LocalAddressType;

	tcp_estats_update_finish_segrecv(tp);
	tcp_estats_update_rwin_rcvd(tp);
	tcp_estats_update_rwin_sent(tp);

	vars->RecInitial = tp->rcv_nxt;

	tcp_estats_update_sndlim(tp, TCP_ESTATS_SNDLIM_SENDER);

        if (tcp_estats_wq_enabled && stats->queued) {
                INIT_WORK(&stats->establish_notify, establish_notify_func);
                queue_work(tcp_estats_wq, &stats->establish_notify);
        }
}

/*
 * Statistics update functions
 */

void tcp_estats_update_snd_nxt(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;

	if (after(tp->snd_nxt, stats->estats_vars.SndMax))
		stats->estats_vars.SndMax = tp->snd_nxt;
}

void tcp_estats_update_acked(struct tcp_sock *tp, u32 ack)
{
	struct tcp_estats *stats = tp->tcp_stats;

	stats->estats_vars.ThruOctetsAcked += ack - tp->snd_una;
}

void tcp_estats_update_rtt(struct sock *sk, unsigned long rtt_sample)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;
	unsigned long rtt_sample_msec = rtt_sample * 1000 / HZ;
	u32 rto;

	stats->estats_vars.SampleRTT = rtt_sample_msec;

	if (rtt_sample_msec > stats->estats_vars.MaxRTT)
		stats->estats_vars.MaxRTT = rtt_sample_msec;
	if (rtt_sample_msec < stats->estats_vars.MinRTT)
		stats->estats_vars.MinRTT = rtt_sample_msec;

	stats->estats_vars.CountRTT++;
	stats->estats_vars.SumRTT += rtt_sample_msec;

	rto = inet_csk(sk)->icsk_rto * 1000 / HZ;
	if (rto > stats->estats_vars.MaxRTO)
		stats->estats_vars.MaxRTO = rto;
	if (rto < stats->estats_vars.MinRTO)
		stats->estats_vars.MinRTO = rto;
}

void tcp_estats_update_timeout(struct sock *sk)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;

	if (inet_csk(sk)->icsk_backoff)
		stats->estats_vars.SubsequentTimeouts++;
	else
		stats->estats_vars.Timeouts++;
	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open)
		stats->estats_vars.AbruptTimeouts++;
}

void tcp_estats_update_mss(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	int mss = tp->mss_cache;

	if (mss > stats->estats_vars.MaxMSS)
		stats->estats_vars.MaxMSS = mss;
	if (mss < stats->estats_vars.MinMSS)
		stats->estats_vars.MinMSS = mss;
}

void tcp_estats_update_finish_segrecv(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_directs *vars = &stats->estats_vars;
	u32 mss = tp->mss_cache;
	u32 cwnd;
	u32 ssthresh;
	u32 pipe_size;

	stats->estats_current_ts = ktime_get();

	cwnd = tp->snd_cwnd * mss;
	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		if (cwnd > vars->MaxSsCwnd)
			vars->MaxSsCwnd = cwnd;
	} else {
		if (cwnd > vars->MaxCaCwnd)
			vars->MaxCaCwnd = cwnd;
	}

	pipe_size = tcp_packets_in_flight(tp) * mss;
	if (pipe_size > vars->MaxPipeSize)
		vars->MaxPipeSize = pipe_size;

	/* Discard initiail ssthresh set at infinity. */
	if (tp->snd_ssthresh >= 0x7ffffff) {
		return;
	}
	ssthresh = tp->snd_ssthresh * tp->mss_cache;
	if (ssthresh > vars->MaxSsthresh)
		vars->MaxSsthresh = ssthresh;
	if (ssthresh < vars->MinSsthresh)
		vars->MinSsthresh = ssthresh;
}

void tcp_estats_update_rwin_rcvd(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	u32 win = tp->snd_wnd;

	if (win > stats->estats_vars.MaxRwinRcvd)
		stats->estats_vars.MaxRwinRcvd = win;
	if (win == 0)
		stats->estats_vars.ZeroRwinRcvd++;
}

void tcp_estats_update_rwin_sent(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	u32 win = tp->rcv_wnd;

	if (win > stats->estats_vars.MaxRwinSent)
		stats->estats_vars.MaxRwinSent = win;
	if (win == 0)
		stats->estats_vars.ZeroRwinSent++;
}

void tcp_estats_update_sndlim(struct tcp_sock *tp, int why)
{
	struct tcp_estats *stats = tp->tcp_stats;
	ktime_t now;

	if (why < 0) {
		printk(KERN_ERR "tcp_estats_update_sndlim: BUG: why < 0\n");
		return;
	}

	now = ktime_get();
	stats->estats_vars.snd_lim_time[stats->estats_limstate]
	    += ktime_to_ns(ktime_sub(now, stats->estats_limstate_ts));

	stats->estats_limstate_ts = now;
	if (stats->estats_limstate != why) {
		stats->estats_limstate = why;
		stats->estats_vars.snd_lim_trans[why]++;
	}
}

void tcp_estats_update_congestion(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;

	stats->estats_vars.CongSignals++;
	stats->estats_vars.PreCongSumCwnd += tp->snd_cwnd * tp->mss_cache;
	stats->estats_vars.PreCongSumRTT += stats->estats_vars.SampleRTT;
}

void tcp_estats_update_post_congestion(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	
	stats->estats_vars.PostCongCountRTT++;
	stats->estats_vars.PostCongSumRTT += stats->estats_vars.SampleRTT;
}

void tcp_estats_update_segsend(struct sock *sk, int len, int pcount,
			       u32 seq, u32 end_seq, int flags)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;

	stats->estats_current_ts = ktime_get();

	/* We know we're sending a segment. */
	stats->estats_vars.SegsOut += pcount;

	/* A pure ACK contains no data; everything else is data. */
	if (len > 0) {
		stats->estats_vars.DataSegsOut += pcount;
		stats->estats_vars.DataOctetsOut += len;
	}

	/* Check for retransmission. */
	if (flags & 0x02) {
		if (inet_csk(sk)->icsk_retransmits)
			stats->estats_vars.SegsRetrans++;
	} else if (before(seq, stats->estats_vars.SndMax)) {
		stats->estats_vars.SegsRetrans += pcount;
		stats->estats_vars.OctetsRetrans += end_seq - seq;
	}
}

void tcp_estats_update_segrecv(struct tcp_sock *tp, struct sk_buff *skb)
{
	struct tcp_estats_directs *vars = &tp->tcp_stats->estats_vars;
	struct tcphdr *th = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);

	vars->SegsIn++;
	if (skb->len == th->doff * 4) {
		if (TCP_SKB_CB(skb)->ack_seq == tp->snd_una)
			vars->DupAcksIn++;
	} else {
		vars->DataSegsIn++;
		vars->DataOctetsIn += skb->len - th->doff * 4;
	}

	vars->IpTtl = iph->ttl;
	vars->IpTosIn = iph->tos;
}

void tcp_estats_update_rcvd(struct tcp_sock *tp, u32 seq)
{
	struct tcp_estats *stats = tp->tcp_stats;

	stats->estats_vars.ThruOctetsReceived += seq - tp->rcv_nxt;
}

void tcp_estats_update_writeq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_estats_directs *vars = &tp->tcp_stats->estats_vars;
	int len = tp->write_seq - vars->SndMax;

	if (len > vars->MaxAppWQueue)
		vars->MaxAppWQueue = len;
}

static inline u32 ofo_qlen(struct tcp_sock *tp)
{
	if (!skb_peek(&tp->out_of_order_queue))
		return 0;
	else
		return TCP_SKB_CB(tp->out_of_order_queue.prev)->end_seq -
		    TCP_SKB_CB(tp->out_of_order_queue.next)->seq;
}

void tcp_estats_update_recvq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_estats_directs *vars = &tp->tcp_stats->estats_vars;
	u32 len1 = tp->rcv_nxt - tp->copied_seq;
	u32 len2 = ofo_qlen(tp);

	if (vars->MaxAppRQueue < len1)
		vars->MaxAppRQueue = len1;

	if (vars->MaxReasmQueue < len2)
		vars->MaxReasmQueue = len2;
}

/*
 * Manage connection ID table
 */

static int get_new_cid(struct tcp_estats *stats)
{
      int err;
      int id_cid;

      again:
        if (unlikely(idr_pre_get(&tcp_estats_idr, GFP_KERNEL) == 0))
            return -ENOMEM;

        spin_lock_bh(&tcp_estats_idr_lock);
        err = idr_get_new_above(&tcp_estats_idr, stats, next_id, &id_cid);
        if (!err) {
                next_id = (id_cid + 1) % 1024;
                stats->tcpe_cid = id_cid;
        }
        spin_unlock_bh(&tcp_estats_idr_lock);

        if (unlikely(err == -EAGAIN))
                goto again;
        else if (unlikely(err))
                return err;

        return 0;
}

static void create_func(struct work_struct *work)
{
        // stub for netlink notification of new connections
        ;
}

static void establish_func(struct work_struct *work)
{
        struct tcp_estats *stats = container_of(work, struct tcp_estats, establish_notify);
        int err = 0;

        if ((stats->tcpe_cid) >= 0) {
                err = get_new_cid(stats);
                if (err) printk(KERN_DEBUG "get_new_cid error %d\n", err);
        }
}

static void destroy_func(struct work_struct *work)
{
        struct tcp_estats *stats = container_of(work, struct tcp_estats, destroy_notify.work);

        int id_cid = stats->tcpe_cid;

        if (id_cid >= 0) {
                if (id_cid) {
                        spin_lock_bh(&tcp_estats_idr_lock);
                        idr_remove(&tcp_estats_idr, id_cid);
                        spin_unlock_bh(&tcp_estats_idr_lock);
                }
                stats->tcpe_cid = -1;

                tcp_estats_unuse(stats);
        }
}

void __init tcp_estats_init()
{
        idr_init(&tcp_estats_idr);

        create_notify_func = &create_func;
        establish_notify_func = &establish_func;
        destroy_notify_func = &destroy_func;

        persist_delay = 60 * HZ;

        if ((tcp_estats_wq = create_workqueue("tcp_estats")) == NULL) {
		printk(KERN_ERR "tcp_estats_init(): alloc_workqueue failed\n");
		goto cleanup_fail;
	}

	tcp_estats_enabled = 1;
        tcp_estats_wq_enabled = 1;

	return;

      cleanup_fail:
	printk("TCP ESTATS: initialization failed.\n");
}

#ifdef CONFIG_IPV6_MODULE
EXPORT_SYMBOL(tcp_estats_create);
EXPORT_SYMBOL(tcp_estats_update_segrecv);
EXPORT_SYMBOL(tcp_estats_update_finish_segrecv);
#endif
