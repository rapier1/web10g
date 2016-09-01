/*
 * net/ipv4/tcp_estats.c
 *
 * Implementation of TCP ESTATS MIB (RFC 4898)
 *
 * Authors:
 *   John Estabrook <jsestabrook@gmail.com>
 *   Andrew K. Adams <akadams@psc.edu>
 *   Kevin Hogan <kwabena@google.com>
 *   Dominin Hamon <dma@stripysock.com>
 *   John Heffner <johnwheffner@gmail.com>
 *   Chris Rapier <rapier@psc.edu>
 *
 * The Web10Gig project.  See http://www.web10gig.org
 *
 * Copyright © 2011, Pittsburgh Supercomputing Center (PSC).
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/export.h>
#ifndef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
#include <linux/jiffies.h>
#endif
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <net/tcp_estats.h>
#include <net/tcp.h>
#include <asm/atomic.h>
#include <asm/byteorder.h>

#define ESTATS_INF32	0xffffffff

#define ESTATS_MAX_CID	5000000

extern int sysctl_tcp_estats;
extern int sysctl_estats_delay;

struct idr tcp_estats_idr;
EXPORT_SYMBOL(tcp_estats_idr);
static int next_id = 1;
DEFINE_SPINLOCK(tcp_estats_idr_lock);

static int get_new_cid(struct tcp_estats *stats);
struct workqueue_struct *tcp_estats_wq = NULL;
void (*destroy_notify_func)(struct work_struct *work);
unsigned long persist_delay = 0;

struct static_key tcp_estats_enabled __read_mostly = STATIC_KEY_INIT_FALSE;
/*EXPORT_SYMBOL(tcp_estats_enabled);*/

/* if HAVE_JUMP_LABEL is defined, then static_key_slow_inc/dec uses a
 *   mutex in its implementation, and hence can't be called if in_interrupt().
 * if HAVE_JUMP_LABEL is NOT defined, then no mutex is used, hence no need
 *   for deferring enable/disable */
#ifdef HAVE_JUMP_LABEL
static atomic_t tcp_estats_enabled_deferred;

static void tcp_estats_handle_deferred_enable_disable(void)
{
	int count = atomic_xchg(&tcp_estats_enabled_deferred, 0);

	while (count > 0) {
		static_key_slow_inc(&tcp_estats_enabled);
		--count;
	}

	while (count < 0) {
		static_key_slow_dec(&tcp_estats_enabled);
		++count;
	}
}
#endif

static inline void tcp_estats_enable(void)
{
#ifdef HAVE_JUMP_LABEL
	if (in_interrupt()) {
		atomic_inc(&tcp_estats_enabled_deferred);
		return;
	}
	tcp_estats_handle_deferred_enable_disable();
#endif
	static_key_slow_inc(&tcp_estats_enabled);
}

static inline void tcp_estats_disable(void)
{
#ifdef HAVE_JUMP_LABEL
	if (in_interrupt()) {
		atomic_dec(&tcp_estats_enabled_deferred);
		return;
	}
	tcp_estats_handle_deferred_enable_disable();
#endif
	static_key_slow_dec(&tcp_estats_enabled);
}

/* Calculates the required amount of memory for any enabled tables. */
int tcp_estats_get_allocation_size(int sysctl)
{
	int size = sizeof(struct tcp_estats) +
		sizeof(struct tcp_estats_connection_table);

	if (sysctl & TCP_ESTATS_TABLEMASK_PERF)
		size += sizeof(struct tcp_estats_perf_table);
	if (sysctl & TCP_ESTATS_TABLEMASK_PATH)
		size += sizeof(struct tcp_estats_path_table);
	if (sysctl & TCP_ESTATS_TABLEMASK_STACK)
		size += sizeof(struct tcp_estats_stack_table);
	if (sysctl & TCP_ESTATS_TABLEMASK_APP)
		size += sizeof(struct tcp_estats_app_table);
	if (sysctl & TCP_ESTATS_TABLEMASK_EXTRAS)
		size += sizeof(struct tcp_estats_extras_table);
	return size;
}

/* Called whenever a TCP/IPv4 sock is created.
 * net/ipv4/tcp_ipv4.c: tcp_v4_syn_recv_sock,
 *			tcp_v4_init_sock
 * Allocates a stats structure and initializes values.
 */
int tcp_estats_create(struct sock *sk, enum tcp_estats_addrtype addrtype,
		      int active)
{
	struct tcp_estats *stats;
	struct tcp_estats_tables *tables;
	struct tcp_sock *tp = tcp_sk(sk);
	void *estats_mem;
	int sysctl;

	/* Read the sysctl once before calculating memory needs and initializing
	 * tables to avoid raciness. */
	sysctl = ACCESS_ONCE(sysctl_tcp_estats);
	if (likely(sysctl == TCP_ESTATS_TABLEMASK_INACTIVE)) {
		return 0;
	}

	/* update the peristence delay if necessary */
	persist_delay = msecs_to_jiffies(ACCESS_ONCE(sysctl_estats_delay));
	
	estats_mem = kzalloc(tcp_estats_get_allocation_size(sysctl), gfp_any());
	if (!estats_mem)
		return -ENOMEM;

	stats = estats_mem;
	estats_mem += sizeof(struct tcp_estats);

	tables = &stats->tables;

	tables->connection_table = estats_mem;
	estats_mem += sizeof(struct tcp_estats_connection_table);

	if (sysctl & TCP_ESTATS_TABLEMASK_PERF) {
		tables->perf_table = estats_mem;
		estats_mem += sizeof(struct tcp_estats_perf_table);
	}
	if (sysctl & TCP_ESTATS_TABLEMASK_PATH) {
		tables->path_table = estats_mem;
		estats_mem += sizeof(struct tcp_estats_path_table);
	}
	if (sysctl & TCP_ESTATS_TABLEMASK_STACK) {
		tables->stack_table = estats_mem;
		estats_mem += sizeof(struct tcp_estats_stack_table);
	}
	if (sysctl & TCP_ESTATS_TABLEMASK_APP) {
		tables->app_table = estats_mem;
		estats_mem += sizeof(struct tcp_estats_app_table);
	}
	if (sysctl & TCP_ESTATS_TABLEMASK_EXTRAS) {
		tables->extras_table = estats_mem;
		estats_mem += sizeof(struct tcp_estats_extras_table);
	}

	stats->tcpe_cid = 0;
	stats->queued = 0;

	tables->connection_table->AddressType = addrtype;

	sock_hold(sk);
	stats->sk = sk;
	atomic_set(&stats->users, 0);

	stats->limstate = TCP_ESTATS_SNDLIM_STARTUP;
	stats->limstate_ts = ktime_get();
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	stats->start_ts = stats->current_ts = stats->limstate_ts;
#else
	stats->start_ts = stats->current_ts = jiffies;
#endif
	do_gettimeofday(&stats->start_tv);

	/* order is important -
	 * must have stats hooked into tp and tcp_estats_enabled()
	 * in order to have the TCP_ESTATS_VAR_<> macros work */
	tp->tcp_stats = stats;
	tcp_estats_enable();

	TCP_ESTATS_VAR_SET(tp, stack_table, ActiveOpen, active);

	TCP_ESTATS_VAR_SET(tp, app_table, SndMax, tp->snd_nxt);
	TCP_ESTATS_VAR_SET(tp, stack_table, SndInitial, tp->snd_nxt);

	TCP_ESTATS_VAR_SET(tp, path_table, MinRTT, ESTATS_INF32);
	TCP_ESTATS_VAR_SET(tp, path_table, MinRTO, ESTATS_INF32);
	TCP_ESTATS_VAR_SET(tp, stack_table, MinMSS, ESTATS_INF32);
	TCP_ESTATS_VAR_SET(tp, stack_table, MinSsthresh, ESTATS_INF32);

	tcp_estats_use(stats);

	return 0;
}

void tcp_estats_destroy(struct sock *sk)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;

	if (stats == NULL)
		return;

	/* Attribute final sndlim time. */
	tcp_estats_update_sndlim(tcp_sk(stats->sk), stats->limstate);

	/* we use a work queue so that we can get the stat struct
	 * to persist for some period of time after the socket closes
	 * allows us to get data on short lived flows and more accurate
	 * stats
	 */ 
	
	if (likely(sysctl_estats_delay == 0)) {
		int id_cid;
		id_cid = stats->tcpe_cid;
		
		if (id_cid == 0)
			pr_devel("TCP estats destroyed before being established.\n");
		
		if (id_cid >= 0) {
			if (id_cid) {
				spin_lock_bh(&tcp_estats_idr_lock);
				idr_remove(&tcp_estats_idr, id_cid);
				spin_unlock_bh(&tcp_estats_idr_lock);
			}
			stats->tcpe_cid = -1;
			
			tcp_estats_unuse(stats);
		}
	} else {
		INIT_DELAYED_WORK(&stats->destroy_notify,
				  destroy_notify_func);
		queue_delayed_work(tcp_estats_wq, &stats->destroy_notify,
				   persist_delay);
	}
}

/* Do not call directly.  Called from tcp_estats_unuse() through call_rcu. */
void tcp_estats_free(struct rcu_head *rcu)
{
	struct tcp_estats *stats = container_of(rcu, struct tcp_estats, rcu);
	tcp_estats_disable();
	kfree(stats);
}
/*EXPORT_SYMBOL(tcp_estats_free);*/

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
	struct tcp_estats_connection_table *conn_table;
	int err;
	err =  0;
	
	if (stats == NULL)
		return;

	conn_table = stats->tables.connection_table;

	/* Let's set these here, since they can't change once the
	 * connection is established.
	 */
	conn_table->LocalPort = inet->inet_num;
	conn_table->RemPort = ntohs(inet->inet_dport);

	if (conn_table->AddressType == TCP_ESTATS_ADDRTYPE_IPV4) {
		memcpy(&conn_table->LocalAddress.addr, &inet->inet_rcv_saddr,
			sizeof(struct in_addr));
		memcpy(&conn_table->RemAddress.addr, &inet->inet_daddr,
			sizeof(struct in_addr));
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (conn_table->AddressType == TCP_ESTATS_ADDRTYPE_IPV6) {
		memcpy(&conn_table->LocalAddress.addr6, &(sk)->sk_v6_rcv_saddr,
		       sizeof(struct in6_addr));
		/* ipv6 daddr now uses a different struct than saddr */
		memcpy(&conn_table->RemAddress.addr6, &(sk)->sk_v6_daddr,
		       sizeof(struct in6_addr));
	}
#endif
	else {
		pr_err("TCP ESTATS: AddressType not valid.\n");
	}

	tcp_estats_update_finish_segrecv(tp);
	tcp_estats_update_rwin_rcvd(tp);
	tcp_estats_update_rwin_sent(tp);

	TCP_ESTATS_VAR_SET(tp, stack_table, RecInitial, tp->rcv_nxt);

	tcp_estats_update_sndlim(tp, TCP_ESTATS_SNDLIM_SENDER);

	if ((stats->tcpe_cid) > 0) {
		pr_err("TCP estats container established multiple times.\n");
		return;
	}
	
	if ((stats->tcpe_cid) == 0) {
		err = get_new_cid(stats);
		if (err)
			pr_devel("get_new_cid error %d\n", err);
	}
}

/*
 * Statistics update functions
 */

void tcp_estats_update_snd_nxt(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;

	if (stats->tables.app_table) {
		if (after(tp->snd_nxt, stats->tables.app_table->SndMax))
			stats->tables.app_table->SndMax = tp->snd_nxt;
	}
}

/* void tcp_estats_update_acked(struct tcp_sock *tp, u32 ack) */
/* { */
/* 	struct tcp_estats *stats = tp->tcp_stats; */

/* 	if (stats->tables.app_table) */
/* 		stats->tables.app_table->ThruOctetsAcked += ack - tp->snd_una; */
/* } */

void tcp_estats_update_rtt(struct sock *sk, unsigned long rtt_sample)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;
	struct tcp_estats_path_table *path_table = stats->tables.path_table;
	unsigned long rtt_sample_msec = rtt_sample/1000;
	u32 rto;

	if (path_table == NULL)
		return;

	path_table->SampleRTT = rtt_sample_msec;

	if (rtt_sample_msec > path_table->MaxRTT)
		path_table->MaxRTT = rtt_sample_msec;
	if (rtt_sample_msec < path_table->MinRTT)
		path_table->MinRTT = rtt_sample_msec;

	path_table->CountRTT++;
	path_table->SumRTT += rtt_sample_msec;

	rto = jiffies_to_msecs(inet_csk(sk)->icsk_rto);
	if (rto > path_table->MaxRTO)
		path_table->MaxRTO = rto;
	if (rto < path_table->MinRTO)
		path_table->MinRTO = rto;
}

void tcp_estats_update_timeout(struct sock *sk)
{
	if (inet_csk(sk)->icsk_backoff)
		TCP_ESTATS_VAR_INC(tcp_sk(sk), stack_table, SubsequentTimeouts);
	else
		TCP_ESTATS_VAR_INC(tcp_sk(sk), perf_table, Timeouts);

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open)
		TCP_ESTATS_VAR_INC(tcp_sk(sk), stack_table, AbruptTimeouts);
}

void tcp_estats_update_mss(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_stack_table *stack_table = stats->tables.stack_table;
	int mss = tp->mss_cache;

	if (stack_table == NULL)
		return;

	if (mss > stack_table->MaxMSS)
		stack_table->MaxMSS = mss;
	if (mss < stack_table->MinMSS)
		stack_table->MinMSS = mss;
}

void tcp_estats_update_finish_segrecv(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_tables *tables = &stats->tables;
	struct tcp_estats_perf_table *perf_table = tables->perf_table;
	struct tcp_estats_stack_table *stack_table = tables->stack_table;
	u32 mss = tp->mss_cache;
	u32 cwnd;
	u32 ssthresh;
	u32 pipe_size;

#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	stats->current_ts = ktime_get();
#else
	stats->current_ts = jiffies;
#endif

	if (stack_table != NULL) {
		cwnd = tp->snd_cwnd * mss;
		if (tp->snd_cwnd <= tp->snd_ssthresh) {
			if (cwnd > stack_table->MaxSsCwnd)
				stack_table->MaxSsCwnd = cwnd;
		} else if (cwnd > stack_table->MaxCaCwnd) {
			stack_table->MaxCaCwnd = cwnd;
		}
	}

	if (perf_table != NULL) {
		pipe_size = tcp_packets_in_flight(tp) * mss;
		if (pipe_size > perf_table->MaxPipeSize)
			perf_table->MaxPipeSize = pipe_size;
	}

	/* Discard initiail ssthresh set at infinity. */
	if (tp->snd_ssthresh >= TCP_INFINITE_SSTHRESH) {
		return;
	}

	if (stack_table != NULL) {
		ssthresh = tp->snd_ssthresh * tp->mss_cache;
		if (ssthresh > stack_table->MaxSsthresh)
			stack_table->MaxSsthresh = ssthresh;
		if (ssthresh < stack_table->MinSsthresh)
			stack_table->MinSsthresh = ssthresh;
	}
}
/* EXPORT_SYMBOL(tcp_estats_update_finish_segrecv);*/

void tcp_estats_update_rwin_rcvd(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_perf_table *perf_table = stats->tables.perf_table;
	u32 win = tp->snd_wnd;

	if (perf_table == NULL)
		return;

	if (win > perf_table->MaxRwinRcvd)
		perf_table->MaxRwinRcvd = win;
	if (win == 0)
		perf_table->ZeroRwinRcvd++;
}

void tcp_estats_update_rwin_sent(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_perf_table *perf_table = stats->tables.perf_table;
	u32 win = tp->rcv_wnd;

	if (perf_table == NULL)
		return;

	if (win > perf_table->MaxRwinSent)
		perf_table->MaxRwinSent = win;
	if (win == 0)
		perf_table->ZeroRwinSent++;
}

void tcp_estats_update_sndlim(struct tcp_sock *tp,
			      enum tcp_estats_sndlim_states state)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_perf_table *perf_table = stats->tables.perf_table;
	ktime_t now;

	if (state <= TCP_ESTATS_SNDLIM_NONE ||
	    state >= TCP_ESTATS_SNDLIM_NSTATES) {
		pr_err("tcp_estats_update_sndlim: BUG: state out of range %d\n",
		       state);
		return;
	}

	if (perf_table == NULL)
		return;

	now = ktime_get();
	perf_table->snd_lim_time[stats->limstate]
	    += ktime_to_us(ktime_sub(now, stats->limstate_ts));
	stats->limstate_ts = now;
	if (stats->limstate != state) {
		stats->limstate = state;
		perf_table->snd_lim_trans[state]++;
	}
}

void tcp_estats_update_congestion(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_path_table *path_table = stats->tables.path_table;

	TCP_ESTATS_VAR_INC(tp, perf_table, CongSignals);

	if (path_table != NULL) {
		path_table->PreCongSumCwnd += tp->snd_cwnd * tp->mss_cache;
		path_table->PreCongSumRTT += path_table->SampleRTT;
	}
}

void tcp_estats_update_post_congestion(struct tcp_sock *tp)
{
	struct tcp_estats *stats = tp->tcp_stats;
	struct tcp_estats_path_table *path_table = stats->tables.path_table;

	if (path_table != NULL) {
		path_table->PostCongCountRTT++;
		path_table->PostCongSumRTT += path_table->SampleRTT;
	}
}

void tcp_estats_update_segsend(struct sock *sk, int pcount,
			       u32 seq, u32 end_seq, int flags)
{
	struct tcp_estats *stats = tcp_sk(sk)->tcp_stats;
	struct tcp_estats_perf_table *perf_table = stats->tables.perf_table;
	struct tcp_estats_app_table *app_table = stats->tables.app_table;

	int data_len = end_seq - seq;

#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	stats->current_ts = ktime_get();
#else
	stats->current_ts = jiffies;
#endif

	if (perf_table == NULL)
		return;

	/* We know we're sending a segment. */
	/*perf_table->SegsOut += pcount;*/

	/* A pure ACK contains no data; everything else is data. */
	if (data_len > 0) { 
	/*	perf_table->DataSegsOut += pcount;*/
		perf_table->DataOctetsOut += data_len;
		}

	/* Check for retransmission. */
	if (flags & TCPHDR_SYN) {
		if (inet_csk(sk)->icsk_retransmits)
			perf_table->SegsRetrans++;
	} else if (app_table != NULL &&
		   before(seq, app_table->SndMax)) {
		perf_table->SegsRetrans += pcount;
		perf_table->OctetsRetrans += data_len;
	}
}

void tcp_estats_update_segrecv(struct tcp_sock *tp, struct sk_buff *skb)
{
	struct tcp_estats_tables *tables = &tp->tcp_stats->tables;
	struct tcp_estats_path_table *path_table = tables->path_table;
	struct tcp_estats_perf_table *perf_table = tables->perf_table;
	struct tcp_estats_stack_table *stack_table = tables->stack_table;
	struct tcphdr *th = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);

	/*if (perf_table != NULL)*/
	/*	perf_table->SegsIn++; */

	if (skb->len == th->doff * 4) {
		if (stack_table != NULL &&
		    TCP_SKB_CB(skb)->ack_seq == tp->snd_una)
			stack_table->DupAcksIn++;
	} else {
		if (perf_table != NULL) {
			/*perf_table->DataSegsIn++;*/
			perf_table->DataOctetsIn += skb->len - th->doff * 4;
		}
	}

	if (path_table != NULL) {
		path_table->IpTtl = iph->ttl;
		path_table->IpTosIn = iph->tos;
	}
}
/*EXPORT_SYMBOL(tcp_estats_update_segrecv);*/

/* void tcp_estats_update_rcvd(struct tcp_sock *tp, u32 seq) */
/* { */
/*         /\* After much debate, it was decided that "seq - rcv_nxt" is  */
/*            indeed what we want, as opposed to what Krishnan suggested  */
/*            to better match the RFC: "seq - tp->rcv_wup" *\/ */
/* 	TCP_ESTATS_VAR_ADD(tp, app_table, ThruOctetsReceived, */
/* 			   seq - tp->rcv_nxt); */
/* } */

void tcp_estats_update_writeq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_estats_app_table *app_table =
			tp->tcp_stats->tables.app_table;
	int len;

	if (app_table == NULL)
		return;

	len = tp->write_seq - app_table->SndMax;

	if (len > app_table->MaxAppWQueue)
		app_table->MaxAppWQueue = len;
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
	struct tcp_estats_tables *tables = &tp->tcp_stats->tables;
	struct tcp_estats_app_table *app_table = tables->app_table;
	struct tcp_estats_stack_table *stack_table = tables->stack_table;

	if (app_table != NULL) {
		u32 len = tp->rcv_nxt - tp->copied_seq;
		if (app_table->MaxAppRQueue < len)
			app_table->MaxAppRQueue = len;
	}

	if (stack_table != NULL) {
		u32 len = ofo_qlen(tp);
		if (stack_table->MaxReasmQueue < len)
			stack_table->MaxReasmQueue = len;
	}
}

/*
 * Manage connection ID table
 */

static int get_new_cid(struct tcp_estats *stats)
{
         int id_cid;

again:
         spin_lock_bh(&tcp_estats_idr_lock);
         id_cid = idr_alloc(&tcp_estats_idr, stats, next_id, 0, GFP_NOWAIT);
         if (unlikely(id_cid == -ENOSPC)) {
                 spin_unlock_bh(&tcp_estats_idr_lock);
                 goto again;
         }
         if (unlikely(id_cid == -ENOMEM)) {
                 spin_unlock_bh(&tcp_estats_idr_lock);
                 return -ENOMEM;
         }
         next_id = (id_cid + 1) % ESTATS_MAX_CID;
         stats->tcpe_cid = id_cid;
         spin_unlock_bh(&tcp_estats_idr_lock);
         return 0;
}

static void destroy_func(struct work_struct *work)
{
	struct tcp_estats *stats = container_of(work, struct tcp_estats,
						destroy_notify.work);

	int id_cid = stats->tcpe_cid;

	if (id_cid == 0)
		pr_devel("TCP estats destroyed before being established.\n");

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

	destroy_notify_func = &destroy_func;
	tcp_estats_wq = alloc_workqueue("tcp_estats", WQ_MEM_RECLAIM, 0);
	if (tcp_estats_wq == NULL) {
		pr_err("tcp_estats_init(): alloc_workqueue failed\n");
		goto cleanup_fail;
	}

	return;

cleanup_fail:
	pr_err("TCP ESTATS: initialization failed.\n");

}
