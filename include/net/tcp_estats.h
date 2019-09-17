/*
 * include/net/tcp_estats.h
 *
 * Implementation of TCP Extended Statistics MIB (RFC 4898)
 *
 * Authors:
 *   John Estabrook <jsestabrook@gmail.com>
 *   Andrew K. Adams <akadams@psc.edu>
 *   Kevin Hogan <kwabena@google.com>
 *   Dominic Hamon <dma@stripysock.com>
 *   John Heffner <johnwheffner@gmail.com>
 *   Chris Rapier <rapier@psc.edu>
 *
 * The Web10Gig project.  See http://www.web10g.org
 *
 * Copyright © 2011, Pittsburgh Supercomputing Center (PSC).
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _TCP_ESTATS_H
#define _TCP_ESTATS_H

#include <net/sock.h>
#include <linux/idr.h>
#include <linux/in.h>
#include <linux/jump_label.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>

/* defines number of seconds that stats persist after connection ends */
/* dfeault is 0 seconds. Can be reset via sysctl */
#define TCP_ESTATS_PERSIST_DELAY_MSECS 0

enum tcp_estats_sndlim_states {
	TCP_ESTATS_SNDLIM_NONE = -1,
	TCP_ESTATS_SNDLIM_SENDER,
	TCP_ESTATS_SNDLIM_CWND,
	TCP_ESTATS_SNDLIM_RWIN,
	TCP_ESTATS_SNDLIM_STARTUP,
	TCP_ESTATS_SNDLIM_TSODEFER,
	TCP_ESTATS_SNDLIM_PACE,
	TCP_ESTATS_SNDLIM_NSTATES	/* Keep at end */
};

enum tcp_estats_addrtype {
	TCP_ESTATS_ADDRTYPE_IPV4 = 1,
	TCP_ESTATS_ADDRTYPE_IPV6 = 2
};

enum tcp_estats_softerror_reason {
	TCP_ESTATS_SOFTERROR_BELOW_DATA_WINDOW = 1,
	TCP_ESTATS_SOFTERROR_ABOVE_DATA_WINDOW = 2,
	TCP_ESTATS_SOFTERROR_BELOW_ACK_WINDOW = 3,
	TCP_ESTATS_SOFTERROR_ABOVE_ACK_WINDOW = 4,
	TCP_ESTATS_SOFTERROR_BELOW_TS_WINDOW = 5,
	TCP_ESTATS_SOFTERROR_ABOVE_TS_WINDOW = 6,
	TCP_ESTATS_SOFTERROR_DATA_CHECKSUM = 7,
	TCP_ESTATS_SOFTERROR_OTHER = 8,
};

#define TCP_ESTATS_INACTIVE	2
#define TCP_ESTATS_ACTIVE	1

#define TCP_ESTATS_TABLEMASK_INACTIVE	0x00
#define TCP_ESTATS_TABLEMASK_ACTIVE	0x01
#define TCP_ESTATS_TABLEMASK_PERF	0x02
#define TCP_ESTATS_TABLEMASK_PATH	0x04
#define TCP_ESTATS_TABLEMASK_STACK	0x08
#define TCP_ESTATS_TABLEMASK_APP	0x10
#define TCP_ESTATS_TABLEMASK_EXTRAS	0x40

#ifdef CONFIG_TCP_ESTATS

extern struct static_key tcp_estats_enabled;

#define TCP_ESTATS_CHECK(tp, table, expr)				\
	do {								\
		if (static_key_false(&tcp_estats_enabled)) {		\
			if (likely((tp)->tcp_stats) &&			\
			    likely((tp)->tcp_stats->tables.table)) {	\
				(expr);					\
			}						\
		}							\
	} while (0)

#define TCP_ESTATS_VAR_INC(tp, table, var)				\
	TCP_ESTATS_CHECK(tp, table, ++((tp)->tcp_stats->tables.table->var))
#define TCP_ESTATS_VAR_DEC(tp, table, var)				\
	TCP_ESTATS_CHECK(tp, table, --((tp)->tcp_stats->tables.table->var))
#define TCP_ESTATS_VAR_ADD(tp, table, var, val)				\
	TCP_ESTATS_CHECK(tp, table,					\
			 ((tp)->tcp_stats->tables.table->var) += (val))
#define TCP_ESTATS_VAR_SET(tp, table, var, val)				\
	TCP_ESTATS_CHECK(tp, table,					\
			 ((tp)->tcp_stats->tables.table->var) = (val))
#define TCP_ESTATS_UPDATE(tp, func)					\
	do {								\
		if (static_key_false(&tcp_estats_enabled)) {		\
			if (likely((tp)->tcp_stats)) {			\
				(func);					\
			}						\
		}							\
	} while (0)

/*
 * Variables that can be read and written directly.
 *
 * Contains all variables from RFC 4898. Commented fields are
 * either not implemented (only StartTimeStamp
 * remains unimplemented in this release) or have
 * handlers and do not need struct storage.
 */
struct tcp_estats_connection_table {
	u32			AddressType;
	union { struct in_addr addr; struct in6_addr addr6; }	LocalAddress;
	union { struct in_addr addr; struct in6_addr addr6; }	RemAddress;
	u16			LocalPort;
	u16			RemPort;
};

struct tcp_estats_perf_table {
	/*u32		SegsOut; */
	/*u32		DataSegsOut;*/
	u64		DataOctetsOut;
	u32		SegsRetrans;
	u32		OctetsRetrans;
	/*u32		SegsIn;*/
	/*u32		DataSegsIn;*/
	u64		DataOctetsIn;
	/*		ElapsedSecs */
	/*		ElapsedMicroSecs */
	/*		StartTimeStamp */
	/*		CurMSS */
	/*		PipeSize */
	u32		MaxPipeSize;
	/*		SmoothedRTT */
	/*		CurRTO */
	u32		CongSignals;
	/*		CurCwnd */
	/*		CurSsthresh */
	u32		Timeouts;
	/*		CurRwinSent */
	u32		MaxRwinSent;
	u32		ZeroRwinSent;
	/*		CurRwinRcvd */
	u32		MaxRwinRcvd;
	u32		ZeroRwinRcvd;
	/*		SndLimTransRwin */
	/*		SndLimTransCwnd */
	/*		SndLimTransSnd */
	/*		SndLimTimeRwin */
	/*		SndLimTimeCwnd */
	/*		SndLimTimeSnd */
	u32		snd_lim_trans[TCP_ESTATS_SNDLIM_NSTATES];
	u32		snd_lim_time[TCP_ESTATS_SNDLIM_NSTATES];
	u32             LostRetransmitSegs;
};

struct tcp_estats_path_table {
	/*		RetranThresh */
	u32		NonRecovDAEpisodes;
	u32		SumOctetsReordered;
	u32		NonRecovDA;
	u32		SampleRTT;
	/*		RTTVar */
	u32		MaxRTT;
	u32		MinRTT;
	u64		SumRTT;
	u32		CountRTT;
	u32		MaxRTO;
	u32		MinRTO;
	u8		IpTtl;
	u8		IpTosIn;
	/*		IpTosOut */
	u32		PreCongSumCwnd;
	u32		PreCongSumRTT;
	u32		PostCongSumRTT;
	u32		PostCongCountRTT;
	u32		ECNsignals;
	u32		DupAckEpisodes;
	/*		RcvRTT */
	u32		DupAcksOut;
	u32		CERcvd;
	u32		ECESent;
};

struct tcp_estats_stack_table {
	u32		ActiveOpen;
	/*		MSSSent */
	/*		MSSRcvd */
	/*		WinScaleSent */
	/*		WinScaleRcvd */
	/*		TimeStamps */
	/*		ECN */
	/*		WillSendSACK */
	/*		WillUseSACK */
	/*		State */
	/*		Nagle */
	u32		MaxSsCwnd;
	u32		MaxCaCwnd;
	u32		MaxSsthresh;
	u32		MinSsthresh;
	/*		InRecovery */
	u32		DupAcksIn;
	u32		SpuriousFrDetected;
	u32		SpuriousRtoDetected;
	u32		SoftErrors;
	u32		SoftErrorReason;
	u32		SlowStart;
	u32		CongAvoid;
	/*u32		OtherReductions;*/
	u32		CongOverCount;
	u32		FastRetran;
	u32		SubsequentTimeouts;
	/*		CurTimeoutCount */
	u32		AbruptTimeouts;
	u32		SACKsRcvd;
	u32		SACKBlocksRcvd;
	u32		SendStall;
	u32		DSACKDups;
	u32		MaxMSS;
	u32		MinMSS;
	u32		SndInitial;
	u32		RecInitial;
	/*		CurRetxQueue */
	/*		MaxRetxQueue */
	/*		CurReasmQueue */
	u32		MaxReasmQueue;
	u32		EarlyRetrans;
	u32		EarlyRetransDelay;
	u32             RackTimeout;
};

struct tcp_estats_app_table {
	/*		SndUna */
	/*		SndNxt */
	u32		SndMax;
	/*u64		ThruOctetsAcked;*/
	/*		RcvNxt */
	/*u64		ThruOctetsReceived;*/
	/*		CurAppWQueue */
	u32		MaxAppWQueue;
	/*		CurAppRQueue */
	u32		MaxAppRQueue;
};

/*
    currently, no backing store is needed for tuning elements in
     web10g - they are all read or written to directly in other
     data structures (such as the socket)
*/

struct tcp_estats_extras_table {
	/*		OtherReductionsCV */
	/*u32		OtherReductionsCM;*/
	u32		Priority;
};

struct tcp_estats_tables {
	struct tcp_estats_connection_table	*connection_table;
	struct tcp_estats_perf_table		*perf_table;
	struct tcp_estats_path_table		*path_table;
	struct tcp_estats_stack_table		*stack_table;
	struct tcp_estats_app_table		*app_table;
	struct tcp_estats_extras_table		*extras_table;
};

struct tcp_estats {
	int				tcpe_cid; /* idr map id */

	struct sock			*sk;
	kuid_t				uid;
	kgid_t				gid;
	int				ids;

	atomic_t			users;

	enum tcp_estats_sndlim_states	limstate;
	ktime_t				limstate_ts;
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	ktime_t				start_ts;
	ktime_t				current_ts;
#else
	unsigned long			start_ts;
	unsigned long			current_ts;
#endif
	struct timespec64	       	start_tv;

        int				queued;
        struct delayed_work		destroy_notify;

	struct tcp_estats_tables	tables;

	struct rcu_head			rcu;
};

extern struct idr tcp_estats_idr;

extern int tcp_estats_wq_enabled;
extern struct workqueue_struct *tcp_estats_wq;
extern void (*destroy_notify_func)(struct work_struct *work);

extern unsigned long persist_delay;
extern spinlock_t tcp_estats_idr_lock;

/* For the TCP code */
extern int  tcp_estats_create(struct sock *sk, enum tcp_estats_addrtype t,
			      int active);
extern void tcp_estats_destroy(struct sock *sk);
extern void tcp_estats_establish(struct sock *sk);
extern void tcp_estats_free(struct rcu_head *rcu);

extern void tcp_estats_update_snd_nxt(struct tcp_sock *tp);
extern void tcp_estats_update_acked(struct tcp_sock *tp, u32 ack);
extern void tcp_estats_update_rtt(struct sock *sk, unsigned long rtt_sample);
extern void tcp_estats_update_timeout(struct sock *sk);
extern void tcp_estats_update_mss(struct tcp_sock *tp);
extern void tcp_estats_update_rwin_rcvd(struct tcp_sock *tp);
extern void tcp_estats_update_sndlim(struct tcp_sock *tp,
				     enum tcp_estats_sndlim_states why);
extern void tcp_estats_update_rcvd(struct tcp_sock *tp, u32 seq);
extern void tcp_estats_update_rwin_sent(struct tcp_sock *tp);
extern void tcp_estats_update_congestion(struct tcp_sock *tp);
extern void tcp_estats_update_post_congestion(struct tcp_sock *tp);
extern void tcp_estats_update_segsend(struct sock *sk, int pcount,
                                      u32 seq, u32 end_seq, int flags);
extern void tcp_estats_update_segrecv(struct tcp_sock *tp, struct sk_buff *skb);
extern void tcp_estats_update_finish_segrecv(struct tcp_sock *tp);
extern void tcp_estats_update_writeq(struct sock *sk);
extern void tcp_estats_update_recvq(struct sock *sk);

extern void tcp_estats_init(void);

static inline void tcp_estats_use(struct tcp_estats *stats)
{
	atomic_inc(&stats->users);
}

static inline int tcp_estats_use_if_valid(struct tcp_estats *stats)
{
	return atomic_inc_not_zero(&stats->users);
}

static inline void tcp_estats_unuse(struct tcp_estats *stats)
{
	if (atomic_dec_and_test(&stats->users)) {
		sock_put(stats->sk);
		stats->sk = NULL;
		call_rcu(&stats->rcu, tcp_estats_free);
	}
}

#else /* !CONFIG_TCP_ESTATS */

#define tcp_estats_enabled	(0)

#define TCP_ESTATS_VAR_INC(tp, table, var)	do {} while (0)
#define TCP_ESTATS_VAR_DEC(tp, table, var)	do {} while (0)
#define TCP_ESTATS_VAR_ADD(tp, table, var, val)	do {} while (0)
#define TCP_ESTATS_VAR_SET(tp, table, var, val)	do {} while (0)
#define TCP_ESTATS_UPDATE(tp, func)		do {} while (0)

static inline void tcp_estats_init(void) { }
static inline void tcp_estats_establish(struct sock *sk) { }
static inline void tcp_estats_create(struct sock *sk,
				     enum tcp_estats_addrtype t,
				     int active) { }
static inline void tcp_estats_destroy(struct sock *sk) { }

#endif /* CONFIG_TCP_ESTATS */

#endif /* _TCP_ESTATS_H */
