/*
 * include/net/tcp_estats.h
 *
 * Implementation of TCP ESTATS MIB (RFC 4898)
 *
 * Authors:
 *   John Estabrook <jestabro@ncsa.illinois.edu>
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

#ifndef _TCP_ESTATS_H
#define _TCP_ESTATS_H

#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

enum tcp_estats_sndlim_states {
	TCP_ESTATS_SNDLIM_NONE = -1,
	TCP_ESTATS_SNDLIM_SENDER,
	TCP_ESTATS_SNDLIM_CWND,
	TCP_ESTATS_SNDLIM_RWIN,
	TCP_ESTATS_SNDLIM_STARTUP,
	TCP_ESTATS_SNDLIM_NSTATES	/* Keep at end */
};

enum tcp_estats_addrtype {
	TCP_ESTATS_ADDRTYPE_IPV4 = 1,
	TCP_ESTATS_ADDRTYPE_IPV6 = 2
};

#ifdef CONFIG_TCP_ESTATS
#define TCP_ESTATS_CHECK(tp,expr) \
	do { if ((tp)->tcp_stats) (expr); } while (0)
#define TCP_ESTATS_VAR_INC(tp,var) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var)++)
#define TCP_ESTATS_VAR_DEC(tp,var) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var)--)
#define TCP_ESTATS_VAR_ADD(tp,var,val) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var) += (val))
#define TCP_ESTATS_VAR_SET(tp,var,val) \
	TCP_ESTATS_CHECK(tp, ((tp)->tcp_stats->estats_vars.var) = (val))
#define TCP_ESTATS_UPDATE(tp,func) \
	TCP_ESTATS_CHECK(tp, func)

/*
 * Variables that can be read and written directly.
 *
 * Contains all variables from RFC 4898. Commented fields are
 * either not implemented (only ElapsedSecs, ElapsedMicroSecs,
 * StartTimeStamp remain unimplemented in this release) or have
 * handlers and do not need struct storage.
 */
struct tcp_estats_directs {
	/* Connection table */
	u32			LocalAddressType;
	struct { u8 data[17]; }	LocalAddress;
	struct { u8 data[17]; }	RemAddress;
	u16			LocalPort;
	u16			RemPort;

	/* Perf table */
	u32		SegsOut;
	u32		DataSegsOut;
	u64		DataOctetsOut;
	u32		SegsRetrans;
	u32		OctetsRetrans;
	u32		SegsIn;
	u32		DataSegsIn;
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
	
	/* Path table */
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
	
	/* Stack table */
	u32		ActiveOpen;
	/*		MSSSent */
	/* 		MSSRcvd */
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
	u32		OtherReductions;
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
	u32		CurRetxQueue;
	u32		MaxRetxQueue;
	/*		CurReasmQueue */
	u32		MaxReasmQueue;

	/* App table */
	/*		SndUna */
	/*		SndNxt */
	u32		SndMax;
	u64		ThruOctetsAcked;
	/*		RcvNxt */
	u64		ThruOctetsReceived;
	/*		CurAppWQueue */
	u32		MaxAppWQueue;
	/*		CurAppRQueue */
	u32		MaxAppRQueue;
	
	/* Tune table */
	/*		LimCwnd */
	/*		LimSsthresh */
	/*		LimRwin */
	/*		LimMSS */
	
	/* Extras */
	u32		OtherReductionsCV;
	u32		OtherReductionsCM;
};

struct tcp_estats {
        int                             tcpe_cid; // idr map id

	struct sock			*estats_sk;

	atomic_t			estats_users;

	int				estats_limstate;
	ktime_t				estats_limstate_ts;
	ktime_t				estats_start_ts;
	ktime_t				estats_current_ts;
	struct timeval			estats_start_tv;

        int                             queued;
        struct work_struct              create_notify;
        struct work_struct              establish_notify;
        struct delayed_work             destroy_notify;

	struct tcp_estats_directs	estats_vars;
};

extern struct idr tcp_estats_idr;

extern int tcp_estats_wq_enabled;
extern struct workqueue_struct *tcp_estats_wq;
extern void (*create_notify_func)(struct work_struct *work);
extern void (*establish_notify_func)(struct work_struct *work);
extern void (*destroy_notify_func)(struct work_struct *work);

extern unsigned long persist_delay;
extern spinlock_t tcp_estats_idr_lock;

/* For the TCP code */
extern int  tcp_estats_create(struct sock *sk, enum tcp_estats_addrtype t);
extern void tcp_estats_destroy(struct sock *sk);
extern void tcp_estats_free(struct tcp_estats *stats);
extern void tcp_estats_establish(struct sock *sk);

extern void tcp_estats_update_snd_nxt(struct tcp_sock *tp);
extern void tcp_estats_update_acked(struct tcp_sock *tp, u32 ack);
extern void tcp_estats_update_rtt(struct sock *sk, unsigned long rtt_sample);
extern void tcp_estats_update_timeout(struct sock *sk);
extern void tcp_estats_update_mss(struct tcp_sock *tp);
extern void tcp_estats_update_rwin_rcvd(struct tcp_sock *tp);
extern void tcp_estats_update_sndlim(struct tcp_sock *tp, int why);
extern void tcp_estats_update_rcvd(struct tcp_sock *tp, u32 seq);
extern void tcp_estats_update_rwin_sent(struct tcp_sock *tp);
extern void tcp_estats_update_congestion(struct tcp_sock *tp);
extern void tcp_estats_update_post_congestion(struct tcp_sock *tp);
extern void tcp_estats_update_segsend(struct sock *sk, int len, int pcount,
                                      u32 seq, u32 end_seq, int flags);
extern void tcp_estats_update_segrecv(struct tcp_sock *tp, struct sk_buff *skb);
extern void tcp_estats_update_finish_segrecv(struct tcp_sock *tp);
extern void tcp_estats_update_writeq(struct sock *sk);
extern void tcp_estats_update_recvq(struct sock *sk);

extern void tcp_estats_init(void);

static inline void tcp_estats_use(struct tcp_estats *stats)
{
	atomic_inc(&stats->estats_users);
}

static inline void tcp_estats_unuse(struct tcp_estats *stats)
{
	if (atomic_dec_and_test(&stats->estats_users))
		tcp_estats_free(stats);
}

#else /* !CONFIG_TCP_ESTATS */

#define tcp_estats_enabled	(0)

#define TCP_ESTATS_VAR_INC(tp,var)	do {} while (0)
#define TCP_ESTATS_VAR_DEC(tp,var)	do {} while (0)
#define TCP_ESTATS_VAR_SET(tp,var,val)	do {} while (0)
#define TCP_ESTATS_VAR_ADD(tp,var,val)	do {} while (0)
#define TCP_ESTATS_UPDATE(tp,func)	do {} while (0)

static inline void tcp_estats_init(void) { }
static inline void tcp_estats_establish(struct sock *sk) { }
static inline void tcp_estats_create(struct sock *sk, enum tcp_estats_addrtype t) { }
static inline void tcp_estats_destroy(struct sock *sk) { }

#endif /* CONFIG_TCP_ESTATS */

#endif /* _TCP_ESTATS_H */
