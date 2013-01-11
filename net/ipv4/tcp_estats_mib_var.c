#include <linux/export.h>
#include <net/tcp_estats_mib_var.h>

#define OFFSET_TP(field)	((unsigned long)(&(((struct tcp_sock *)NULL)->field)))

static void read_stats(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)stats + vp->read_data, tcp_estats_var_len(vp));
}

static void read_sk32(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)(stats->estats_sk) + vp->read_data, 4);
}

static void read_inf32(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
        u32 val;

	memcpy(&val, (char *)stats + vp->read_data, 8);
        val &= 0xffffffff;
	memcpy(buf, &val, 4);
}

static void read_ElapsedSecs(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
        u32 val = 0; // currently unimplemented

        memcpy(buf, &val, 4);
}

static void read_ElapsedMicroSecs(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
        u32 val = 0; // currently unimplemented

        memcpy(buf, &val, 4);
}

static void read_StartTimeStamp(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
        u8 val = 0; // currently unimplemented

        memcpy(buf, &val, 1);
}

static void read_PipeSize(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tcp_packets_in_flight(tp) * tp->mss_cache;
	memcpy(buf, &val, 4);
}

static void read_SmoothedRTT(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;
	
	val = (tp->srtt >> 3) * 1000 / HZ;
	memcpy(buf, &val, 4);
}

static void read_CurRTO(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->estats_sk);
	u32 val;

	val = icsk->icsk_rto * 1000 / HZ;
	memcpy(buf, &val, 4);
}

static void read_CurCwnd(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->snd_cwnd * tp->mss_cache;
	memcpy(buf, &val, 4);
}

static void read_CurSsthresh(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->snd_ssthresh == 0x7fffffff ?
	      tp->snd_ssthresh * tp->mss_cache : 0xffffffff;
	memcpy(buf, &val, 4);
}

static void read_RetranThresh(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->reordering;
	memcpy(buf, &val, 4);
}

static void read_RTTVar(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = (tp->rttvar >> 2) * 1000 / HZ;
	memcpy(buf, &val, 4);
}

/* Note: this value returned is technically incorrect between a
 * setsockopt of IP_TOS, and when the next segment is sent. */
static void read_IpTosOut(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct inet_sock *inet = inet_sk(stats->estats_sk);

	*(char *)buf = inet->tos;
}

static void read_RcvRTT(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;
	
	val = ((1000000*tp->rcv_rtt_est.rtt)/HZ)>>3;
	memcpy(buf, &val, 4);
}

static void read_MSSSent(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->advmss;
	memcpy(buf, &val, 4);
}

static void read_MSSRcvd(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val;

	val = tp->rx_opt.rec_mss;
	memcpy(buf, &val, 4);
}

/* Note: WinScaleSent and WinScaleRcvd are incorrectly
 * implemented for the case where we sent a scale option
 * but did not receive one. */
static void read_WinScaleSent(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	val = tp->rx_opt.wscale_ok ? tp->rx_opt.rcv_wscale : -1;
	memcpy(buf, &val, 4);
}

static void read_WinScaleRcvd(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	val = tp->rx_opt.wscale_ok ? tp->rx_opt.snd_wscale : -1;
	memcpy(buf, &val, 4);
}

/* Note: all these (TimeStamps, ECN, SACK, Nagle) are incorrect
 * if the sysctl values are changed during the connection. */
static void read_TimeStamps(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	if (tp->rx_opt.tstamp_ok)
		val = 1;
	else
		val = sysctl_tcp_timestamps ? 3 : 2;

	memcpy(buf, &val, 4);
}

static void read_ECN(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	if (tp->ecn_flags & TCP_ECN_OK)
		val = 1;
	else
		val = sysctl_tcp_ecn ? 3 : 2;
	memcpy(buf, &val, 4);
}

static void read_WillSendSACK(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	if (tp->rx_opt.sack_ok)
		val = 1;
	else
		val = sysctl_tcp_sack ? 3 : 2;

	memcpy(buf, &val, 4);
}

#define read_WillUseSACK	read_WillSendSACK

static void read_State(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	/* A mapping from Linux to MIB state. */
	static char state_map[] = { 0, TCP_ESTATS_STATE_ESTABLISHED,
				    TCP_ESTATS_STATE_SYNSENT,
				    TCP_ESTATS_STATE_SYNRECEIVED,
				    TCP_ESTATS_STATE_FINWAIT1,
				    TCP_ESTATS_STATE_FINWAIT2,
				    TCP_ESTATS_STATE_TIMEWAIT,
				    TCP_ESTATS_STATE_CLOSED,
				    TCP_ESTATS_STATE_CLOSEWAIT,
				    TCP_ESTATS_STATE_LASTACK,
				    TCP_ESTATS_STATE_LISTEN,
				    TCP_ESTATS_STATE_CLOSING };
	s32 val = state_map[stats->estats_sk->sk_state];
	
	memcpy(buf, &val, 4);
}

static void read_Nagle(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	s32 val;

	val = tp->nonagle ? 2 : 1;
	memcpy(buf, &val, 4);
}

static void read_InRecovery(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->estats_sk);
	s32 val;

	val = icsk->icsk_ca_state > TCP_CA_CWR ? 1 : 2;
	memcpy(buf, &val, 4);
}

static void read_CurTimeoutCount(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->estats_sk);
	u32 val;
	
	val = icsk->icsk_retransmits;
	memcpy(buf, &val, 4);
}

static inline u32 ofo_qlen(struct tcp_sock *tp)
{
	if (!skb_peek(&tp->out_of_order_queue))
		return 0;
	else
		return TCP_SKB_CB(tp->out_of_order_queue.prev)->end_seq -
		    TCP_SKB_CB(tp->out_of_order_queue.next)->seq;
}

static void read_CurReasmQueue(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val = ofo_qlen(tp);

	memcpy(buf, &val, 4);
}

static void read_CurAppWQueue(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val = tp->write_seq - stats->estats_vars.SndMax;

	memcpy(buf, &val, 4);
}

static void read_CurAppRQueue(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 val = tp->rcv_nxt - tp->copied_seq;

	memcpy(buf, &val, 4);
}

static void read_LimCwnd(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);
	u32 tmp = (u32) (tp->snd_cwnd_clamp * tp->mss_cache);

	memcpy(buf, &tmp, 4);
}

static void read_LimSsthresh(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	u32 tmp = (u32) sysctl_tcp_max_ssthresh;

	if (tmp == 0)
		tmp = 0x7fffffff;
	memcpy(buf, &sysctl_tcp_max_ssthresh, 4);
}

static void write_LimCwnd(void *buf, struct tcp_estats *stats,
	struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->estats_sk);

	tp->snd_cwnd_clamp = min(*(u32 *) buf / tp->mss_cache, 65535U);
}

static void read_LimRwin(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)(stats->estats_sk) + OFFSET_TP(window_clamp), 4);
}

static void write_LimRwin(void *buf, struct tcp_estats *stats,
	struct tcp_estats_var *vp)
{
        u32 val;
        struct tcp_sock *tp = tcp_sk(stats->estats_sk);

        memcpy(&val, buf, 4);
        tp->window_clamp = min(val, 65535U << tp->rx_opt.rcv_wscale);
}

static void read_LimMSS(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)(stats->estats_sk) + OFFSET_TP(rx_opt.mss_clamp), 4);
}

#define OFFSET_ST(field)	((unsigned long)(&(((struct tcp_estats *)NULL)->estats_vars.field)))

#define ESTATSVAR(__name,__type)		{ .name = #__name, .type = TCP_ESTATS_##__type, .read = read_stats, .read_data = OFFSET_ST(__name), .write = NULL }
#define ESTATSVARN(__name,__type,__var)	{ .name = #__name, .type = TCP_ESTATS_##__type, .read = read_stats, .read_data = OFFSET_ST(__var), .write = NULL }
#define TPVAR32(__name,__type,__var)	{ .name = #__name, .type = TCP_ESTATS_##__type, .read = read_sk32, .read_data = OFFSET_TP(__var), .write = NULL }
#define HCINF32(__name,__type) { .name = #__name, .type = TCP_ESTATS_##__type, .read = read_inf32, .read_data = OFFSET_ST(__name), .write = NULL }
#define READFUNC(__name,__type)		{ .name = #__name, .type = TCP_ESTATS_##__type, .read = read_##__name, .write = NULL }
#define RWFUNC(__name,__type)		{ .name = #__name, .type = TCP_ESTATS_##__type, .read = read_##__name, .write = write_##__name }

int max_index[MAX_TABLE] = { PERF_INDEX_MAX, PATH_INDEX_MAX, STACK_INDEX_MAX, APP_INDEX_MAX, TUNE_INDEX_MAX };
EXPORT_SYMBOL(max_index);

struct tcp_estats_var perf_var_array[] = {
        ESTATSVAR(SegsOut,UNSIGNED32),
        ESTATSVAR(DataSegsOut,UNSIGNED32),
        HCINF32(DataOctetsOut,UNSIGNED32),
        ESTATSVARN(HCDataOctetsOut,UNSIGNED64, DataOctetsOut),
        ESTATSVAR(SegsRetrans,UNSIGNED32),
        ESTATSVAR(OctetsRetrans,UNSIGNED32),
        ESTATSVAR(SegsIn,UNSIGNED32),
        ESTATSVAR(DataSegsIn,UNSIGNED32),
        HCINF32(DataOctetsIn,UNSIGNED32),
        ESTATSVARN(HCDataOctetsIn,UNSIGNED64, DataOctetsIn),
        READFUNC(ElapsedSecs,UNSIGNED32),
        READFUNC(ElapsedMicroSecs,UNSIGNED32),
        READFUNC(StartTimeStamp,UNSIGNED8),
        TPVAR32(CurMSS,UNSIGNED32, mss_cache),
        READFUNC(PipeSize,UNSIGNED32),
        ESTATSVAR(MaxPipeSize,UNSIGNED32),
        READFUNC(SmoothedRTT,UNSIGNED32),
        READFUNC(CurRTO,UNSIGNED32),
        ESTATSVAR(CongSignals,UNSIGNED32),
        READFUNC(CurCwnd,UNSIGNED32),
        READFUNC(CurSsthresh,UNSIGNED32),
        ESTATSVAR(Timeouts,UNSIGNED32),
        TPVAR32(CurRwinSent,UNSIGNED32, rcv_wnd),
        ESTATSVAR(MaxRwinSent,UNSIGNED32),
        ESTATSVAR(ZeroRwinSent,UNSIGNED32),
        TPVAR32(CurRwinRcvd,UNSIGNED32, snd_wnd),
        ESTATSVAR(MaxRwinRcvd,UNSIGNED32),
        ESTATSVAR(ZeroRwinRcvd,UNSIGNED32),
        ESTATSVARN(SndLimTransRwin,UNSIGNED32,
                snd_lim_trans[TCP_ESTATS_SNDLIM_RWIN]),
        ESTATSVARN(SndLimTransCwnd,UNSIGNED32,
                snd_lim_trans[TCP_ESTATS_SNDLIM_CWND]),
        ESTATSVARN(SndLimTransSnd,UNSIGNED32,
                snd_lim_trans[TCP_ESTATS_SNDLIM_SENDER]),
        ESTATSVARN(SndLimTimeRwin,UNSIGNED32,
                snd_lim_time[TCP_ESTATS_SNDLIM_RWIN]),
        ESTATSVARN(SndLimTimeCwnd,UNSIGNED32,
                snd_lim_time[TCP_ESTATS_SNDLIM_CWND]),
        ESTATSVARN(SndLimTimeSnd,UNSIGNED32,
                snd_lim_time[TCP_ESTATS_SNDLIM_SENDER]),
};

struct tcp_estats_var path_var_array[] = {
        READFUNC(RetranThresh,UNSIGNED32),
        ESTATSVAR(NonRecovDAEpisodes,UNSIGNED32),
        ESTATSVAR(SumOctetsReordered,UNSIGNED32),
        ESTATSVAR(NonRecovDA,UNSIGNED32),
        ESTATSVAR(SampleRTT,UNSIGNED32),
        READFUNC(RTTVar,UNSIGNED32),
        ESTATSVAR(MaxRTT,UNSIGNED32),
        ESTATSVAR(MinRTT,UNSIGNED32),
        HCINF32(SumRTT,UNSIGNED32),
        ESTATSVARN(HCSumRTT,UNSIGNED64, SumRTT),
        ESTATSVAR(CountRTT,UNSIGNED32),
        ESTATSVAR(MaxRTO,UNSIGNED32),
        ESTATSVAR(MinRTO,UNSIGNED32),
        ESTATSVAR(IpTtl,UNSIGNED32),
        ESTATSVAR(IpTosIn,UNSIGNED8),
        READFUNC(IpTosOut,UNSIGNED8),
        ESTATSVAR(PreCongSumCwnd,UNSIGNED32),
        ESTATSVAR(PreCongSumRTT,UNSIGNED32),
        ESTATSVAR(PostCongSumRTT,UNSIGNED32),
        ESTATSVAR(PostCongCountRTT,UNSIGNED32),
        ESTATSVAR(ECNsignals,UNSIGNED32),
        ESTATSVAR(DupAckEpisodes,UNSIGNED32),
        READFUNC(RcvRTT,UNSIGNED32),
        ESTATSVAR(DupAcksOut,UNSIGNED32),
        ESTATSVAR(CERcvd,UNSIGNED32),
        ESTATSVAR(ECESent,UNSIGNED32),
};

struct tcp_estats_var stack_var_array[] = {
	ESTATSVAR(ActiveOpen,SIGNED32),
	READFUNC(MSSSent,UNSIGNED32),
	READFUNC(MSSRcvd,UNSIGNED32),
	READFUNC(WinScaleSent,SIGNED32),
	READFUNC(WinScaleRcvd,SIGNED32),
	READFUNC(TimeStamps,SIGNED32),
	READFUNC(ECN,SIGNED32),
	READFUNC(WillSendSACK,SIGNED32),
	READFUNC(WillUseSACK,SIGNED32),
	READFUNC(State,SIGNED32),
	READFUNC(Nagle,SIGNED32),
	ESTATSVAR(MaxSsCwnd,UNSIGNED32),
	ESTATSVAR(MaxCaCwnd,UNSIGNED32),
	ESTATSVAR(MaxSsthresh,UNSIGNED32),
	ESTATSVAR(MinSsthresh,UNSIGNED32),
	READFUNC(InRecovery,SIGNED32),
	ESTATSVAR(DupAcksIn,UNSIGNED32),
	ESTATSVAR(SpuriousFrDetected,UNSIGNED32),
	ESTATSVAR(SpuriousRtoDetected,UNSIGNED32),
	ESTATSVAR(SoftErrors,UNSIGNED32),
	ESTATSVAR(SoftErrorReason,SIGNED32),
	ESTATSVAR(SlowStart,UNSIGNED32),
	ESTATSVAR(CongAvoid,UNSIGNED32),
	ESTATSVAR(OtherReductions,UNSIGNED32),
	ESTATSVAR(CongOverCount,UNSIGNED32),
	ESTATSVAR(FastRetran,UNSIGNED32),
	ESTATSVAR(SubsequentTimeouts,UNSIGNED32),
	READFUNC(CurTimeoutCount,UNSIGNED32),
	ESTATSVAR(AbruptTimeouts,UNSIGNED32),
	ESTATSVAR(SACKsRcvd,UNSIGNED32),
	ESTATSVAR(SACKBlocksRcvd,UNSIGNED32),
	ESTATSVAR(SendStall,UNSIGNED32),
	ESTATSVAR(DSACKDups,UNSIGNED32),
	ESTATSVAR(MaxMSS,UNSIGNED32),
	ESTATSVAR(MinMSS,UNSIGNED32),
	ESTATSVAR(SndInitial,UNSIGNED32),
	ESTATSVAR(RecInitial,UNSIGNED32),
	ESTATSVAR(CurRetxQueue,UNSIGNED32),
	ESTATSVAR(MaxRetxQueue,UNSIGNED32),
	READFUNC(CurReasmQueue,UNSIGNED32),
	ESTATSVAR(MaxReasmQueue,UNSIGNED32),
};

struct tcp_estats_var app_var_array[] = {
        TPVAR32(SndUna,UNSIGNED32, snd_una),
        TPVAR32(SndNxt,UNSIGNED32, snd_nxt),
        ESTATSVAR(SndMax,UNSIGNED32),
        HCINF32(ThruOctetsAcked,UNSIGNED32),
        ESTATSVARN(HCThruOctetsAcked,UNSIGNED64, ThruOctetsAcked),
        TPVAR32(RcvNxt,UNSIGNED32, rcv_nxt),
        HCINF32(ThruOctetsReceived,UNSIGNED32),
        ESTATSVARN(HCThruOctetsReceived,UNSIGNED64, ThruOctetsReceived),
        READFUNC(CurAppWQueue,UNSIGNED32),
        ESTATSVAR(MaxAppWQueue,UNSIGNED32),
        READFUNC(CurAppRQueue,UNSIGNED32),
        ESTATSVAR(MaxAppRQueue,UNSIGNED32),
};

struct tcp_estats_var tune_var_array[] = {
        RWFUNC(LimCwnd,UNSIGNED32),
        READFUNC(LimSsthresh,UNSIGNED32),
        RWFUNC(LimRwin,UNSIGNED32),
        READFUNC(LimMSS,UNSIGNED32),
};

struct tcp_estats_var *estats_var_array[] = {
        perf_var_array,
        path_var_array,
        stack_var_array,
        app_var_array,
        tune_var_array
};
EXPORT_SYMBOL(estats_var_array);

void tcp_estats_find_var_by_iname(struct tcp_estats_var **var, const char *name)
{
	int i, j;

	*var = NULL;
	for (i = 0; i < MAX_TABLE; i++) {
		for (j = 0; j < max_index[i]; j++) {
			if (strnicmp(estats_var_array[i][j].name, name, 21) == 0) {
				*var = &estats_var_array[i][j];
				return;
			}
		}
	}
}
EXPORT_SYMBOL(tcp_estats_find_var_by_iname);

void tcp_estats_read_connection_spec(struct tcp_estats_connection_spec *spec,
        struct tcp_estats *stats)
{
        memcpy(&spec->rem_addr[0],
                (char *)stats + OFFSET_ST(RemAddress), 17);
        memcpy(&spec->local_addr[0],
                (char *)stats + OFFSET_ST(LocalAddress), 17);
        spec->rem_port = stats->estats_vars.RemPort;
        spec->local_port = stats->estats_vars.LocalPort;
}
EXPORT_SYMBOL(tcp_estats_read_connection_spec);


