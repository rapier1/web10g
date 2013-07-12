#include <linux/export.h>
#include <net/tcp_estats_mib_var.h>

#ifdef CONFIG_TCP_ESTATS

#define OFFSET_TP(field)	((unsigned long)(&(((struct tcp_sock *)NULL)->field)))

static char *get_stats_base(struct tcp_estats *stats,
			    struct tcp_estats_var *vp) {
	char* base = NULL;

	if (strcmp(vp->table, "perf_table") == 0)
		base = (char *) stats->tables.perf_table;
	else if (strcmp(vp->table, "path_table") == 0)
		base = (char *) stats->tables.path_table;
	else if (strcmp(vp->table, "stack_table") == 0)
		base = (char *) stats->tables.stack_table;
	else if (strcmp(vp->table, "app_table") == 0)
		base = (char *) stats->tables.app_table;
	/*else if (strcmp(vp->table, "tune_table") == 0)
		base = (char *) stats->tables.tune_table;*/
	else if (strcmp(vp->table, "extras_table") == 0)
	       base = (char *) stats->tables.extras_table;

	return base;
};

static void read_stats(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	char *base = get_stats_base(stats, vp);
	if (base != NULL)
		memcpy(buf, base + vp->read_data, tcp_estats_var_len(vp));
}

static void read_sk32(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)(stats->sk) + vp->read_data, 4);
}

static void read_inf32(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
        u64 val;
	char *base = get_stats_base(stats, vp);
	if (base != NULL) {
		memcpy(&val, base + vp->read_data, 8);
		val &= 0xffffffff;
		memcpy(buf, &val, 4);
	}
}

static void read_ElapsedSecs(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	ktime_t elapsed;
	u32 secs;

#ifndef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	stats->current_ts = ktime_get();
#endif
	elapsed = ktime_sub(stats->current_ts, stats->start_ts);
	secs = ktime_to_timeval(elapsed).tv_sec;

        memcpy(buf, &secs, 4);
}

static void read_ElapsedMicroSecs(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	ktime_t elapsed;
	u32 usecs;

#ifndef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	stats->current_ts = ktime_get();
#endif
	elapsed = ktime_sub(stats->current_ts, stats->start_ts);
	usecs = ktime_to_timeval(elapsed).tv_usec;

        memcpy(buf, &usecs, 4);
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
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = tcp_packets_in_flight(tp) * tp->mss_cache;
	memcpy(buf, &val, 4);
}

static void read_SmoothedRTT(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = (tp->srtt >> 3) * 1000 / HZ;
	memcpy(buf, &val, 4);
}

static void read_CurRTO(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->sk);
	u32 val = icsk->icsk_rto * 1000 / HZ;
	memcpy(buf, &val, 4);
}

static void read_CurCwnd(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = tp->snd_cwnd * tp->mss_cache;
	memcpy(buf, &val, 4);
}

static void read_CurSsthresh(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = tp->snd_ssthresh <= 0x7fffffff ?
	      tp->snd_ssthresh * tp->mss_cache : 0xffffffff;
	memcpy(buf, &val, 4);
}

static void read_RetranThresh(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = tp->reordering;
	memcpy(buf, &val, 4);
}

static void read_RTTVar(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = (tp->rttvar >> 2) * 1000 / HZ;
	memcpy(buf, &val, 4);
}

/* Note: this value returned is technically incorrect between a
 * setsockopt of IP_TOS, and when the next segment is sent. */
static void read_IpTosOut(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct inet_sock *inet = inet_sk(stats->sk);
	*(char *)buf = inet->tos;
}

static void read_RcvRTT(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = ((1000000*tp->rcv_rtt_est.rtt)/HZ)>>3;
	memcpy(buf, &val, 4);
}

static void read_MSSSent(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = tp->advmss;
	memcpy(buf, &val, 4);
}

static void read_MSSRcvd(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = tp->rx_opt.rec_mss;
	memcpy(buf, &val, 4);
}

/* Note: WinScaleSent and WinScaleRcvd are incorrectly
 * implemented for the case where we sent a scale option
 * but did not receive one. */
static void read_WinScaleSent(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	s32 val = tp->rx_opt.wscale_ok ? tp->rx_opt.rcv_wscale : -1;
	memcpy(buf, &val, 4);
}

static void read_WinScaleRcvd(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	s32 val = tp->rx_opt.wscale_ok ? tp->rx_opt.snd_wscale : -1;
	memcpy(buf, &val, 4);
}

/* Note: all these (TimeStamps, ECN, SACK, Nagle) are incorrect
 * if the sysctl values are changed during the connection. */
static void read_TimeStamps(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	s32 val = 1;

	if (!tp->rx_opt.tstamp_ok)
		val = sysctl_tcp_timestamps ? 3 : 2;
	memcpy(buf, &val, 4);
}

static void read_ECN(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct sock *sk = stats->sk;
	struct tcp_sock *tp = tcp_sk(sk);
	s32 val = 1;

	if ((tp->ecn_flags & TCP_ECN_OK) == 0)
		val = sock_net(sk)->ipv4.sysctl_tcp_ecn ? 3 : 2;
	memcpy(buf, &val, 4);
}

static void read_WillSendSACK(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	s32 val = 1;

	if (!tp->rx_opt.sack_ok)
		val = sysctl_tcp_sack ? 3 : 2;

	memcpy(buf, &val, 4);
}

#define read_WillUseSACK	read_WillSendSACK

static void read_State(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	/* A mapping from Linux to MIB state. */
	static char state_map[] = { 0,
				    TCP_ESTATS_STATE_ESTABLISHED,
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
	s32 val = state_map[stats->sk->sk_state];
	memcpy(buf, &val, 4);
}

static void read_Nagle(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	s32 val = tp->nonagle ? 2 : 1;
	memcpy(buf, &val, 4);
}

static void read_InRecovery(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->sk);
	s32 val = icsk->icsk_ca_state > TCP_CA_CWR ? 1 : 2;
	memcpy(buf, &val, 4);
}

static void read_CurTimeoutCount(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct inet_connection_sock *icsk = inet_csk(stats->sk);
	u32 val = icsk->icsk_retransmits;
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
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = ofo_qlen(tp);
	memcpy(buf, &val, 4);
}

static void read_CurAppWQueue(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	struct tcp_estats_app_table *app_table =
		tp->tcp_stats->tables.app_table;
	u32 val;

	if (app_table == NULL)
		return;
	val = tp->write_seq - app_table->SndMax;
	memcpy(buf, &val, 4);
}

static void read_CurAppRQueue(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
	u32 val = tp->rcv_nxt - tp->copied_seq;
	memcpy(buf, &val, 4);
}

static void read_LimCwnd(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	struct tcp_sock *tp = tcp_sk(stats->sk);
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
	struct tcp_sock *tp = tcp_sk(stats->sk);
	tp->snd_cwnd_clamp = min(*(u32 *) buf / tp->mss_cache, 65535U);
}

static void read_LimRwin(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)(stats->sk) + OFFSET_TP(window_clamp), 4);
}

static void write_LimRwin(void *buf, struct tcp_estats *stats,
	struct tcp_estats_var *vp)
{
        struct tcp_sock *tp = tcp_sk(stats->sk);
        u32 val;
        memcpy(&val, buf, 4);
        tp->window_clamp = min(val, 65535U << tp->rx_opt.rcv_wscale);
}

static void read_LimMSS(void *buf, struct tcp_estats *stats,
        struct tcp_estats_var *vp)
{
	memcpy(buf, (char *)(stats->sk) + OFFSET_TP(rx_opt.mss_clamp), 4);
}

#define OFFSET_ST(field, table)	\
	((unsigned long)(&(((struct tcp_estats_##table *)NULL)->field)))

#define ESTATSVAR(__name, __type, __table)  { \
	.name = #__name, \
	.type = TCP_ESTATS_##__type, \
	.table = #__table, \
	.read = read_stats, \
	.read_data = OFFSET_ST(__name, __table), \
	.write = NULL }
#define ESTATSVARN(__name, __type, __var, __table) { \
	.name = #__name, \
	.type = TCP_ESTATS_##__type, \
	.table = #__table, \
	.read = read_stats, \
	.read_data = OFFSET_ST(__var, __table), \
	.write = NULL }
#define TPVAR32(__name, __type, __var) { \
	.name = #__name, \
	.type = TCP_ESTATS_##__type, \
	.read = read_sk32, \
	.read_data = OFFSET_TP(__var), \
	.write = NULL }
#define HCINF32(__name, __type, __table) { \
	.name = #__name, \
	.type = TCP_ESTATS_##__type, \
	.table = #__table, \
	.read = read_inf32, \
	.read_data = OFFSET_ST(__name, __table), \
	.write = NULL }
#define READFUNC(__name, __type) { \
	.name = #__name, \
	.type = TCP_ESTATS_##__type, \
	.read = read_##__name, \
	.write = NULL }
#define RWFUNC(__name, __type) { \
	.name = #__name, \
	.type = TCP_ESTATS_##__type, \
	.read = read_##__name, \
	.write = write_##__name } 

int max_index[MAX_TABLE] = { PERF_INDEX_MAX, PATH_INDEX_MAX, STACK_INDEX_MAX,
			     APP_INDEX_MAX, TUNE_INDEX_MAX, EXTRAS_INDEX_MAX };
EXPORT_SYMBOL(max_index);

struct tcp_estats_var perf_var_array[] = {
        ESTATSVAR(SegsOut,UNSIGNED32, perf_table),
        ESTATSVAR(DataSegsOut,UNSIGNED32, perf_table),
        HCINF32(DataOctetsOut,UNSIGNED32, perf_table),
        ESTATSVARN(HCDataOctetsOut,UNSIGNED64, DataOctetsOut, perf_table),
        ESTATSVAR(SegsRetrans,UNSIGNED32, perf_table),
        ESTATSVAR(OctetsRetrans,UNSIGNED32, perf_table),
        ESTATSVAR(SegsIn,UNSIGNED32, perf_table),
        ESTATSVAR(DataSegsIn,UNSIGNED32, perf_table),
        HCINF32(DataOctetsIn,UNSIGNED32, perf_table),
        ESTATSVARN(HCDataOctetsIn,UNSIGNED64, DataOctetsIn, perf_table),
        READFUNC(ElapsedSecs,UNSIGNED32),
        READFUNC(ElapsedMicroSecs,UNSIGNED32),
        READFUNC(StartTimeStamp,UNSIGNED8),
        TPVAR32(CurMSS,UNSIGNED32, mss_cache),
        READFUNC(PipeSize,UNSIGNED32),
        ESTATSVAR(MaxPipeSize,UNSIGNED32, perf_table),
        READFUNC(SmoothedRTT,UNSIGNED32),
        READFUNC(CurRTO,UNSIGNED32),
        ESTATSVAR(CongSignals,UNSIGNED32, perf_table),
        READFUNC(CurCwnd,UNSIGNED32),
        READFUNC(CurSsthresh,UNSIGNED32),
        ESTATSVAR(Timeouts,UNSIGNED32, perf_table),
        TPVAR32(CurRwinSent,UNSIGNED32, rcv_wnd),
        ESTATSVAR(MaxRwinSent,UNSIGNED32, perf_table),
        ESTATSVAR(ZeroRwinSent,UNSIGNED32, perf_table),
        TPVAR32(CurRwinRcvd,UNSIGNED32, snd_wnd),
        ESTATSVAR(MaxRwinRcvd,UNSIGNED32, perf_table),
        ESTATSVAR(ZeroRwinRcvd,UNSIGNED32, perf_table),
        ESTATSVARN(SndLimTransRwin,UNSIGNED32,
                snd_lim_trans[TCP_ESTATS_SNDLIM_RWIN], perf_table),
        ESTATSVARN(SndLimTransCwnd,UNSIGNED32,
                snd_lim_trans[TCP_ESTATS_SNDLIM_CWND], perf_table),
        ESTATSVARN(SndLimTransSnd,UNSIGNED32,
                snd_lim_trans[TCP_ESTATS_SNDLIM_SENDER], perf_table),
        ESTATSVARN(SndLimTransTSODefer,UNSIGNED32,
                snd_lim_trans[TCP_ESTATS_SNDLIM_TSODEFER], perf_table),
        ESTATSVARN(SndLimTimeRwin,UNSIGNED32,
                snd_lim_time[TCP_ESTATS_SNDLIM_RWIN], perf_table),
        ESTATSVARN(SndLimTimeCwnd,UNSIGNED32,
                snd_lim_time[TCP_ESTATS_SNDLIM_CWND], perf_table),
        ESTATSVARN(SndLimTimeSnd,UNSIGNED32,
                snd_lim_time[TCP_ESTATS_SNDLIM_SENDER], perf_table),
        ESTATSVARN(SndLimTimeTSODefer,UNSIGNED32,
                snd_lim_time[TCP_ESTATS_SNDLIM_TSODEFER], perf_table),
};

struct tcp_estats_var path_var_array[] = {
        READFUNC(RetranThresh,UNSIGNED32),
        ESTATSVAR(NonRecovDAEpisodes,UNSIGNED32, path_table),
        ESTATSVAR(SumOctetsReordered,UNSIGNED32, path_table),
        ESTATSVAR(NonRecovDA,UNSIGNED32, path_table),
        ESTATSVAR(SampleRTT,UNSIGNED32, path_table),
        READFUNC(RTTVar,UNSIGNED32),
        ESTATSVAR(MaxRTT,UNSIGNED32, path_table),
        ESTATSVAR(MinRTT,UNSIGNED32, path_table),
        HCINF32(SumRTT,UNSIGNED32, path_table),
        ESTATSVARN(HCSumRTT,UNSIGNED64, SumRTT, path_table),
        ESTATSVAR(CountRTT,UNSIGNED32, path_table),
        ESTATSVAR(MaxRTO,UNSIGNED32, path_table),
        ESTATSVAR(MinRTO,UNSIGNED32, path_table),
        ESTATSVAR(IpTtl,UNSIGNED32, path_table),
        ESTATSVAR(IpTosIn,UNSIGNED8, path_table),
        READFUNC(IpTosOut,UNSIGNED8),
        ESTATSVAR(PreCongSumCwnd,UNSIGNED32, path_table),
        ESTATSVAR(PreCongSumRTT,UNSIGNED32, path_table),
        ESTATSVAR(PostCongSumRTT,UNSIGNED32, path_table),
        ESTATSVAR(PostCongCountRTT,UNSIGNED32, path_table),
        ESTATSVAR(ECNsignals,UNSIGNED32, path_table),
        ESTATSVAR(DupAckEpisodes,UNSIGNED32, path_table),
        READFUNC(RcvRTT,UNSIGNED32),
        ESTATSVAR(DupAcksOut,UNSIGNED32, path_table),
        ESTATSVAR(CERcvd,UNSIGNED32, path_table),
        ESTATSVAR(ECESent,UNSIGNED32, path_table),
};

struct tcp_estats_var stack_var_array[] = {
	ESTATSVAR(ActiveOpen,SIGNED32, stack_table),
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
	ESTATSVAR(MaxSsCwnd,UNSIGNED32, stack_table),
	ESTATSVAR(MaxCaCwnd,UNSIGNED32, stack_table),
	ESTATSVAR(MaxSsthresh,UNSIGNED32, stack_table),
	ESTATSVAR(MinSsthresh,UNSIGNED32, stack_table),
	READFUNC(InRecovery,SIGNED32),
	ESTATSVAR(DupAcksIn,UNSIGNED32, stack_table),
	ESTATSVAR(SpuriousFrDetected,UNSIGNED32, stack_table),
	ESTATSVAR(SpuriousRtoDetected,UNSIGNED32, stack_table),
	ESTATSVAR(SoftErrors,UNSIGNED32, stack_table),
	ESTATSVAR(SoftErrorReason,SIGNED32, stack_table),
	ESTATSVAR(SlowStart,UNSIGNED32, stack_table),
	ESTATSVAR(CongAvoid,UNSIGNED32, stack_table),
	ESTATSVAR(OtherReductions,UNSIGNED32, stack_table),
	ESTATSVAR(CongOverCount,UNSIGNED32, stack_table),
	ESTATSVAR(FastRetran,UNSIGNED32, stack_table),
	ESTATSVAR(SubsequentTimeouts,UNSIGNED32, stack_table),
	READFUNC(CurTimeoutCount,UNSIGNED32),
	ESTATSVAR(AbruptTimeouts,UNSIGNED32, stack_table),
	ESTATSVAR(SACKsRcvd,UNSIGNED32, stack_table),
	ESTATSVAR(SACKBlocksRcvd,UNSIGNED32, stack_table),
	ESTATSVAR(SendStall,UNSIGNED32, stack_table),
	ESTATSVAR(DSACKDups,UNSIGNED32, stack_table),
	ESTATSVAR(MaxMSS,UNSIGNED32, stack_table),
	ESTATSVAR(MinMSS,UNSIGNED32, stack_table),
	ESTATSVAR(SndInitial,UNSIGNED32, stack_table),
	ESTATSVAR(RecInitial,UNSIGNED32, stack_table),
	ESTATSVAR(CurRetxQueue,UNSIGNED32, stack_table),
	ESTATSVAR(MaxRetxQueue,UNSIGNED32, stack_table),
	READFUNC(CurReasmQueue,UNSIGNED32),
	ESTATSVAR(MaxReasmQueue,UNSIGNED32, stack_table),
	ESTATSVAR(EarlyRetrans,UNSIGNED32, stack_table),
	ESTATSVAR(EarlyRetransDelay,UNSIGNED32, stack_table),
};

struct tcp_estats_var app_var_array[] = {
        TPVAR32(SndUna,UNSIGNED32, snd_una),
        TPVAR32(SndNxt,UNSIGNED32, snd_nxt),
        ESTATSVAR(SndMax,UNSIGNED32, app_table),
        HCINF32(ThruOctetsAcked,UNSIGNED32, app_table),
        ESTATSVARN(HCThruOctetsAcked,UNSIGNED64, ThruOctetsAcked, app_table),
        TPVAR32(RcvNxt,UNSIGNED32, rcv_nxt),
        HCINF32(ThruOctetsReceived,UNSIGNED32, app_table),
        ESTATSVARN(HCThruOctetsReceived,UNSIGNED64, ThruOctetsReceived,
		   app_table),
        READFUNC(CurAppWQueue,UNSIGNED32),
        ESTATSVAR(MaxAppWQueue,UNSIGNED32, app_table),
        READFUNC(CurAppRQueue,UNSIGNED32),
        ESTATSVAR(MaxAppRQueue,UNSIGNED32, app_table),
};

struct tcp_estats_var tune_var_array[] = {
        RWFUNC(LimCwnd,UNSIGNED32),
        READFUNC(LimSsthresh,UNSIGNED32),
        RWFUNC(LimRwin,UNSIGNED32),
        READFUNC(LimMSS,UNSIGNED32),
};

struct tcp_estats_var extras_var_array[] = {
	ESTATSVAR(OtherReductionsCV, UNSIGNED32, extras_table),
	ESTATSVAR(OtherReductionsCM, UNSIGNED32, extras_table),
};

struct tcp_estats_var *estats_var_array[] = {
        perf_var_array,
        path_var_array,
        stack_var_array,
        app_var_array,
        tune_var_array,
	extras_var_array
};
EXPORT_SYMBOL(estats_var_array);

void tcp_estats_find_var_by_iname(struct tcp_estats_var **var, const char *name)
{
	int i, j;

	*var = NULL;
	for (i = 0; i < MAX_TABLE; i++) {
		for (j = 0; j < max_index[i]; j++) {
			if (strnicmp(estats_var_array[i][j].name,
				     name, 21) == 0) {
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
	struct tcp_estats_connection_table *connection_table =
		stats->tables.connection_table;
        memcpy(&spec->rem_addr[0], connection_table->RemAddress.data, 16);
        memcpy(&spec->local_addr[0], connection_table->LocalAddress.data, 16);
	spec->addr_type = connection_table->AddressType;
        spec->rem_port = connection_table->RemPort;
        spec->local_port = connection_table->LocalPort;
}
EXPORT_SYMBOL(tcp_estats_read_connection_spec);

#else
#endif /* CONFIG_TCP_ESTATS */
