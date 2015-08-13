#ifndef _TCP_ESTATS_MIB_VAR_H_
#define _TCP_ESTATS_MIB_VAR_H_

#ifndef CONFIG_TCP_ESTATS
#error This should not be included outside of CONFIG_TCP_ESTATS enabled builds.
#endif

#ifdef __KERNEL__
#include <net/sock.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/tcp_estats.h>
#else
#include <linux/types.h>
#include <inttypes.h>
#endif

union estats_val {
	__u64 u_64;
	__u32 u_32;
	__s32 s_32;
	__u16 u_16;
	__u8  u_8;
};

enum MIB_TABLE {
	PERF_TABLE,
	PATH_TABLE,
	STACK_TABLE,
	APP_TABLE,
	TUNE_TABLE,
	EXTRAS_TABLE,
	__MAX_TABLE
};
#define MAX_TABLE __MAX_TABLE

extern int estats_max_index[]; /* MAX_TABLE */

/* The official MIB states are enumerated differently than Linux's. */
enum tcp_estats_states {
	TCP_ESTATS_STATE_CLOSED = 1,
	TCP_ESTATS_STATE_LISTEN,
	TCP_ESTATS_STATE_SYNSENT,
	TCP_ESTATS_STATE_SYNRECEIVED,
	TCP_ESTATS_STATE_ESTABLISHED,
	TCP_ESTATS_STATE_FINWAIT1,
	TCP_ESTATS_STATE_FINWAIT2,
	TCP_ESTATS_STATE_CLOSEWAIT,
	TCP_ESTATS_STATE_LASTACK,
	TCP_ESTATS_STATE_CLOSING,
	TCP_ESTATS_STATE_TIMEWAIT,
	TCP_ESTATS_STATE_DELETECB
};

typedef enum TCP_ESTATS_VAR_TYPE {
	TCP_ESTATS_VAR_INTEGER,
	TCP_ESTATS_VAR_INTEGER32,
	TCP_ESTATS_VAR_COUNTER32,
	TCP_ESTATS_VAR_GAUGE32,
	TCP_ESTATS_VAR_UNSIGNED32,
	TCP_ESTATS_VAR_COUNTER64,
	TCP_ESTATS_VAR_DATEANDTIME,
	TCP_ESTATS_VAR_TIMESTAMP,
	TCP_ESTATS_VAR_TRUTHVALUE,
	TCP_ESTATS_VAR_OCTET,
} tcp_estats_vartype_t;

typedef enum TCP_ESTATS_VAL_TYPE {
        TCP_ESTATS_VAL_UNSIGNED64,
        TCP_ESTATS_VAL_UNSIGNED32,
        TCP_ESTATS_VAL_SIGNED32,
        TCP_ESTATS_VAL_UNSIGNED16,
        TCP_ESTATS_VAL_UNSIGNED8,
} tcp_estats_valtype_t;

struct tcp_estats_var;
typedef void (*estats_rwfunc_t)(void *buf, struct tcp_estats *stats,
				struct tcp_estats_var *vp);

struct tcp_estats_var {
	char			*name;
	tcp_estats_vartype_t	vartype;
	tcp_estats_valtype_t	valtype;
	char			*table;

	estats_rwfunc_t		read;
	unsigned long		read_data;

	estats_rwfunc_t		write;
	unsigned long		write_data;
};

extern struct tcp_estats_var   perf_var_array[];
extern struct tcp_estats_var   path_var_array[];
extern struct tcp_estats_var  stack_var_array[];
extern struct tcp_estats_var    app_var_array[];
extern struct tcp_estats_var   tune_var_array[];
extern struct tcp_estats_var extras_var_array[];

extern struct tcp_estats_var *estats_var_array[];

static inline int single_index(int index_a, int index_b)
{
	int ret = index_b;
	int i;

	if (index_a > 0) {
		for (i = 0; i < index_a; i++) {
			ret += estats_max_index[i];
		}
	}
	return ret;
}

static inline void read_tcp_estats(void *buf, struct tcp_estats *stats,
				   struct tcp_estats_var *vp)
{
	vp->read(buf, stats, vp);
}

static inline int write_tcp_estats(void *buf, struct tcp_estats *stats,
				   struct tcp_estats_var *vp)
{
	if (vp->write != NULL) {
		vp->write(buf, stats, vp);
		return 0;
	}
	return -1;
}

static inline int tcp_estats_var_len(struct tcp_estats_var *vp)
{
	switch (vp->valtype) {
	case TCP_ESTATS_VAL_UNSIGNED64:
		return sizeof(u64);
	case TCP_ESTATS_VAL_UNSIGNED32:
 		return sizeof(u32);
	case TCP_ESTATS_VAL_SIGNED32:
		return sizeof(s32);
	case TCP_ESTATS_VAL_UNSIGNED16:
		return sizeof(u16);
	case TCP_ESTATS_VAL_UNSIGNED8:
		return sizeof(u8);
	}

	printk(KERN_WARNING
	       "TCP ESTATS: Adding variable of unknown type %d.\n", vp->valtype);
	return 0;
}

typedef enum ESTATS_PERF_INDEX {
	SEGSOUT			= 0,
	DATASEGSOUT,
	DATAOCTETSOUT,
	HCDATAOCTETSOUT,
	SEGSRETRANS,
	OCTETSRETRANS,
	SEGSIN,
	DATASEGSIN,
	DATAOCTETSIN,
	HCDATAOCTETSIN,
	ELAPSEDSECS,
	ELAPSEDMICROSECS,
	STARTTIMESTAMP,
	CURMSS,
	PIPESIZE,
	MAXPIPESIZE,
	SMOOTHEDRTT,
	CURRTO,
	CONGSIGNALS,
	CURCWND,
	CURSSTHRESH,
	TIMEOUTS,
	CURRWINSENT,
	MAXRWINSENT,
	ZERORWINSENT,
	CURRWINRCVD,
	MAXRWINRCVD,
	ZERORWINRCVD,
	SNDLIMTRANSSND,
	SNDLIMTRANSCWND,
	SNDLIMTRANSRWIN,
	SNDLIMTRANSSTARTUP,
	SNDLIMTRANSTSODEFER,
	SNDLIMTRANSPACE,
	SNDLIMTIMESND,
	SNDLIMTIMECWND,
	SNDLIMTIMERWIN,
	SNDLIMTIMESTARTUP,
	SNDLIMTIMETSODEFER,
	SNDLIMTIMEPACE,
	__PERF_INDEX_MAX
} ESTATS_PERF_INDEX;
#define PERF_INDEX_MAX __PERF_INDEX_MAX

typedef enum ESTATS_PATH_INDEX {
	RETRANTHRESH,
	NONRECOVDAEPISODES,
	SUMOCTETSREORDERED,
	NONRECOVDA,
	SAMPLERTT,
	RTTVAR,
	MAXRTT,
	MINRTT,
	SUMRTT,
	HCSUMRTT,
	COUNTRTT,
	MAXRTO,
	MINRTO,
	IPTTL,
	IPTOSIN,
	IPTOSOUT,
	PRECONGSUMCWND,
	PRECONGSUMRTT,
	POSTCONGSUMRTT,
	POSTCONGCOUNTRTT,
	ECNSIGNALS,
	DUPACKEPISODES,
	RCVRTT,
	DUPACKSOUT,
	CERCVD,
	ECESENT,
	__PATH_INDEX_MAX
} ESTATS_PATH_INDEX;
#define PATH_INDEX_MAX __PATH_INDEX_MAX

typedef enum ESTATS_STACK_INDEX {
	ACTIVEOPEN,
	MSSSENT,
	MSSRCVD, 
	WINSCALESENT,
	WINSCALERCVD,
	TIMESTAMPS, 
	ECN,
	WILLSENDSACK, 
	WILLUSESACK, 
	STATE,
	NAGLE,
	MAXSSCWND,
	MAXCACWND,
	MAXSSTHRESH,
	MINSSTHRESH,
	INRECOVERY,
	DUPACKSIN,
	SPURIOUSFRDETECTED,
	SPURIOUSRTODETECTED,
	SOFTERRORS,
	SOFTERRORREASON,
	SLOWSTART,
	CONGAVOID,
	OTHERREDUCTIONS,
	CONGOVERCOUNT,
	FASTRETRAN,
	SUBSEQUENTTIMEOUTS,
	CURTIMEOUTCOUNT,
	ABRUPTTIMEOUTS,
	SACKSRCVD,
	SACKBLOCKSRCVD,
	SENDSTALL,
	DSACKDUPS,
	MAXMSS,
	MINMSS,
	SNDINITIAL,
	RECINITIAL,
/*	CURRETXQUEUE, */
/*	MAXRETXQUEUE, */
	CURREASMQUEUE,
	MAXREASMQUEUE,
	EARLYRETRANS,
	EARLYRETRANSDELAY,
	__STACK_INDEX_MAX
} ESTATS_STACK_INDEX;
#define STACK_INDEX_MAX __STACK_INDEX_MAX

typedef enum ESTATS_APP_INDEX {
	SNDUNA,
	SNDNXT,
	SNDMAX,
	THRUOCTETSACKED,
	HCTHRUOCTETSACKED,
	RCVNXT,
	THRUOCTETSRECEIVED,
	HCTHRUOCTETSRECEIVED,
	CURAPPWQUEUE,
	MAXAPPWQUEUE,
	CURAPPRQUEUE,
	MAXAPPRQUEUE,
	__APP_INDEX_MAX
} ESTATS_APP_INDEX;
#define APP_INDEX_MAX __APP_INDEX_MAX

typedef enum ESTATS_TUNE_INDEX {
	LIMCWND,
	LIMRWIN,
	LIMMSS,
	__TUNE_INDEX_MAX
} ESTATS_TUNE_INDEX;
#define TUNE_INDEX_MAX __TUNE_INDEX_MAX

typedef enum ESTATS_EXTRAS_INDEX {
/*	OTHERREDUCTIONSCV,*/
	OTHERREDUCTIONSCM,
	PRIORITY,
	__EXTRAS_INDEX_MAX
} ESTATS_EXTRAS_INDEX;
#define EXTRAS_INDEX_MAX __EXTRAS_INDEX_MAX

#define TOTAL_NUM_VARS ((PERF_INDEX_MAX) + \
			(PATH_INDEX_MAX) + \
			(STACK_INDEX_MAX) + \
			(APP_INDEX_MAX) + \
			(TUNE_INDEX_MAX) + \
			(EXTRAS_INDEX_MAX))

#if BITS_PER_LONG == 64
#define DEFAULT_PERF_MASK	((1UL << (PERF_INDEX_MAX))-1)
#define DEFAULT_PATH_MASK	((1UL << (PATH_INDEX_MAX))-1)
#define DEFAULT_STACK_MASK	((1UL << (STACK_INDEX_MAX))-1)
#define DEFAULT_APP_MASK	((1UL << (APP_INDEX_MAX))-1)
#define DEFAULT_TUNE_MASK	((1UL << (TUNE_INDEX_MAX))-1)
#define DEFAULT_EXTRAS_MASK	((1UL << (EXTRAS_INDEX_MAX))-1)
#else
#define DEFAULT_PERF_MASK	((1ULL << (PERF_INDEX_MAX))-1)
#define DEFAULT_PATH_MASK	((1ULL << (PATH_INDEX_MAX))-1)
#define DEFAULT_STACK_MASK	((1ULL << (STACK_INDEX_MAX))-1)
#define DEFAULT_APP_MASK	((1ULL << (APP_INDEX_MAX))-1)
#define DEFAULT_TUNE_MASK	((1ULL << (TUNE_INDEX_MAX))-1)
#define DEFAULT_EXTRAS_MASK	((1ULL << (EXTRAS_INDEX_MAX))-1)
#endif

#endif /* _TCP_ESTATS_MIB_VAR_H_ */
