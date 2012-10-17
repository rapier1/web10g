#ifndef _TCP_ESTATS_MIB_VAR_H_
#define _TCP_ESTATS_MIB_VAR_H_

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
        __u64 o;
        __u32 t;
        __s32 s;
        __u16 w;
        __u8  b;
};

enum MIB_TABLE {
        PERF_TABLE,
        PATH_TABLE,
        STACK_TABLE,
        APP_TABLE,
        TUNE_TABLE,
        __MAX_TABLE
};
#define MAX_TABLE __MAX_TABLE

extern int max_index[];

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

struct tcp_estats_connection_spec {
	uint8_t  rem_addr[17];
	uint8_t  local_addr[17];
	uint16_t rem_port;
	uint16_t local_port;
};

enum TCP_ESTATS_TYPE {
        TCP_ESTATS_UNSIGNED64,
        TCP_ESTATS_UNSIGNED32,
        TCP_ESTATS_SIGNED32,
        TCP_ESTATS_UNSIGNED16,
        TCP_ESTATS_UNSIGNED8,
};

struct tcp_estats_var;
typedef void (*estats_rwfunc_t)(void *buf, struct tcp_estats *stats,
                                struct tcp_estats_var *vp);

struct tcp_estats_var {
	char		*name;
	u32		type;

	estats_rwfunc_t	read;
	unsigned long	read_data;

	estats_rwfunc_t	write;
	unsigned long	write_data;
};

extern struct tcp_estats_var   perf_var_array[];
extern struct tcp_estats_var   path_var_array[];
extern struct tcp_estats_var  stack_var_array[];
extern struct tcp_estats_var    app_var_array[];
extern struct tcp_estats_var   tune_var_array[];

extern struct tcp_estats_var *estats_var_array[];

static inline int single_index(int inda, int indb)
{
	int ret = indb;
	int i;

	if (inda > 0) {
		for (i = 0; i < inda; i++) {
			ret += max_index[i];
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
	switch (vp->type) {
        case TCP_ESTATS_UNSIGNED64:
                return 8;
        case TCP_ESTATS_UNSIGNED32:
                return 4;
        case TCP_ESTATS_SIGNED32:
                return 4;
        case TCP_ESTATS_UNSIGNED16:
                return 2;
        case TCP_ESTATS_UNSIGNED8:
                return 1;
	}
	
	printk(KERN_WARNING
	       "TCP ESTATS: Adding variable of unknown type %d.\n", vp->type);
	return 0;
}

void tcp_estats_find_var_by_iname(struct tcp_estats_var **, const char *);

void tcp_estats_read_connection_spec(struct tcp_estats_connection_spec *,
        struct tcp_estats *);

typedef enum ESTATS_PERF_INDEX {
	SEGSOUT                 = 0,
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
	SNDLIMTRANSRWIN,
	SNDLIMTRANSCWND,
	SNDLIMTRANSSND,
	SNDLIMTIMERWIN,
	SNDLIMTIMECWND,
	SNDLIMTIMESND,
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
	CURRETXQUEUE,
	MAXRETXQUEUE,
	CURREASMQUEUE,
	MAXREASMQUEUE,
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
        LIMSSTHRESH,
        LIMRWIN,
        LIMMSS,
        __TUNE_INDEX_MAX
} ESTATS_TUNE_INDEX;
#define TUNE_INDEX_MAX __TUNE_INDEX_MAX

#define TOTAL_NUM_VARS PERF_INDEX_MAX+PATH_INDEX_MAX+STACK_INDEX_MAX+APP_INDEX_MAX+TUNE_INDEX_MAX

#endif /* _TCP_ESTATS_MIB_VAR_H_ */
