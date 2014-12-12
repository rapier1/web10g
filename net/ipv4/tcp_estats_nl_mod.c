#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/genetlink.h>
#include <linux/jiffies.h>
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
#include <linux/time.h>
#endif
#include <net/genetlink.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/sock.h>

#include <net/tcp_estats_mib_var.h>
#include <net/tcp_estats_nl.h>

struct tcp_estats_connection_spec {
	uint32_t addr_type;
	uint8_t  rem_addr[16];
	uint8_t  local_addr[16];
	uint16_t rem_port;
	uint16_t local_port;
};

static struct genl_family genl_estats_family = {
	.id     = GENL_ID_GENERATE,
	.name   = "tcp_estats",
	.hdrsize = 0,
	.version = 1,
	.maxattr = NLE_ATTR_MAX,
};

static const struct genl_multicast_group genl_estats_mc[] = {
	{ .name   = "tcp_estats_mc", },
};

static const struct nla_policy spec_policy[NEA_4TUPLE_MAX+1] = {
	[NEA_REM_ADDR]		= { .type = NLA_BINARY,
				    .len  = 16 },
	[NEA_REM_PORT]		= { .type = NLA_U16 },
	[NEA_LOCAL_ADDR]	= { .type = NLA_BINARY,
				    .len  = 16 },
	[NEA_LOCAL_PORT]	= { .type = NLA_U16 },
	[NEA_ADDR_TYPE]		= { .type = NLA_U8 },
	[NEA_CID]		= { .type = NLA_U32 },
};

static const struct nla_policy mask_policy[NEA_MASK_MAX+1] = {
	[NEA_PERF_MASK]   = { .type = NLA_U64 },
	[NEA_PATH_MASK]   = { .type = NLA_U64 },
	[NEA_STACK_MASK]  = { .type = NLA_U64 },
	[NEA_APP_MASK]    = { .type = NLA_U64 },
	[NEA_TUNE_MASK]   = { .type = NLA_U64 },
	[NEA_EXTRAS_MASK] = { .type = NLA_U64 },
};

static const struct nla_policy write_policy[NEA_WRITE_MAX+1] = {
	[NEA_WRITE_VAR]   = { .type = NLA_STRING },
	[NEA_WRITE_VAL]   = { .type = NLA_U32 },
};

/* parser "helper" functions */
static int
tcp_estats_parse_cid(int *cid, const struct nlattr *nla) {
	int ret = 0;
	struct nlattr *tb[NEA_4TUPLE_MAX+1] = {};

	ret = nla_parse_nested(tb, NEA_4TUPLE_MAX, nla, spec_policy);

	if (ret < 0) {
		pr_debug("Failed to parse nested 4tuple\n");
		return -EINVAL;
	}

        if(!tb[NEA_CID]) {
		pr_debug("No CID found in table\n");
                return -EINVAL;
	}

        *cid = (int)nla_get_u32(tb[NEA_CID]);

	return ret;
}

static int
tcp_estats_parse_attr_mask(int if_mask[], uint64_t masks[],
			   const struct nlattr *nla) {
	int ret = 0;
	struct nlattr *tb_mask[NEA_MASK_MAX+1] = {};

	ret = nla_parse_nested(tb_mask, NEA_MASK_MAX,
		nla, mask_policy);

	if (ret < 0) {
		pr_debug("Failed to parse nested mask\n");
		return ret;
	}

	if (tb_mask[NEA_PERF_MASK]) {
		masks[PERF_TABLE] = nla_get_u64(tb_mask[NEA_PERF_MASK]);
		if_mask[PERF_TABLE] = 1;
	}
	if (tb_mask[NEA_PATH_MASK]) {
		masks[PATH_TABLE] = nla_get_u64(tb_mask[NEA_PATH_MASK]);
		if_mask[PATH_TABLE] = 1;
	}
	if (tb_mask[NEA_STACK_MASK]) {
		masks[STACK_TABLE] = nla_get_u64(
				tb_mask[NEA_STACK_MASK]);
		if_mask[STACK_TABLE] = 1;
	}
	if (tb_mask[NEA_APP_MASK]) {
		masks[APP_TABLE] = nla_get_u64(tb_mask[NEA_APP_MASK]);
		if_mask[APP_TABLE] = 1;
	}
	if (tb_mask[NEA_TUNE_MASK]) {
		masks[TUNE_TABLE] = nla_get_u64(tb_mask[NEA_TUNE_MASK]);
		if_mask[TUNE_TABLE] = 1;
	}
	if (tb_mask[NEA_EXTRAS_MASK]) {
		masks[EXTRAS_TABLE] = nla_get_u64(
				tb_mask[NEA_EXTRAS_MASK]);
		if_mask[EXTRAS_TABLE] = 1;
	}

	return ret;
}

static void tcp_estats_read_connection_spec(struct tcp_estats_connection_spec *spec,
				     struct tcp_estats *stats)
{
	struct tcp_estats_connection_table *connection_table =
		stats->tables.connection_table;
	if (connection_table == NULL) {
		printk(KERN_DEBUG
		       "Uninitialized connection_table in tcp_estats_read_connection_spec\n");
		return;
	}
	if (spec == NULL) {
		printk(KERN_ERR "NULL spec passed to tcp_estats_read_connection_spec\n");
		return;
	}
        memcpy(&spec->rem_addr[0], &connection_table->RemAddress,
	       sizeof(connection_table->RemAddress));
        spec->rem_port = connection_table->RemPort;
        memcpy(&spec->local_addr[0], &connection_table->LocalAddress,
	       sizeof(connection_table->LocalAddress));
        spec->local_port = connection_table->LocalPort;
	spec->addr_type = connection_table->AddressType;
}

static void
tcp_estats_find_var_by_iname(struct tcp_estats_var **var, const char *name)
{
	int i, j;

	*var = NULL;
	for (i = 0; i < MAX_TABLE; i++) {
		for (j = 0; j < estats_max_index[i]; j++) {
			if (strnicmp(estats_var_array[i][j].name,
				     name, 21) == 0) {
				*var = &estats_var_array[i][j];
				return;
			}
		}
	}
}

static int
tcp_estats_read_conn_vals(union estats_val *val, struct timeval *read_time,
			  bool sys_admin, kgid_t current_gid, kuid_t current_uid,
			  int if_mask[], uint64_t masks[],
			  struct tcp_estats *stats) {
	int tblnum;
	int i, j, k;
	uint64_t mask;
	struct sock *sk;

	lock_sock(stats->sk);
	sk = stats->sk;

	/* check access restrictions and read variables */
	if (!stats->ids) {
		read_lock_bh(&sk->sk_callback_lock);
		stats->uid = sk->sk_socket ? SOCK_INODE(sk->sk_socket)->i_uid :
				GLOBAL_ROOT_UID;
		stats->gid = sk->sk_socket ? SOCK_INODE(sk->sk_socket)->i_gid :
				GLOBAL_ROOT_GID;
		read_unlock_bh(&sk->sk_callback_lock);

		stats->ids = 1;
	}

	if (!(sys_admin ||
	      uid_eq(stats->uid, current_uid) ||
	      gid_eq(stats->gid, current_gid))) {
		release_sock(stats->sk);
		return -EACCES;
	}

	do_gettimeofday(read_time);

        for (tblnum = 0; tblnum < MAX_TABLE; tblnum++) {
		if (if_mask[tblnum]) {
			i = 0;
			mask = masks[tblnum];
			while ((i < estats_max_index[tblnum]) && mask) {
				j = __builtin_ctzl(mask);
				mask = mask >> j;
				i += j;

				k = single_index(tblnum, i);
				read_tcp_estats(&(val[k]), stats,
						&(estats_var_array[tblnum][i]));

				mask = mask >> 1;
				i++;
			}
		} else {
			for (i = 0; i < estats_max_index[tblnum]; i++) {
				k = single_index(tblnum, i);
				read_tcp_estats(&(val[k]), stats,
						&(estats_var_array[tblnum][i]));
			}
		}
        }

        release_sock(stats->sk);
	return 0;
}

/* functions for writing shared message fragments */
/*
  Fragment: [NLE_ATTR_TIME]
  Fragment Attributes:
    [NLE_ATTR_TIME
      [NEA_TIME_SEC{u32}]
      [NEA_TIME_USEC{u32}]
    ]
*/
static int
tcp_estats_put_time(struct sk_buff *msg, struct timeval *read_time) {
	int ret = 0;
	struct nlattr *nest = NULL;

	nest = nla_nest_start(msg, NLE_ATTR_TIME | NLA_F_NESTED);
	if (!nest)
		return -EMSGSIZE;

	ret = nla_put_u32(msg, NEA_TIME_SEC,
	       lower_32_bits(read_time->tv_sec));
	if (ret<0)
		return ret;
	ret = nla_put_u32(msg, NEA_TIME_USEC,
	       lower_32_bits(read_time->tv_usec));
	if (ret<0)
		return ret;
	nla_nest_end(msg, nest);
	return 0;
}

/*
  Fragment: [NLE_ATTR_4TUPLE]
  Fragment Attributes:
    [NLE_ATTR_4TUPLE
      [NEA_REM_ADDR{str}]
      [NEA_REM_PORT{u16}]
      [NEA_LOCAL_ADDR{str}]
      [NEA_LOCAL_PORT{u16}]
      [NEA_ADDR_TYPE{u8}]
      [NEA_CID{u32}]
    ]
*/
static int
tcp_estats_put_connection_spec(struct sk_buff *msg,
			       struct tcp_estats_connection_spec *spec,
			       int cid) {
	int ret = 0;
	struct nlattr *nest = NULL;
	nest = nla_nest_start(msg, NLE_ATTR_4TUPLE | NLA_F_NESTED);
	if (!nest)
		return -EMSGSIZE;

	ret = nla_put(msg, NEA_REM_ADDR, 16, &spec->rem_addr[0]);
	if (ret<0)
		return ret;
	ret = nla_put_u16(msg, NEA_REM_PORT, spec->rem_port);
	if (ret<0)
		return ret;
	ret = nla_put(msg, NEA_LOCAL_ADDR, 16, &spec->local_addr[0]);
	if (ret<0)
		return ret;
	ret = nla_put_u16(msg, NEA_LOCAL_PORT, spec->local_port);
	if (ret<0)
		return ret;
	ret = nla_put_u8(msg, NEA_ADDR_TYPE, spec->addr_type);
	if (ret<0)
		return ret;
	ret = nla_put_u32(msg, NEA_CID, cid);
	if (ret<0)
		return ret;

	nla_nest_end(msg, nest);
	return 0;
}

/*
  Fragment: [NLE_ATTR_<table>_VALS]
              for <table> in [PERF, PATH, STACK, APP, TUNE, EXTRAS]
  Fragment Attributes:
    [NLE_ATTR_<table>_VALS
      [<var_num>{**varies}]*
    ]
          for <table> in [PERF, PATH, STACK, APP, TUNE, EXTRAS]
*/
static int
tcp_estats_put_conn_vals(struct sk_buff *msg, union estats_val *val,
			 uint64_t masks[]) {
	struct nlattr *nest[MAX_TABLE];
	int i, j, k;
	int tblnum;
	uint64_t mask;

        for (tblnum = 0; tblnum < MAX_TABLE; tblnum++) {
                switch (tblnum) {
                case PERF_TABLE:
                        nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_PERF_VALS | NLA_F_NESTED);
                        break;
                case PATH_TABLE:
                        nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_PATH_VALS | NLA_F_NESTED);
                        break;
                case STACK_TABLE:
                        nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_STACK_VALS | NLA_F_NESTED);
                        break;
                case APP_TABLE:
                        nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_APP_VALS | NLA_F_NESTED);
                        break;
                case TUNE_TABLE:
                        nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_TUNE_VALS | NLA_F_NESTED);
                        break;
		case EXTRAS_TABLE:
			nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_EXTRAS_VALS | NLA_F_NESTED);
			break;
                }
                if (!nest[tblnum]) {
			pr_debug("Failed to nest table %d\n", tblnum);
                        return -EMSGSIZE;
		}

                i = 0;
                mask = masks[tblnum];
                while ((i < estats_max_index[tblnum]) && mask) {
                        j = __builtin_ctzl(mask);
                        mask = mask >> j;
                        i += j;

			k = single_index(tblnum, i);

                        switch (estats_var_array[tblnum][i].valtype) {

                        case TCP_ESTATS_VAL_UNSIGNED64:
                                if (nla_put_u64(msg, i, val[k].u_64))
					return -EMSGSIZE;
                                break;
                        case TCP_ESTATS_VAL_UNSIGNED32:
                                if (nla_put_u32(msg, i, val[k].u_32))
					return -EMSGSIZE;
				break;
                        case TCP_ESTATS_VAL_SIGNED32:
                                if (nla_put_u32(msg, i, val[k].s_32))
					return -EMSGSIZE;
                                break;
                        case TCP_ESTATS_VAL_UNSIGNED16:
                                if (nla_put_u16(msg, i, val[k].u_16))
					return -EMSGSIZE;
                                break;
                        case TCP_ESTATS_VAL_UNSIGNED8:
                                if (nla_put_u8(msg, i, val[k].u_8))
					return -EMSGSIZE;
                                break;
                        }

                        mask = mask >> 1;
                        i++;
                }
                nla_nest_end(msg, nest[tblnum]);
        }
	return 0;
}

/*
 Command: TCPE_CMD_INIT
  Lists all tables and variables in MIB
 Request args:
   <NONE>
 SINGLE RESPONSE
 Response Attributes:
   [NLE_ATTR_NUM_TABLES{u32}]
   [NLE_ATTR_NUM_VARS{u32}]
   [NLE_ATTR_<table>_VARS
     [NLE_ATTR_VAR
       [NEA_VAR_NAME{str}]
       [NEA_VAR_TYPE{u32}]
     ]*
   ] for <table> in [PERF, PATH, STACK, APP, TUNE, EXTRAS]
*/
static int
genl_get_mib(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg = NULL;
	void *hdr = NULL;
	struct nlattr *nest[MAX_TABLE];
	struct nlattr *entry_nest;
	int tblnum, i;

	if (skb == NULL) {
		pr_debug("invalid netlink socket\n");
		return -EINVAL;
	}

	/* NLMSG_DEFAULT_SIZE is not big enough on kernels where
	    page size is 4K */
	msg = nlmsg_new(2*NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		goto nlmsg_failure;

	hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0,
			  TCPE_CMD_INIT);
	if (hdr == NULL)
		goto nlmsg_failure;

	if (nla_put_u32(msg, NLE_ATTR_NUM_TABLES, MAX_TABLE))
		goto nla_put_failure;

	if (nla_put_u32(msg, NLE_ATTR_NUM_VARS, TOTAL_NUM_VARS))
		goto nla_put_failure;

	for (tblnum = 0; tblnum < MAX_TABLE; tblnum++) {
		switch (tblnum) {
		case PERF_TABLE:
			nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_PERF_VARS | NLA_F_NESTED);
			break;
		case PATH_TABLE:
			nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_PATH_VARS | NLA_F_NESTED);
			break;
		case STACK_TABLE:
			nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_STACK_VARS | NLA_F_NESTED);
			break;
		case APP_TABLE:
			nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_APP_VARS | NLA_F_NESTED);
			break;
		case TUNE_TABLE:
			nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_TUNE_VARS | NLA_F_NESTED);
			break;
		case EXTRAS_TABLE:
			nest[tblnum] = nla_nest_start(msg,
					NLE_ATTR_EXTRAS_VARS | NLA_F_NESTED);
			break;
		}
		if (!nest[tblnum])
			goto nla_put_failure;

		for (i=0; i < estats_max_index[tblnum]; i++) {
			entry_nest = nla_nest_start(msg,
					NLE_ATTR_VAR | NLA_F_NESTED);
			if (!entry_nest)
				goto nla_put_failure;

			if (nla_put_string(msg, NEA_VAR_NAME,
					estats_var_array[tblnum][i].name))
				goto nla_put_failure;

			if (nla_put_u32(msg, NEA_VAR_TYPE,
					estats_var_array[tblnum][i].vartype))
				goto nla_put_failure;

			nla_nest_end(msg, entry_nest);
		}

		nla_nest_end(msg, nest[tblnum]);
        }
	genlmsg_end(msg, hdr);

	genlmsg_unicast(sock_net(skb->sk), msg, info->snd_portid);

	return 0;

nlmsg_failure:
	pr_err("nlmsg_failure\n");

nla_put_failure:
	pr_err("nla_put_failure\n");
	genlmsg_cancel(msg, hdr);
	kfree_skb(msg);

	return -ENOBUFS;
}

/*
 Command: TCPE_CMD_LIST_CONNS
  Lists all connections, up to what will fit in reply skb.
 Request args:
   [NLE_ATTR_4TUPLE (optional)
     [NEA_CID] - (required) return only connections with id <cid> or higher
   ]
   [NLE_ATTR_TIMESTAMP] - (optional) absolute timestamp (in jiffies),
                                       for filtering active conns

 REPEATED RESPONSE
 Response Attributes:
   <Fragment: [NLE_ATTR_4TUPLE]>
*/
static int
genl_list_conns(struct sk_buff *skb, struct genl_info *info)
{
        struct sk_buff *msg = NULL;
	void *hdr = NULL;
	struct tcp_estats_connection_spec spec;

	unsigned int sk_buff_size = nlmsg_total_size(NLMSG_DEFAULT_SIZE);
	bool list_finished = false;
	/* variables for filtering inactive connections */
	bool filter_new = false;
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	ktime_t timestamp = { .tv64 = 0 };
#else
	unsigned long timestamp = 0;
#endif
	uint64_t timestamp_token = 0;
	/* initial estimate of connection message size */
	unsigned int conn_msg_size = NLMSG_HDRLEN;
	unsigned int old_skblen;

	struct tcp_estats *stats;
	int tmpid = 0;
	int cid;

	if (skb == NULL) {
		pr_debug("invalid netlink socket\n");
		return -EINVAL;
	}

	/* NLE_ATTR_4TUPLE is optional */
	if (info->attrs[NLE_ATTR_4TUPLE]) {
		if (tcp_estats_parse_cid(&tmpid,
					 info->attrs[NLE_ATTR_4TUPLE])<0)
			return -EINVAL;
		/* tpmid == 0 is fine - means "start from beginning" */
		if (tmpid<0) {
			pr_debug("Invalid starting CID (%d)\n",tmpid);
			return -EINVAL;
		}
	}
	/* optional - user can filter by connection ts >= timestamp */
	if (info->attrs[NLE_ATTR_TIMESTAMP]) {
		filter_new = true;
		timestamp_token = nla_get_u64(info->attrs[NLE_ATTR_TIMESTAMP]);
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
		timestamp.tv64 = (int64_t)timestamp_token;
#else
		timestamp = (unsigned long)timestamp_token;
#endif
	}

	msg = alloc_skb(sk_buff_size, GFP_KERNEL);
	if (msg == NULL) {
		pr_debug("failed to allocate memory for message\n");
		return -ENOMEM;
	}

	old_skblen = msg->len;
	while (1) {
		/* there are only 2 ways to break out of this loop:
			- run out of connections => free or send msg
			- run out of space => cancel last and free or send msg
		*/

		if (skb_tailroom(msg) < conn_msg_size)
			/* msg is full - no message was added, therefore
			    we may safely leave and either free or send msg */
			break;

		/* Get estats pointer from idr. */
		rcu_read_lock();  // read lock #1
		stats = idr_get_next(&tcp_estats_idr, &tmpid);
		/* preserve tmpid for put_connection_spec */
		cid = tmpid;
		/* increment tmpid so idr_get_next won't re-get this value */
		tmpid = tmpid + 1;
		if (stats == NULL) {
			/* Out of connections - we're done */
			list_finished = true;
			rcu_read_unlock(); // read lock #1 unlock
			break;
		}

		if (!tcp_estats_use_if_valid(stats)) {
			pr_debug("stats were already freed for %d\n", tmpid);
			rcu_read_unlock(); // read lock #1 unlock
			continue;
		}
		rcu_read_unlock(); //read lock #1 unlock

		/* skip this connection if older than timestamp filter.
			accessing stats without locking socket may be mild
			race condition... should be benign */
		if (filter_new &&
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
			(stats->current_ts.tv64 < timestamp.tv64)
#else
			time_before(stats->current_ts, timestamp)
#endif
		   )
		{
			tcp_estats_unuse(stats);
			continue;
		}

		/* Read the connection table into spec. */
		tcp_estats_read_connection_spec(&spec, stats);
		tcp_estats_unuse(stats);

		/* add a new message to batch msg */
		hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0,
				  TCPE_CMD_LIST_CONNS);
	        if (hdr == NULL) {
			/* msg is full - no message was added, therefore
			    we may safely leave and either free or send msg */
                        break;
		}

		if (tcp_estats_put_connection_spec(msg, &spec, cid) < 0) {
			/* msg is full - cancel this last hdr, then
			    we are safe to leave and either free or send msg */
			genlmsg_cancel(msg, hdr);
			break;
		}

		/* updates nlmsg_len only - can't fail */
		conn_msg_size = genlmsg_end(msg, hdr) - old_skblen;
		old_skblen = msg->len;
	}
	/* reached end of list, or out of room in socket buffer -
		free message if empty, otherwise, send socket buffer.
		(if message freed, receiver will still get ACK message) */
	if (msg->len==0) {
		kfree_skb(msg);
		/* an empty message is an error if the list is not done */
		if (!list_finished)
			return -ENOBUFS;
	} else {
		/* msg is attached to receiving socket
		   and freed during rcvfrom() */
		genlmsg_unicast(sock_net(skb->sk), msg, info->snd_portid);
	}
	return 0;
}

/*
 Command: TCPE_CMD_READ_ALL
  Posts connection variables for all connections,
                                 up to what will fit in reply skb.
 Request args:
   [NLE_ATTR_4TUPLE (optional)
     [NEA_CID] - (required) return only connections with id <cid> or higher
   ]
   [NLE_ATTR_MASK - (optional) table masks
      [NEA_PERF_MASK] (optional)
      [NEA_PATH_MASK] (optional)
      [NEA_STACK_MASK] (optional)
      [NEA_APP_MASK] (optional)
      [NEA_TUNE_MASK] (optional)
      [NEA_EXTRAS_MASK] (optional)
   ]
   [NLE_ATTR_TIMESTAMP] - (optional) absolute timestamp (in jiffies),
                                       for filtering active conns
 REPEATED RESPONSE
 Response Attributes:
   <Fragment: [NLE_ATTR_TIME]>
   <Fragment: [NLE_ATTR_4TUPLE]>
   <Fragment: [NLE_ATTR_<table>_VALS]>
*/
static int
genl_read_all(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg = NULL;
	void *hdr = NULL;
	struct tcp_estats_connection_spec spec;

	unsigned int sk_buff_size = nlmsg_total_size(NLMSG_DEFAULT_SIZE);
	bool list_finished = false;
	/* variables for filtering inactive connections */
	bool filter_new = false;
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	ktime_t timestamp;
#else
	unsigned long timestamp;
#endif
	uint64_t timestamp_token = 0;
	/* initial estimate of connection message size */
	unsigned int conn_msg_size = NLMSG_HDRLEN;
	unsigned int old_skblen;

	struct tcp_estats *stats;
	int tmpid=0;

	int ret;
	uint64_t masks[MAX_TABLE] = { DEFAULT_PERF_MASK, DEFAULT_PATH_MASK,
		DEFAULT_STACK_MASK, DEFAULT_APP_MASK, DEFAULT_TUNE_MASK,
		DEFAULT_EXTRAS_MASK };

	int if_mask[] = { [0 ... MAX_TABLE-1] = 0 };

	union estats_val *val = NULL;
	int numvars = TOTAL_NUM_VARS;
	size_t valarray_size = numvars*sizeof(union estats_val);

	struct timeval read_time;

	bool sys_admin = capable(CAP_SYS_ADMIN);
	/* ARGH!! this grabs a reference to current cred - must call put_cred */
	const struct cred *cred = get_current_cred();
	kgid_t current_gid = cred->gid;
	kuid_t current_uid = cred->uid;
	put_cred(cred);

	if (skb == NULL) {
		pr_debug("Invalid netlink socket\n");
		return -EINVAL;
	}

	/* NLE_ATTR_4TUPLE is optional */
	if (info->attrs[NLE_ATTR_4TUPLE]) {
		if (tcp_estats_parse_cid(&tmpid,
					 info->attrs[NLE_ATTR_4TUPLE])<0)
			return -EINVAL;
		/* tpmid == 0 is fine - means "start from beginning" */
		if (tmpid<0) {
			pr_debug("Invalid starting CID (%d)\n",tmpid);
			return -EINVAL;
		}
	}
	/* NLE_ATTR_MASK is optional */
	if (info->attrs[NLE_ATTR_MASK]) {
		if (tcp_estats_parse_attr_mask(if_mask, masks,
						 info->attrs[NLE_ATTR_MASK])<0)
			return -EINVAL;
	}
	/* optional - user can filter by connection ts >= timestamp */
	if (info->attrs[NLE_ATTR_TIMESTAMP]) {
		filter_new = true;
		timestamp_token = nla_get_u64(info->attrs[NLE_ATTR_TIMESTAMP]);
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
		timestamp.tv64 = (int64_t)timestamp_token;
#else
		timestamp = (unsigned long)timestamp_token;
#endif
	}

        msg = alloc_skb(sk_buff_size, GFP_KERNEL);
	if (msg == NULL) {
		pr_debug("failed to allocate memory for message\n");
		return -ENOMEM;
	}

	val = kmalloc(valarray_size, GFP_KERNEL);
	if (!val) {
		kfree_skb(msg);
		pr_debug("failed to allocate memory for var temp vals\n");
		return -ENOMEM;
	}

	old_skblen = msg->len;
	while (1) {
		if (skb_tailroom(msg) < conn_msg_size)
			/* msg is full - no message was added, therefore
			    we may safely leave and either free or send msg */
			break;
		/* get a reference to stats record for next cid */
		rcu_read_lock();  // read lock #1
		stats = idr_get_next(&tcp_estats_idr, &tmpid);
		/* increment tmpid so idr_get_next won't re-get this value */
		tmpid = tmpid + 1;

		if (stats == NULL) {
			/* Out of connections - we're done */
			list_finished = true;
			rcu_read_unlock(); // read lock #1 unlock
			break;
		}

		if (!tcp_estats_use_if_valid(stats)) {
			pr_debug("stats were already freed for %d\n", tmpid);
			rcu_read_unlock(); // read lock #1 unlock
			continue;
		}
		rcu_read_unlock(); // read lock #1 unlock

		/* skip this connection if older than timestamp filter.
			accessing stats without locking socket may be mild
			race condition... should be benign */
		if (filter_new &&
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
			(stats->current_ts.tv64 < timestamp.tv64)
#else
			time_before(stats->current_ts, timestamp)
#endif
		   )
		{
			tcp_estats_unuse(stats);
			continue;
		}

		/* read connection spec while holding ref to stats */
		tcp_estats_read_connection_spec(&spec, stats);

		/* check access restrictions and read variables while ref'd */
		ret = tcp_estats_read_conn_vals(val, &read_time,
						sys_admin,
						current_gid, current_uid,
						if_mask, masks, stats);
		/* release stats ref */
		tcp_estats_unuse(stats);

		/* if issue accessing vars, just skip response for this conn */
		if (ret<0)
			continue;

		/* write response for successful socket vars read */
		hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0,
		                  TCPE_CMD_READ_ALL);
		if (hdr == NULL) {
			/* msg is full - no message was added, therefore
			    we may safely leave and either free or send msg */
                        break;
		}

		if (tcp_estats_put_time(msg, &read_time) < 0) {
			/* msg is full - cancel this last hdr, then
			    we are safe to leave and either free or send msg */
			genlmsg_cancel(msg, hdr);
			break;
		}

		if (tcp_estats_put_connection_spec(msg, &spec, tmpid) < 0) {
			/* msg is full - cancel this last hdr, then
			    we are safe to leave and either free or send msg */
			genlmsg_cancel(msg, hdr);
			break;
		}

		if (tcp_estats_put_conn_vals(msg, val, masks)<0) {
			/* msg is full - cancel this last hdr, then
			    we are safe to leave and either free or send msg */
			genlmsg_cancel(msg, hdr);
			break;
		}

		conn_msg_size = genlmsg_end(msg, hdr) - old_skblen;
		old_skblen = msg->len;
	}

	kfree(val);
	/* reached end of list, or out of room in socket buffer -
		free message if empty, otherwise, send socket buffer.
		(if message freed, receiver will still get ACK message) */
	if (msg->len==0) {
		kfree_skb(msg);
		/* an empty message is an error if the list is not done */
		if (!list_finished)
			return -ENOBUFS;
	} else {
		/* msg is attached to receiving socket
		   and freed during rcvfrom() */
		ret = genlmsg_unicast(sock_net(skb->sk), msg, info->snd_portid);
	}
	return 0;
}

/*
 Command: TCPE_CMD_READ_VARS
  Posts connection variables for single connection.
 Request args:
   [NLE_ATTR_4TUPLE - (required)
     [NEA_CID] - (required) return variables for connection <cid>
   ]
   [NLE_ATTR_MASK - (optional) table masks
      [NEA_PERF_MASK] (optional)
      [NEA_PATH_MASK] (optional)
      [NEA_STACK_MASK] (optional)
      [NEA_APP_MASK] (optional)
      [NEA_TUNE_MASK] (optional)
      [NEA_EXTRAS_MASK] (optional)
   ]
 SINGLE RESPONSE
 Response Attributes:
   <Fragment: [NLE_ATTR_TIME]>
   <Fragment: [NLE_ATTR_4TUPLE]>
   <Fragment: [NLE_ATTR_<table>_VALS]>
*/
static int
genl_read_vars(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg = NULL;
	void *hdr = NULL;
	struct tcp_estats_connection_spec spec;

	struct tcp_estats *stats;
	int cid;
	int ret;
	uint64_t masks[MAX_TABLE] = { DEFAULT_PERF_MASK, DEFAULT_PATH_MASK,
		DEFAULT_STACK_MASK, DEFAULT_APP_MASK, DEFAULT_TUNE_MASK,
		DEFAULT_EXTRAS_MASK};

	int if_mask[] = { [0 ... MAX_TABLE-1] = 0 };

	union estats_val *val = NULL;
	int numvars = TOTAL_NUM_VARS;
	size_t valarray_size = numvars*sizeof(union estats_val);

	struct timeval read_time;

	/* could this be CAP_NET_ADMIN ? */
	bool sys_admin = capable(CAP_SYS_ADMIN);
	/* ARGH!! this grabs a reference to current cred - must call put_cred */
	const struct cred *cred = get_current_cred();
	kgid_t current_gid = cred->gid;
	kuid_t current_uid = cred->uid;
	put_cred(cred);

	if (skb == NULL) {
		pr_debug("Invalid netlink socket\n");
		return -EINVAL;
	}

	if (!info->attrs[NLE_ATTR_4TUPLE]) {
		pr_debug("Did not receive connection info\n");
		return -EINVAL;
	}

        if (tcp_estats_parse_cid(&cid, info->attrs[NLE_ATTR_4TUPLE])<0)
		goto nla_parse_failure;

        if (cid < 1) {
		pr_debug("Invalid CID %d found in table\n", cid);
                goto nla_parse_failure;
	}

	if (info->attrs[NLE_ATTR_MASK]) {
		if (tcp_estats_parse_attr_mask(if_mask, masks,
						 info->attrs[NLE_ATTR_MASK])<0)
			goto nla_parse_failure;
	}

	/* get a reference to stats record for this cid */
        rcu_read_lock();
        stats = idr_find(&tcp_estats_idr, cid);

	if (stats == NULL) {
		rcu_read_unlock();
		return -EINVAL;
	}

	if (!tcp_estats_use_if_valid(stats)) {
		rcu_read_unlock();
		return -EINVAL;
	}
        rcu_read_unlock();

	val = kmalloc(valarray_size, GFP_KERNEL);
	if (!val) {
		tcp_estats_unuse(stats);
		return -ENOMEM;
	}

	/* read connection spec while holding ref to stats */
	tcp_estats_read_connection_spec(&spec, stats);

	/* check access restrictions and read variables */
	ret = tcp_estats_read_conn_vals(val, &read_time,
					sys_admin, current_gid, current_uid,
					if_mask, masks, stats);
        tcp_estats_unuse(stats);

	if (ret<0) {
		kfree(val);
		return ret;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		goto nlmsg_failure;

	hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0,
			  TCPE_CMD_READ_VARS);
	if (hdr == NULL)
		goto nlmsg_failure;

	if (tcp_estats_put_time(msg, &read_time) < 0) {
		pr_debug("failed to write connection read time\n");
		goto nla_put_failure;
	}

	if (tcp_estats_put_connection_spec(msg, &spec, cid) < 0) {
		pr_debug("failed to write connection 4tuple\n");
		goto nla_put_failure;
	}

	if (tcp_estats_put_conn_vals(msg, val, masks)<0) {
		pr_debug("failed to write connection vals\n");
		goto nla_put_failure;
	}

	genlmsg_end(msg, hdr);

	/* netlink_unicast_kernel() will free msg. */
        genlmsg_unicast(sock_net(skb->sk), msg, info->snd_portid);

	kfree(val);

	return 0;

nlmsg_failure:
        pr_err("nlmsg_failure\n");

nla_put_failure:
        pr_err("nla_put_failure\n");
	genlmsg_cancel(msg, hdr);
	if (msg != NULL)
		kfree_skb(msg);
	kfree(val);

	return -ENOBUFS;

nla_parse_failure:
        pr_err("nla_parse_failure\n");
        return -EINVAL;
}

/*
 Command: TCPE_CMD_WRITE_VAR
  Modifies a variable for a single connection.
 Request args:
   [NLE_ATTR_4TUPLE - (required)
     [NEA_CID] - (required) modify variable for connection <cid>
   ]
   [NLE_ATTR_WRITE - (required) variable name and value to write
      [NEA_WRITE_VAR{str}] (required) variable name
      [NEA_WRITE_VAL{**various}] (required) variable value
   ]
 NO RESPONSE (ACK or ERROR only)
*/
static int
genl_write_var(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *tb_tuple[NEA_4TUPLE_MAX+1];
	struct nlattr *tb_write[NEA_WRITE_MAX+1];
	int ret;
	int cid = 0;
	char name[21];
	struct tcp_estats *stats;
	struct tcp_estats_var *var = NULL;
	uint32_t val;

	struct sock *sk;
	/* ARGH!! this grabs a reference to current cred - must call put_cred */
	const struct cred *cred = get_current_cred();
	kuid_t current_uid = cred->uid;
	put_cred(cred);

	if (!info->attrs[NLE_ATTR_4TUPLE])
		return -EINVAL;

        ret = nla_parse_nested(tb_tuple, NEA_4TUPLE_MAX,
			       info->attrs[NLE_ATTR_4TUPLE], spec_policy);

	if (ret < 0)
		goto nla_parse_failure;

        if(!tb_tuple[NEA_CID])
                goto nla_parse_failure;

        cid = nla_get_u32(tb_tuple[NEA_CID]);

        if (cid < 1)
                goto nla_parse_failure;

	if (!info->attrs[NLE_ATTR_WRITE])
		return -EINVAL;

        ret = nla_parse_nested(tb_write, NEA_WRITE_MAX,
			       info->attrs[NLE_ATTR_WRITE], write_policy);

	if (ret < 0)
		goto nla_parse_failure;

        if(!tb_write[NEA_WRITE_VAR])
                goto nla_parse_failure;

	nla_strlcpy(name, tb_write[NEA_WRITE_VAR], 21);

	tcp_estats_find_var_by_iname(&var, name);

	if (var == NULL) return -EINVAL;

	if (!tb_write[NEA_WRITE_VAL])
		goto nla_parse_failure;

	val = nla_get_u32(tb_write[NEA_WRITE_VAL]);

        rcu_read_lock();
        stats = idr_find(&tcp_estats_idr, cid);
        rcu_read_unlock();
        if (stats == NULL)
                return -EINVAL;

        tcp_estats_use(stats);

	sk = stats->sk;

	if (!stats->ids) {
		read_lock_bh(&sk->sk_callback_lock);
		stats->uid = sk->sk_socket ? SOCK_INODE(sk->sk_socket)->i_uid :
				GLOBAL_ROOT_UID;
		stats->gid = sk->sk_socket ? SOCK_INODE(sk->sk_socket)->i_gid :
				GLOBAL_ROOT_GID;
		read_unlock_bh(&sk->sk_callback_lock);

		stats->ids = 1;
	}

	if (!(capable(CAP_SYS_ADMIN) || uid_eq(stats->uid, current_uid))) {
		tcp_estats_unuse(stats);
		return -EACCES;
	}

        lock_sock(stats->sk);
	ret = write_tcp_estats(&val, stats, var);
	release_sock(stats->sk);

	tcp_estats_unuse(stats);

	if (ret == -1)
		return -EPERM;

	return 0;

nla_parse_failure:
	printk(KERN_DEBUG "nla_parse_failure\n");

	return -EINVAL;
}

/*
 Command: TCPE_CMD_TIMESTAMP
  return now-msecs_to_jiffies(delta)
 Request args:
   [NLE_ATTR_TIMESTAMP_DELTA{u32}] - timestamp delta (in ms) (default=0)
                                 (optional)
 SINGLE RESPONSE
 Response Attributes:
   [NLE_ATTR_TIMESTAMP{u64}] - absolute timestamp (jiffies) now - delta
*/
static int
genl_get_timestamp(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg = NULL;
	void *hdr = NULL;
	uint32_t ms_delta = 0;
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	ktime_t timestamp = ktime_get();
#else
	unsigned long timestamp = jiffies;
#endif
	uint64_t timestamp_token = 0;

	if (skb == NULL) {
		pr_debug("invalid netlink socket\n");
		return -EINVAL;
	}

	/* optional - ts = now - msec_to_jiffies(delta) */
	if (info->attrs[NLE_ATTR_TIMESTAMP_DELTA]) {
		ms_delta = nla_get_u32(info->attrs[NLE_ATTR_TIMESTAMP_DELTA]);
#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
		timestamp = ktime_sub_ns(timestamp, NSEC_PER_MSEC*ms_delta);
#else
		timestamp -= msecs_to_jiffies(ms_delta);
#endif
	}
	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		goto nlmsg_failure;

	hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0,
			  TCPE_CMD_TIMESTAMP);
	if (hdr == NULL)
		goto nlmsg_failure;

#ifdef CONFIG_TCP_ESTATS_STRICT_ELAPSEDTIME
	timestamp_token = (uint64_t)(timestamp.tv64);
#else
	timestamp_token = (uint64_t)timestamp;
#endif
	if (nla_put_u64(msg, NLE_ATTR_TIMESTAMP, timestamp_token))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_unicast(sock_net(skb->sk), msg, info->snd_portid);

	return 0;

nlmsg_failure:
	pr_err("nlmsg_failure\n");

nla_put_failure:
	pr_err("nla_put_failure\n");
	genlmsg_cancel(msg, hdr);
	kfree_skb(msg);

	return -ENOBUFS;
}

static const struct genl_ops genl_estats_ops[] = {
	{
		.cmd  = TCPE_CMD_INIT,
		.doit = genl_get_mib,
	},
        {
                .cmd  = TCPE_CMD_LIST_CONNS,
                .doit = genl_list_conns,
        },
        {
                .cmd  = TCPE_CMD_READ_ALL,
                .doit = genl_read_all,
        },
        {
                .cmd  = TCPE_CMD_READ_VARS,
                .doit = genl_read_vars,
        },
        {
                .cmd  = TCPE_CMD_WRITE_VAR,
                .doit = genl_write_var,
        },
        {
                .cmd  = TCPE_CMD_TIMESTAMP,
                .doit = genl_get_timestamp,
        },
};

static int __init tcp_estats_nl_init(void)
{
	int ret = -EINVAL;

	ret = genl_register_family_with_ops_groups(&genl_estats_family,
						genl_estats_ops, 
						genl_estats_mc);
	if (ret > 0) {
		return ret;
	}
        
        printk(KERN_INFO "tcp_estats netlink module initialized.\n");

        return ret;
}

void __exit tcp_estats_nl_exit(void)
{
        genl_unregister_family(&genl_estats_family);

        printk(KERN_INFO "tcp_estats netlink module exiting.\n");
}

module_init(tcp_estats_nl_init);
module_exit(tcp_estats_nl_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Web10g Dev Team");
MODULE_DESCRIPTION("Netlink Module for Extended TCP Instruments");
