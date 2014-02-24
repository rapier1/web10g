#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/genetlink.h>
#include <linux/time.h>
#include <net/genetlink.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/sock.h>

#include <net/tcp_estats_mib_var.h>
#include <net/tcp_estats_nl.h>

#ifdef CONFIG_TCP_ESTATS

static struct genl_family genl_estats_family = {
	.id     = GENL_ID_GENERATE,
	.name   = "tcp_estats",
	.hdrsize = 0,
	.version = 1,
	.maxattr = NLE_ATTR_MAX,
};

static struct genl_multicast_group genl_estats_mc = {
	.name   = "tcp_estats_mc",
};

static const struct nla_policy spec_policy[NEA_4TUPLE_MAX+1] = {
	[NEA_REM_ADDR]    = { .type = NLA_BINARY,
			      .len  = 16 },
	[NEA_LOCAL_ADDR]  = { .type = NLA_BINARY,
			      .len  = 16 },
	[NEA_ADDR_TYPE]	  = { .type = NLA_U8 },
	[NEA_REM_PORT]    = { .type = NLA_U16 },
	[NEA_LOCAL_PORT]  = { .type = NLA_U16 },
	[NEA_CID]         = { .type = NLA_U32 },
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

static int
genl_get_mib(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg = NULL;
	void *hdr = NULL;
	struct nlattr *nest[MAX_TABLE];
	struct nlattr *entry_nest;
	int tblnum, i;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
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
			entry_nest = nla_nest_start(msg, i | NLA_F_NESTED);

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

static int
genl_list_conns(struct sk_buff *skb, struct genl_info *info)
{
        struct tcp_estats_connection_spec spec;
        int tmpid = 0;

	if (skb == NULL) {
		pr_debug("invalid netlink socket");
		goto nlmsg_failure;
	}

        while (1) {
		struct sk_buff *msg = NULL;
		void *hdr = NULL;
		struct nlattr *nest = NULL;
		struct tcp_estats *stats = NULL;

		/* Get estats pointer from idr. */
		rcu_read_lock();
		stats = idr_get_next(&tcp_estats_idr, &tmpid);
		if (stats == NULL) {
			pr_debug("invalid stats pointer for %d\n", tmpid);
			rcu_read_unlock();
			break;
		}

		if (!tcp_estats_use_if_valid(stats)) {
			pr_debug("stats were already freed for %d\n", tmpid);
			rcu_read_unlock();
			continue;
		}
		rcu_read_unlock();

		/* Read the connection table into spec. */
                tcp_estats_read_connection_spec(&spec, stats);
		tcp_estats_unuse(stats);

		/* Build and send the connection spec netlink message. */
                msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	        if (msg == NULL) {
			pr_debug("failed to allocate memory for message.\n");
                        return -ENOMEM;
		}

	        hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0,
				  TCPE_CMD_LIST_CONNS);
	        if (hdr == NULL)
                        goto nlmsg_failure;

                nest = nla_nest_start(msg, NLE_ATTR_4TUPLE | NLA_F_NESTED);

                nla_put(msg, NEA_REM_ADDR, 16, &spec.rem_addr[0]);
                nla_put_u16(msg, NEA_REM_PORT, spec.rem_port);
                nla_put(msg, NEA_LOCAL_ADDR, 16, &spec.local_addr[0]);
                nla_put_u16(msg, NEA_LOCAL_PORT, spec.local_port);
		nla_put_u8(msg, NEA_ADDR_TYPE, spec.addr_type);
                nla_put_u32(msg, NEA_CID, tmpid);

                nla_nest_end(msg, nest);

	        genlmsg_end(msg, hdr);
                genlmsg_unicast(sock_net(skb->sk), msg, info->snd_portid);

                tmpid = tmpid + 1;
        }

        return 0;

nlmsg_failure:
        pr_err("nlmsg_failure\n");

        return -ENOBUFS;
}

static int
genl_read_vars(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg = NULL;
	void *hdr = NULL;
        struct nlattr *tb[NEA_4TUPLE_MAX+1];
        struct nlattr *tb_mask[NEA_MASK_MAX+1] = {};
        struct nlattr *nest[MAX_TABLE];
        struct nlattr *nest_time;
        struct nlattr *nest_spec;
        struct tcp_estats_connection_spec spec;

        struct tcp_estats *stats;
        int cid;
        int ret;
        int i, j, k;
        int tblnum;
        uint64_t mask;
        uint64_t masks[MAX_TABLE] = { DEFAULT_PERF_MASK, DEFAULT_PATH_MASK,
                DEFAULT_STACK_MASK, DEFAULT_APP_MASK, DEFAULT_TUNE_MASK,
		DEFAULT_EXTRAS_MASK };

        int if_mask[] = { [0 ... MAX_TABLE-1] = 0 };

	union estats_val *val = NULL;
	int numvars = TOTAL_NUM_VARS;
	size_t valarray_size = numvars*sizeof(union estats_val);

	struct timeval read_time;

	struct sock *sk;
	const struct cred *cred = get_current_cred();

	if (!info->attrs[NLE_ATTR_4TUPLE]) {
		pr_debug("Did not receive connection info\n");
		return -EINVAL;
	}

        ret = nla_parse_nested(tb, NEA_4TUPLE_MAX, info->attrs[NLE_ATTR_4TUPLE],
			       spec_policy);

	if (ret < 0) {
		pr_debug("Failed to parse nested 4tuple\n");
		goto nla_parse_failure;
	}

        if(!tb[NEA_CID]) {
		pr_debug("No CID found in table\n");
                goto nla_parse_failure;
	}

        cid = nla_get_u32(tb[NEA_CID]);

        if (cid < 1) {
		pr_debug("Invalid CID %d found in table\n", cid);
                goto nla_parse_failure;
	}

	if (info->attrs[NLE_ATTR_MASK]) {
		ret = nla_parse_nested(tb_mask, NEA_MASK_MAX,
			info->attrs[NLE_ATTR_MASK], mask_policy);

		if (ret < 0) {
			pr_debug("Failed to parse nested mask\n");
			goto nla_parse_failure;
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
	}

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

	lock_sock(stats->sk);
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

	if (!(capable(CAP_SYS_ADMIN) ||
	      (stats->uid == cred->uid) ||
	      (stats->gid == cred->gid))) {
		tcp_estats_unuse(stats);
		return -EACCES;
	}

	val = kmalloc(valarray_size, GFP_KERNEL);
	if (!val)
		return -ENOMEM;

	do_gettimeofday(&read_time);

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
        tcp_estats_unuse(stats);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		goto nlmsg_failure;

	hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0,
			  TCPE_CMD_READ_VARS);
	if (hdr == NULL)
		goto nlmsg_failure;

	nest_time = nla_nest_start(msg, NLE_ATTR_TIME | NLA_F_NESTED);
	if (nla_put_u32(msg, NEA_TIME_SEC,
			lower_32_bits(read_time.tv_sec)))
		goto nla_put_failure;
	if (nla_put_u32(msg, NEA_TIME_USEC,
			lower_32_bits(read_time.tv_usec)))
		goto nla_put_failure;
	nla_nest_end(msg, nest_time);

	tcp_estats_read_connection_spec(&spec, stats);

	nest_spec = nla_nest_start(msg, NLE_ATTR_4TUPLE | NLA_F_NESTED);

	nla_put(msg, NEA_REM_ADDR, 16, &spec.rem_addr[0]);
	nla_put_u16(msg, NEA_REM_PORT, spec.rem_port);
	nla_put(msg, NEA_LOCAL_ADDR, 16, &spec.local_addr[0]);
	nla_put_u16(msg, NEA_LOCAL_PORT, spec.local_port);
	nla_put_u8(msg, NEA_ADDR_TYPE, spec.addr_type);
	nla_put_u32(msg, NEA_CID, cid);

	nla_nest_end(msg, nest_spec);

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
                        goto nla_put_failure;
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
                                if (nla_put_u64(msg, i, val[k].o))
					goto nla_put_failure;
                                break;
                        case TCP_ESTATS_VAL_UNSIGNED32:
                                if (nla_put_u32(msg, i, val[k].t))
					goto nla_put_failure;
                        	break;
                        case TCP_ESTATS_VAL_SIGNED32:
                                if (nla_put_u32(msg, i, val[k].s))
					goto nla_put_failure;
                                break;
                        case TCP_ESTATS_VAL_UNSIGNED16:
                                if (nla_put_u16(msg, i, val[k].w))
					goto nla_put_failure;
                                break;
                        case TCP_ESTATS_VAL_UNSIGNED8:
                                if (nla_put_u8(msg, i, val[k].b))
					goto nla_put_failure;
                                break;
                        default:
                                break;
                        }
        
                        mask = mask >> 1;
                        i++;
                }
                nla_nest_end(msg, nest[tblnum]);
        }
	genlmsg_end(msg, hdr);

	if (skb == NULL) {
		pr_debug("Invalid netlink socket\n");
		goto nlmsg_failure;
	}

        genlmsg_unicast(sock_net(skb->sk), msg, info->snd_portid);

	kfree(val);

	return 0;

nlmsg_failure:
        pr_err("nlmsg_failure\n");

nla_put_failure:
        pr_err("nla_put_failure\n");
	genlmsg_cancel(msg, hdr);
	kfree_skb(msg);
	kfree(val);

	return -ENOBUFS;

nla_parse_failure:
        pr_err("nla_parse_failure\n");
        return -EINVAL;
}

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
	const struct cred *cred = get_current_cred();

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

	if (!(capable(CAP_SYS_ADMIN) || (stats->uid == cred->uid))) {
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

static struct genl_ops genl_estats_ops[] = {
	{
		.cmd  = TCPE_CMD_INIT,
		.doit = genl_get_mib,
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
                .cmd  = TCPE_CMD_LIST_CONNS,
                .doit = genl_list_conns,
        },
};

static int __init tcp_estats_nl_init(void)
{
	int ret = -EINVAL;
        int i;

	ret = genl_register_family(&genl_estats_family);
	if (ret < 0)
		goto err;

	for (i = 0; i < ARRAY_SIZE(genl_estats_ops); i++) {
		ret = genl_register_ops(&genl_estats_family,
					&genl_estats_ops[i]);
		if (ret < 0)
			goto err_unregister;
	}

	ret = genl_register_mc_group(&genl_estats_family, &genl_estats_mc);
	if (ret < 0)
		goto err_unregister;

        printk(KERN_INFO "tcp_estats netlink module initialized.\n");

        return ret;

err_unregister:
	genl_unregister_family(&genl_estats_family);
err:
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

#else
#endif /* CONFIG_TCP_ESTATS */
