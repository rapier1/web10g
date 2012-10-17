#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/genetlink.h>
#include <net/genetlink.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/sock.h>

#include <net/tcp_estats_mib_var.h>
#include <net/tcp_estats_nl.h>


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
	                      .len  = 17 },
        [NEA_LOCAL_ADDR]  = { .type = NLA_BINARY,
	                      .len  = 17 },
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
};

static const struct nla_policy write_policy[NEA_WRITE_MAX+1] = {
	[NEA_WRITE_VAR]   = { .type = NLA_STRING },
	[NEA_WRITE_VAL]   = { .type = NLA_U32 },
};

static int
genl_list_conns(struct sk_buff *skb, struct genl_info *info)
{

	struct sk_buff *msg = NULL;
	void *hdr = NULL;
        struct nlattr *nest;
        struct tcp_estats *stats;
        struct tcp_estats_connection_spec spec;

        int tmpid = 0;

        while (1) {
                msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	        if (msg == NULL)
                        return -ENOMEM;

	        hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0, TCPE_CMD_LIST_CONNS);
	        if (hdr == NULL)
                        goto nlmsg_failure;

                spin_lock(&tcp_estats_idr_lock);
                stats = idr_get_next(&tcp_estats_idr, &tmpid);
                spin_unlock(&tcp_estats_idr_lock);

                if (stats == NULL)
                        break;

                tcp_estats_read_connection_spec(&spec, stats);

                nest = nla_nest_start(msg, NLE_ATTR_4TUPLE | NLA_F_NESTED);

                nla_put(msg, NEA_REM_ADDR, 17, &spec.rem_addr[0]);
                nla_put_u16(msg, NEA_REM_PORT, spec.rem_port);
                nla_put(msg, NEA_LOCAL_ADDR, 17, &spec.local_addr[0]);
                nla_put_u16(msg, NEA_LOCAL_PORT, spec.local_port);
                nla_put_u32(msg, NEA_CID, tmpid);

                nla_nest_end(msg, nest);

	        genlmsg_end(msg, hdr);
                genlmsg_unicast(sock_net(skb->sk), msg, info->snd_pid);

                tmpid = tmpid + 1;
        }

        return 0;

nlmsg_failure:
        printk(KERN_DEBUG "nlmsg_failure\n");

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

        struct tcp_estats *stats;
        int cid;
        int ret;
        int i, j, k;
        int tblnum;
        uint64_t mask;
        uint64_t masks[MAX_TABLE] = { DEFAULT_PERF_MASK, DEFAULT_PATH_MASK,
                DEFAULT_STACK_MASK, DEFAULT_APP_MASK, DEFAULT_TUNE_MASK };

        int index[MAX_TABLE] = { PERF_INDEX_MAX, PATH_INDEX_MAX,
                STACK_INDEX_MAX, APP_INDEX_MAX, TUNE_INDEX_MAX };
        int if_mask[] = { [0 ... MAX_TABLE-1] = 0 };
        static void *mask_jump[] = { &&mask_no, &&mask_yes };

	union estats_val val[TOTAL_NUM_VARS];

	const struct cred *cred = get_current_cred();

	if (!info->attrs[NLE_ATTR_4TUPLE])
		return -EINVAL;

        ret = nla_parse_nested(tb, NEA_4TUPLE_MAX, info->attrs[NLE_ATTR_4TUPLE], spec_policy);

	if (ret < 0)
		goto nla_parse_failure;

        if(!tb[NEA_CID])
                goto nla_parse_failure;

        cid = nla_get_u32(tb[NEA_CID]);

        if (cid < 1)
                goto nla_parse_failure;

        ret = nla_parse_nested(tb_mask, NEA_MASK_MAX,
                info->attrs[NLE_ATTR_MASK], mask_policy);

	if (ret < 0)
		goto nla_parse_failure;

        if (tb_mask[NEA_PERF_MASK]) {
                masks[PERF_TABLE] = nla_get_u64(tb_mask[NEA_PERF_MASK]);
                if_mask[PERF_TABLE] = 1;
        }
        if (tb_mask[NEA_PATH_MASK]) {
                masks[PATH_TABLE] = nla_get_u64(tb_mask[NEA_PATH_MASK]);
                if_mask[PATH_TABLE] = 1;
        }
        if (tb_mask[NEA_STACK_MASK]) {
                masks[STACK_TABLE] = nla_get_u64(tb_mask[NEA_STACK_MASK]);
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

        rcu_read_lock();
        stats = idr_find(&tcp_estats_idr, cid);
        rcu_read_unlock();
        if (stats == NULL)
                return -EINVAL;

        tcp_estats_use(stats);

	if (!(capable(CAP_SYS_ADMIN) ||
		(sock_i_uid(stats->estats_sk) == cred->uid))) {

		tcp_estats_unuse(stats);
		return -EACCES;
	}

        lock_sock(stats->estats_sk);

        for (tblnum = 0; tblnum < MAX_TABLE; tblnum++) {

                goto *mask_jump[if_mask[tblnum]];

              mask_yes:
                i = 0;
                mask = masks[tblnum];
                while ((i < index[tblnum]) && mask) {
                        j = __builtin_ctzl(mask);
                        mask = mask >> j;
                        i += j;

			k = single_index(tblnum, i);
                        read_tcp_estats(&(val[k]), stats, &(estats_var_array[tblnum][i]));

                        mask = mask >> 1;
                        i++;
                }
                
                continue;

              mask_no:
                for (i = 0; i < max_index[tblnum]; i++) {
			k = single_index(tblnum, i);
                        read_tcp_estats(&(val[k]), stats, &(estats_var_array[tblnum][i]));

                }
        }

        release_sock(stats->estats_sk);

        tcp_estats_unuse(stats);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &genl_estats_family, 0, TCPE_CMD_READ_VARS);
	if (hdr == NULL)
		goto nlmsg_failure;

        for (tblnum = 0; tblnum < MAX_TABLE; tblnum++) {
        
                switch (tblnum) {
                case PERF_TABLE:
                        nest[tblnum] = nla_nest_start(msg, NLE_ATTR_PERF | NLA_F_NESTED);
                        break;
                case PATH_TABLE:
                        nest[tblnum] = nla_nest_start(msg, NLE_ATTR_PATH | NLA_F_NESTED);
                        break;
                case STACK_TABLE:
                        nest[tblnum] = nla_nest_start(msg, NLE_ATTR_STACK | NLA_F_NESTED);
                        break;
                case APP_TABLE:
                        nest[tblnum] = nla_nest_start(msg, NLE_ATTR_APP | NLA_F_NESTED);
                        break;
                case TUNE_TABLE:
                        nest[tblnum] = nla_nest_start(msg, NLE_ATTR_TUNE | NLA_F_NESTED);
                        break;
                }
                if (!nest[tblnum])
                        goto nla_put_failure;

                i = 0;
                mask = masks[tblnum];
                while ((i < max_index[tblnum]) && mask) {
                        j = __builtin_ctzl(mask);
                        mask = mask >> j;
                        i += j;

			k = single_index(tblnum, i);

                        switch (estats_var_array[tblnum][i].type) {
        
                        case TCP_ESTATS_UNSIGNED64:
                                if (nla_put_u64(msg, i, val[k].o))
					goto nla_put_failure;
                                break;
                        case TCP_ESTATS_UNSIGNED32:
                                if (nla_put_u32(msg, i, val[k].t))
					goto nla_put_failure;
                        	break;
                        case TCP_ESTATS_SIGNED32:
                                if (nla_put_u32(msg, i, val[k].s))
					goto nla_put_failure;
                                break;
                        case TCP_ESTATS_UNSIGNED16:
                                if (nla_put_u16(msg, i, val[k].w))
					goto nla_put_failure;
                                break;
                        case TCP_ESTATS_UNSIGNED8:
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

        genlmsg_unicast(sock_net(skb->sk), msg, info->snd_pid);

	return 0;

nlmsg_failure:
        printk(KERN_DEBUG "nlmsg_failure\n");

nla_put_failure:
        printk(KERN_DEBUG "nla_put_failure\n");
	genlmsg_cancel(msg, hdr);
	kfree_skb(msg);
	return -ENOBUFS;

nla_parse_failure:
        printk(KERN_DEBUG "nla_parse_failure\n");

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

	const struct cred *cred = get_current_cred();

	if (!info->attrs[NLE_ATTR_4TUPLE])
		return -EINVAL;

        ret = nla_parse_nested(tb_tuple, NEA_4TUPLE_MAX, info->attrs[NLE_ATTR_4TUPLE], spec_policy);

	if (ret < 0)
		goto nla_parse_failure;

        if(!tb_tuple[NEA_CID])
                goto nla_parse_failure;

        cid = nla_get_u32(tb_tuple[NEA_CID]);

        if (cid < 1)
                goto nla_parse_failure;

	if (!info->attrs[NLE_ATTR_WRITE])
		return -EINVAL;

        ret = nla_parse_nested(tb_write, NEA_WRITE_MAX, info->attrs[NLE_ATTR_WRITE], write_policy);

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

	if (!(capable(CAP_SYS_ADMIN) ||
		(sock_i_uid(stats->estats_sk) == cred->uid))) {

		tcp_estats_unuse(stats);
		return -EACCES;
	}

        lock_sock(stats->estats_sk);
	ret = write_tcp_estats(&val, stats, var);
	release_sock(stats->estats_sk);

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
