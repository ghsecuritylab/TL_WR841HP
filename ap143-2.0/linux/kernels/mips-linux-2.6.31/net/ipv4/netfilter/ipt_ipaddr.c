#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include "ipt_ipaddr.h"

#define NIPQUAD(addr) \ 
	((unsigned char*)&addr)[0],\
	((unsigned char*)&addr)[1],\
	((unsigned char*)&addr)[2],\
	((unsigned char*)&addr)[3]
	
#define NF_IP_LOCAL_IN 1
#define NF_IP_LOCAL_OUT 3

static int checkentry(const struct xt_mtchk_param *param)
{
	printk("entered ipaddr_checkentry\n");
	const struct ipt_ipaddr_info *info = param->matchinfo;
	unsigned int hook_mask = param->hook_mask;
	unsigned int matchsize = param->matchsize;
	char tablename[XT_TABLE_MAXNAMELEN];
	const struct ipt_ip *ip = (struct ipt_ip *)param->entryinfo;
	
	if (hook_mask & ~((1 << NF_IP_LOCAL_IN) | (1 << NF_IP_LOCAL_OUT)))
	{
		printk(KERN_WARNING "ipt_ipaddr: only valid with the FIlter table.\n");
		return 0;
	}
	
	if (matchsize != XT_ALIGN(sizeof(struct ipt_ipaddr_info))) {
		printk(KERN_ERROR "ipt_ipaddr:matchsize differ, you may forgotten to recompile me.\n");
		return 0;
	}
	
	strcpy(tablename, param->match->table);
	printk(KERN_INFO "ipt_ipaddr: Registered in the %s table, hook=%x, proto=%u\n",
				tablename, hook_mask, ip->proto);
				
	return 1;
}

static int ipt_match(const struct sk_buff *skb, struct xt_action_param *param)
{
	const struct net_device *in = param->in;
	const struct net_device *out = param->out;
	const struct ipt_ipaddr_info *info = param->matchinfo;
	
	struct iphdr *iph = ip_hdr(skb);
	printk("entered ipt_match!\n");
	printk(KERN_INFO "ipt_ipaddr: IN=%s OUT=%s TOS=0x%02X "
					"TTL=%x SRC=%u.%u.%u.%u DST=%u.%u.%u.%u "
					"ID=%u IPSRC=%u.%u.%u.%u IPDSR=%u.%u.%u.%u\n",
					in?in:"", out?out:"",iph->tos,
					iph->ttl, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
					ntohs(iph->id), NIPQUAD(info->ipaddr.src), NIPQUAD(info->ipaddr.dst)
		);
		
	if (info->flags & IPADDR_SRC)
	{
		if ((ntohl(iph->saddr) != ntohl(info->ipaddr.src)) ^ !!(info->flags & IPADDR_SRC_INV))
		{
			printk(KERN_INFO "src IP %u.%u.%u.%u is not matching %s.\n",
					NIPQUAD(info->ipaddr.src), info->flags & IPADDR_SRC_INV?"(INV)":"");
			return 0;
		}
	}

	if (info->flags & IPADDR_DST)
	{
		if ((ntohl(iph->daddr) != ntohl(info->ipaddr.dst)) ^ !!(info->flags & IPADDR_DST_INV))
		{
			printk(KERN_INFO "dst IP %u.%u.%u.%u is not matching %s.\n",
					NIPQUAD(info->ipaddr.dst), info->flags & IPADDR_DST_INV?"(INV)":"");
			return 0;
		}
	}
	
	return 1;
}

static struct ipt_match ipaddr_match = {
	.name = "ipaddr",
	.match = match,
	.checkentry = checkentry,
	.me = THIS_MODULE,
	.matchsize = XT_ALIGN(sizeof(struct ipt_ipaddr_info))
}

static int __init init(void)
{
	printk(KERN_INFO "ipt_ipaddr: init!\n");
	return xt_register_match(&ipaddr_match);
}

static void __exit fini(void)
{
	printk(KERN_INFO "ipt_ipaddr: exit!\n");
	return xt_unregister_match(&ipaddr_match);
}

module_init(init);
module_exit(fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Bouliane && Samule Jean");
MODULE_DESCRIPTION("netfilter module skeleton");