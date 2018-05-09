#ifndef _IPT_IPADDR_H
#define _IPT_IPADDR_H

#define IPADDR_SRC 0x01	/* match source ip addr */
#define IPADDR_DST 0x02	/* match destination ip addr */

#define IPADDR_SRC_INV	0x10	/* Negate the condition */
#define IPADDR_DST_INV	0x20	/* Negate the condition */

struct ipt_ipaddr{
	u_int32_t src, dst;
};

struct ipt_ipaddr_info{
	struct ipt_ipaddr ipaddr;
	
	/* Flags from above */
	u_int8_t flags;
};

#endif