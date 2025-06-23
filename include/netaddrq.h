/*
 * Netlink address quality rating tree builder
 *
 * Copyright (C) 2025 Stanislav Brabec <sbrabec@suse.com>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 *
 * This set of netlink callbacks kernel and creates
 * and/or maintains a linked list of requested type. Using callback fuctions
 * and custom data, it could be used for arbitraty purpose.
 *
 */

#ifndef UTIL_LINUX_NETADDRQ_H
#define UTIL_LINUX_NETADDRQ_H

#include "netlink.h"

/* Specific return code */
#define	UL_NL_IFACES_MAX	 64	/* ADDR: Too many interfaces */

/*
struct ul_netaddrq {
	ul_nl_addr *addr;
} ul_netaddrq;
*/

/* Network address "quality". Higher means worse. */
enum ul_netaddrq_ip_rating {
	IP_QUALITY_SCOPE_UNIVERSE,
	IP_QUALITY_SCOPE_SITE,
	IP_QUALITY_IFA_LOCAL,
	IP_QUALITY_F_TEMPORARY,
	IP_QUALITY_SCOPE_LINK,
	IP_QUALITY_BAD
};

/* Data structure in ul_nl_data */
struct ul_netaddrq_data {
	ul_nl_callback callback;	/* Function to process ul_netaddrq_data */
	void *callback_data;		/* Arbitrary data for callback */
	struct list_head ifaces;	/* The intefaces list */
	int nifaces;			/* interface count */
	bool overflow;			/* Too many interfaces? */
};
/* Macro casting generic ul_nl_data->data_addr to struct ul_netaddrq_data */
#define UL_NETADDRQ_DATA(nl) ((struct ul_netaddrq_data*)(nl->data_addr))

/* List item for for a particular address contains information for IP quality
 * evaluation and a copy of generic ul_nl_addr data */
struct ul_netaddrq_ip {
	struct list_head entry;
	enum ul_netaddrq_ip_rating quality;
	struct ul_nl_addr *addr;
};

/* List item for particular interface contains interface specific data and
 * heads of two lists, one per each address family */
struct ul_netaddrq_iface {
	struct list_head entry;
	uint32_t ifa_index;
	char *ifname;
	struct list_head ip_quality_list_4;
	struct list_head ip_quality_list_6;
/* FIXME: probably move to global part */
	bool ifaces_change_4;
	bool ifaces_change_6;
};

/* Initialize ul_nl_data for use with netlink-addr-quality
 * callback: Process the data after updating the tree. If NULL, it just
 *   updates the tree and everything has to be processed outside.
 */
int ul_netaddrq_init(struct ul_nl_data *nl, ul_nl_callback callback, void *data);

#endif /* UTIL_LINUX_NETADDRQ_H */
