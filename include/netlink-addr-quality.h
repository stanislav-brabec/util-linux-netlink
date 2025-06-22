/*
 * Netlink address quality tree builder
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

#include "netlink.h"

/* Specific return code */
#define	UL_NL_IFACES_MAX	 64	/* ADDR: Too many interfaces */

/*
struct ul_nl_addr_quality {
	ul_nl_addr *addr;
} ul_nl_addr_quality;
*/

/* Network address "quality". Higher means worse. */
enum ip_quality_item_value {
	IP_QUALITY_SCOPE_UNIVERSE,
	IP_QUALITY_SCOPE_SITE,
	IP_QUALITY_IFA_LOCAL,
	IP_QUALITY_F_TEMPORARY,
	IP_QUALITY_SCOPE_LINK,
	IP_QUALITY_BAD
};

/* Data structure in ul_nl_data */
struct ul_nl_addr_quality_data {
	ul_nl_callback callback;	/* Function to process ul_nl_addr_quality_data */
	void *callback_data;		/* Arbitrary data for callback */
	struct list_head ifaces_list;	/* The intefaces list */
	int ifaces_count;		/* interface count */
	bool ifaces_skip_dump;		/* Too many interfaces? */
};
/* Macro casting generic ul_nl_data->data_addr to struct ul_nl_addrquality_data */
#define UL_NL_QUALITY_DATA(nl) ((struct ul_nl_addr_quality_data*)(nl->data_addr))

/* List item for for a particular address contains information for IP quality
 * evaluation and a copy of generic ul_nl_addr data */
struct ip_quality_item {
	struct list_head entry;
	enum ip_quality_item_value quality;
	struct ul_nl_addr *addr;
};

/* List item for particular interface contains interface specific data and
 * heads of two lists, one per each address family */
struct iface_quality_item {
	struct list_head entry;
	uint32_t ifa_index;
	char *ifname;
	struct list_head ip_quality_list_4;
	struct list_head ip_quality_list_6;
/* FIXME: probably move to global part */
	bool ifaces_list_change_4;
	bool ifaces_list_change_6;
};

/* Initialize ul_nl_data for use with netlink-addr-quality
 * callback: Process the data after updating the tree. If NULL, it just
 *   updates the tree and everything has to be processed outside.
 */
int ul_nl_addr_quality_init(struct ul_nl_data *nl, ul_nl_callback callback, void *data);
