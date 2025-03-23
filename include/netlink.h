/*
 * Netlink message processing
 *
 * Copyright (C) 2025 Stanislav Brabec <sbrabec@suse.com>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 *
 * This set of functions processes netlink messages from kernel and creates
 * and/or maintains a linked list of requested type. Using callback fuctions
 * and custom data, it could be used for arbitraty purpose.
 *
 */
 
#ifndef UTIL_LINUX_NETLINK
#define UTIL_LINUX_NETLINK

#include <stddef.h>
#include <stdbool.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "list.h"

typedef struct ul_netlink_data ul_netlink_data;
typedef struct ul_netlink_callback_data ul_netlink_callback_data;

/* Return codes */
typedef enum ul_netlink_rc {
	UL_NETLINK_OK,		/* no error */
	UL_NETLINK_ERROR,	/* generic error */
	UL_NETLINK_DONE,	/* processing reached NLMSG_DONE (for
				 * ul_netlink_dump_request() */
	UL_NETLINK_WOULDBLOCK,	/* no data are ready (for asynchronous mode) */
	UL_NETLINK_ABORT	/* immediate termination requested (by callback) */
} ul_netlink_rc;

/* The callback of the netlink message header.
 * Return code: Normally returns UL_NETLINK_OK. In all other cases,
 *   ul_netlink_process() immediately exits with an error. A special return
 *   code UL_NETLINK_ABORT is reserved for intended aborting of further
 *   processing that does not mean an error.
 */
typedef ul_netlink_rc (*ul_netlink_callback)(ul_netlink_data *ulnetlink, struct nlmsghdr *nh, ul_netlink_callback_data *callbackdata);

typedef struct ul_netlink_callback_data {
	struct list_head list_item;
	ul_netlink_callback call;		/* arbitrary callback for each message,
						 * defined by the caller */
	void *data;				/* arbitrary custom data stored by the caller */
} ul_netlink_callback_data;

typedef struct ul_netlink_data {
	struct list_head callbacks;	/* First callback data */
	int fd;				/* netlink socket FD */
} ul_netlink_data;

/* Initialize ul_netlink_data */
void ul_netlink_init(ul_netlink_data *ulnetlink);

/* Adds a callback to the chain of callbacks
 * ul_netlink_callback: Function to call for each message.
 * callbackdata: This implementation callback.__attribute__((__unused__))
 */
void ul_netlink_callback_add(ul_netlink_data *ulnetlink, ul_netlink_callback_data *callbackdata);

/* Open a netlink connection.
 * nl_groups: Applies for monitoring. In case of ul_netlink_dump_request(),
 *   use its argument to select one.
 */
ul_netlink_rc ul_netlink_open(ul_netlink_data *ulnetlink, uint32_t nl_groups);

/* Close a netlink connection. */
ul_netlink_rc ul_netlink_close(ul_netlink_data *ulnetlink);

/* Synchronously sends dump request of a selected nlmsg_type. It does not
 * perform any further actions. The result is returned through the callback
 * mechanism.
 * Under normal conditions, use
 * ul_netlink_process(ulnetlink, false, true);
 * for processing the reply
 */
ul_netlink_rc ul_netlink_dump_request(ul_netlink_data *ulnetlink, uint16_t nlmsg_type);

/* Process netlink messages.
 * asynchronous: If true, return UL_NETLINK_WOULDBLOCK immediately if there is
 *   no data ready. If false, wait for a message.
 * wait_for_nlmsg_done: If true, run in a loop until NLMSG_DONE is
 *   received. Returns after finishing a reply from ul_netlink_dump_request(),
 *   otherwise it acts as an infinite loop. If false, it returns after
 *   processing one message.
 */
ul_netlink_rc ul_netlink_process(ul_netlink_data *ulnetlink, bool asynchronous, bool wait_for_nlmsg_done);

#endif /* UTIL_LINUX_NETLINK */
