/*
 * Netlink message processing
 *
 * Copyright (C) 2025 Stanislav Brabec <sbrabec@suse.com>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 *
 * This set of functions processes netlink messages from the kernel socket,
 * joins message parts into a single structure and calls callback.
 *
 * To do something useful, callback for a selected message type has to be
 * defined. Using callback fuctions and custom data, it could be used for
 * arbitraty purpose.
 *
 * The code is incomplete. More could be implemented as needed by its use
 * cases.
 *
 */
 
#ifndef UTIL_LINUX_NETLINK
#define UTIL_LINUX_NETLINK

#include <stddef.h>
#include <stdbool.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "list.h"

/* Return codes */
typedef enum ul_netlink_rc {
	UL_NETLINK_OK,		/* no error */
	UL_NETLINK_ERROR,	/* generic error */
	UL_NETLINK_DONE,	/* processing reached NLMSG_DONE (for
				 * ul_netlink_dump_request() */
	UL_NETLINK_WOULDBLOCK,	/* no data are ready (for asynchronous mode) */
	//	UL_NETLINK_ABORT,	/* like UL_NETLINK_ERROR, but initiated by the callback */
	/* callback specific */
	UL_NETLINK_IFACES_MAX,	/* ADDR: Too many interfaces */
} ul_netlink_rc;

/* The callback of the netlink message header.
 * Return code: Normally returns UL_NETLINK_OK. In other cases,
 *   ul_netlink_process() immediately exits with an error.
 *   Special return codes:
 *   UL_NETLINK_ABORT: aborting further processing that does not mean an error
 *     (example: Message we were waiting for was found.)
 * See <linux/netlink.h> nlmsghdr to see, what you can process here.
 */
struct ul_netlink_data;

typedef ul_netlink_rc (*ul_netlink_callback)(struct ul_netlink_data *ulnetlink);

/* Structure for ADDR messages collects information from a single ifaddsmsg
 * structure and all optional rtattr structures into a single structure
 * containing all useful data. */
struct ul_netlink_addr {
	uint8_t ifa_family;	/* values from ifaddrmsg */
	uint8_t ifa_scope;
	uint8_t ifa_index;
	uint32_t ifa_flags;
	void *ifa_address;	/* IFA_ADDRESS */
	int ifa_address_len;
	void *ifa_local;	/* IFA_LOCAL */
	int ifa_local_len;
	void *address;		/* IFA_LOCAL, if defined, otherwise
				 * IFA_ADDRESS. This is what you want it most
				 * cases */
	int address_len;
	uint32_t ifa_valid;	/* ifa_valid from IFA_CACHEINFO */
	/* More can be implemented in future. */
};

struct ul_netlink_data {
	/* "static" part of the structure, filled once and kept */ 
	ul_netlink_callback callback_addr; /* Function to process ul_netlink_addr */
	void *data_addr;		/* Arbitrary data of callback_addr */
	int fd;				/* netlink socket FD */
	/* volatile part of the structure, filled by the current message */
	bool is_new;			/* Processing RTM_NEW* */
	bool is_dump;			/* Dump in progress */
	union {
		/* ADDR */
		struct ul_netlink_addr addr;
		/* More can be implemented in future (e. g. LINK, ROUTE etc.). */
	};
};

/* Initialize ul_netlink_data structure */
void ul_netlink_init(struct ul_netlink_data *ulnetlink);

/* Open a netlink connection.
 * nl_groups: Applies for monitoring. In case of ul_netlink_dump_request(),
 *   use its argument to select one.
 *
 * Close and open vs. initial open with parameters?
 * If we use single open with parameters, we can get mixed output.
 * If we use close/open, we get a small race window that could contain
 * unprocessed events. */
ul_netlink_rc ul_netlink_open(struct ul_netlink_data *ulnetlink, uint32_t nl_groups);

/* Close a netlink connection. */
ul_netlink_rc ul_netlink_close(struct ul_netlink_data *ulnetlink);

/* Synchronously sends dump request of a selected nlmsg_type. It does not
 * perform any further actions. The result is returned through the callback
 * mechanism.
 * Under normal conditions, use
 * ul_netlink_process(ulnetlink, false, true);
 * for processing the reply
 */
ul_netlink_rc ul_netlink_dump_request(struct ul_netlink_data *ulnetlink, uint16_t nlmsg_type);

/* Process netlink messages.
 * asynchronous: If true, return UL_NETLINK_WOULDBLOCK immediately if there is
 *   no data ready. If false, wait for a message.
 * wait_for_nlmsg_done: If true, run in a loop until NLMSG_DONE is
 *   received. Returns after finishing a reply from ul_netlink_dump_request(),
 *   otherwise it acts as an infinite loop. If false, it returns after
 *   processing one message.
 */
ul_netlink_rc ul_netlink_process(struct ul_netlink_data *ulnetlink, bool asynchronous, bool wait_for_nlmsg_done);

/* Duplicate ul_netlink_addr structure to a newly allocated memory */
struct ul_netlink_addr *ul_netlink_addr_dup (struct ul_netlink_addr *addr);

/* Deallocate ul_netlink_addr structure */
void ul_netlink_addr_free (struct ul_netlink_addr *addr);

/* TODO: use AC_C_INLINE */
#ifdef __GNUC__
#define _INLINE_ static __inline__
#else                         /* For Watcom C */
#define _INLINE_ static inline
#endif

_INLINE_ const char *ul_netlink_addr_indextoname(const struct ul_netlink_addr *addr){
	static char ifname[IF_NAMESIZE];

	return if_indextoname(addr->ifa_index, ifname);
}

/* Convert ul_netlink_addr to string.
   addr: ul_netlink_addr structure
   id: Which of 3 possible addresses should be converted?
 * Returns static string, valid to next call.
 */
#define UL_NETLINK_ADDR_ADDRESS offsetof(struct ul_netlink_addr, address)
#define UL_NETLINK_ADDR_IFA_ADDRESS offsetof(struct ul_netlink_addr, ifa_address)
#define UL_NETLINK_ADDR_IFA_LOCAL offsetof(struct ul_netlink_addr, ifa_local)
const char *ul_netlink_addr_ntop (const struct ul_netlink_addr *addr, int id);

#endif /* UTIL_LINUX_NETLINK */
