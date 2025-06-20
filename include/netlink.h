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
typedef enum ul_nl_rc {
	UL_NL_OK,		/* no error */
	UL_NL_ERROR,	/* generic error */
	UL_NL_DONE,	/* processing reached NLMSG_DONE (for
				 * ul_nl_dump_request() */
	UL_NL_WOULDBLOCK,	/* no data are ready (for asynchronous mode) */
	//	UL_NL_ABORT,	/* like UL_NL_ERROR, but initiated by the callback */
	/* callback specific */
	UL_NL_IFACES_MAX,	/* ADDR: Too many interfaces */
} ul_nl_rc;

/* The callback of the netlink message header.
 * Return code: Normally returns UL_NL_OK. In other cases,
 *   ul_nl_process() immediately exits with an error.
 *   Special return codes:
 *   UL_NL_ABORT: aborting further processing that does not mean an error
 *     (example: Message we were waiting for was found.)
 * See <linux/netlink.h> nlmsghdr to see, what you can process here.
 */
struct ul_nl_data;

typedef ul_nl_rc (*ul_nl_callback)(struct ul_nl_data *nl);

/* Structure for ADDR messages collects information from a single ifaddsmsg
 * structure and all optional rtattr structures into a single structure
 * containing all useful data. */
struct ul_nl_addr {
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

/* Values for rtm_event */
#define UL_NL_RTM_DEL false		/* processing RTM_DEL_* */
#define UL_NL_RTM_NEW true		/* processing RTM_NEW_* */

struct ul_nl_data {
	/* "static" part of the structure, filled once and kept */ 
	ul_nl_callback callback_addr;	/* Function to process ul_nl_addr */
	void *data_addr;		/* Arbitrary data of callback_addr */
	int fd;				/* netlink socket FD */

	/* volatile part of the structure, filled by the current message */
	bool rtm_event;			/* UL_NL_RTM_DEL or UL_NL_RTM_NEW */
	bool dumping;			/* Dump in progress */

	/* volatile part of the structure that depends on message typ */
	union {
		/* ADDR */
		struct ul_nl_addr addr;
		/* More can be implemented in future (e. g. LINK, ROUTE etc.). */
	};
};

/* Initialize ul_nl_data structure */
void ul_nl_init(struct ul_nl_data *nl);

/* Open a netlink connection.
 * nl_groups: Applies for monitoring. In case of ul_nl_dump_request(),
 *   use its argument to select one.
 *
 * Close and open vs. initial open with parameters?
 * If we use single open with parameters, we can get mixed output.
 * If we use close/open, we get a small race window that could contain
 * unprocessed events. */
ul_nl_rc ul_nl_open(struct ul_nl_data *nl, uint32_t nl_groups);

/* Close a netlink connection. */
ul_nl_rc ul_nl_close(struct ul_nl_data *nl);

/* Synchronously sends dump request of a selected nlmsg_type. It does not
 * perform any further actions. The result is returned through the callback
 * mechanism.
 * Under normal conditions, use
 * ul_nl_process(nl, false, true);
 * for processing the reply
 */
ul_nl_rc ul_nl_dump_request(struct ul_nl_data *nl, uint16_t nlmsg_type);

/* Process netlink messages.
 * asynchronous: If true, return UL_NL_WOULDBLOCK immediately if there is
 *   no data ready. If false, wait for a message.
 * wait_for_nlmsg_done: If true, run in a loop until NLMSG_DONE is
 *   received. Returns after finishing a reply from ul_nl_dump_request(),
 *   otherwise it acts as an infinite loop. If false, it returns after
 *   processing one message.
 */
ul_nl_rc ul_nl_process(struct ul_nl_data *nl, bool asynchronous, bool wait_for_nlmsg_done);

/* Duplicate ul_nl_addr structure to a newly allocated memory */
struct ul_nl_addr *ul_nl_addr_dup (struct ul_nl_addr *addr);

/* Deallocate ul_nl_addr structure */
void ul_nl_addr_free (struct ul_nl_addr *addr);

/* TODO: use AC_C_INLINE */
#ifdef __GNUC__
#define _INLINE_ static __inline__
#else                         /* For Watcom C */
#define _INLINE_ static inline
#endif

_INLINE_ const char *ul_nl_addr_indextoname(const struct ul_nl_addr *addr){
	static char ifname[IF_NAMESIZE];

	return if_indextoname(addr->ifa_index, ifname);
}

/* Convert ul_nl_addr to string.
   addr: ul_nl_addr structure
   id: Which of 3 possible addresses should be converted?
 * Returns static string, valid to next call.
 */
#define UL_NL_ADDR_ADDRESS offsetof(struct ul_nl_addr, address)
#define UL_NL_ADDR_IFA_ADDRESS offsetof(struct ul_nl_addr, ifa_address)
#define UL_NL_ADDR_IFA_LOCAL offsetof(struct ul_nl_addr, ifa_local)
const char *ul_nl_addr_ntop (const struct ul_nl_addr *addr, int id);

#endif /* UTIL_LINUX_NETLINK */
