#include "netlink-addr-quality.h"
#include "list.h"
#include <net/if.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>

/* Maximal number of interfaces. The algorithm has a quadratic complexity,
 * don't overflood it. */
const int max_ifaces = 12;
#define DEBUG 1
#define DEBUGGING 1
#ifdef DEBUG
# define debug(s) do { fprintf(dbf,s); fflush(dbf); } while (0)
FILE *dbf;
#else
# define debug(s) do { ; } while (0)
#endif
#define debug_net(s) debug("network: " s)

static inline enum ip_quality_item_value evaluate_ip_quality(ul_netlink_addr *uladdr) {
	enum ip_quality_item_value quality;
	switch (uladdr->ifa_scope) {
	case RT_SCOPE_UNIVERSE:
		quality = IP_QUALITY_SCOPE_UNIVERSE;
		break;
	case RT_SCOPE_LINK:
		quality = IP_QUALITY_SCOPE_LINK;
		break;
	case RT_SCOPE_SITE:
		quality = IP_QUALITY_SCOPE_SITE;
		break;
	default:
		quality = IP_QUALITY_BAD;
		break;
	}
	if (uladdr->ifa_flags & IFA_F_TEMPORARY) {
		if (quality <= IP_QUALITY_F_TEMPORARY)
			quality = IP_QUALITY_F_TEMPORARY;
	}
	return quality;
}

/* Netlink callback evaluating the address quality and building the list of
 * interface lists */
static ul_netlink_rc callback_addr_quality(ul_netlink_data *ulnetlink) {
	struct ul_netlink_addr_quality_data *uladdrq = UL_NETLINK_QUALITY_DATA(ulnetlink);
	struct list_head *li, *ipq_list;
	bool *ifaces_list_change;
	struct iface_quality_item *ifaceq = NULL;
	struct ip_quality_item *ipq = NULL;

	/* Search for interface in ifaces_list */
	uladdrq->ifaces_count = 0;

			debug_net(". callback_addr_quality()\n");
			printf("  ulnetlink->addr.ifa_index %d\n", ulnetlink->addr.ifa_index);
	list_for_each(li, &(uladdrq->ifaces_list)) {
		struct iface_quality_item *ifaceqq;
		ifaceqq = list_entry(li, struct iface_quality_item, entry);
			printf("  ifaceq->ifa_index %d\n", ifaceq->ifa_index);
		if (ifaceq->ifa_index == ulnetlink->addr.ifa_index) {
			ifaceq = ifaceqq;
			debug_net("+ interface found in the list\n");
			break;
		}
		uladdrq->ifaces_count++;
	}

	if (ifaceq == NULL) {
		if (ulnetlink->is_new) {
			if (uladdrq->ifaces_count >= max_ifaces) {
				debug_net("+ too many interfaces\n");
				uladdrq->ifaces_skip_dump = true;
				return UL_NETLINK_IFACES_MAX;
			}
			debug_net("+ allocating new interface\n");
			/* FIXME: can fail */
			ifaceq = malloc(sizeof(struct iface_quality_item));
			INIT_LIST_HEAD(&(ifaceq->ip_quality_list_4));
			INIT_LIST_HEAD(&(ifaceq->ip_quality_list_6));
			ifaceq->ifa_index = ulnetlink->addr.ifa_index;
			printf("  index %d\n", ifaceq->ifa_index);
			debug_net("+ allocating new interface\n");
			list_add_tail(&(ifaceq->entry), &(uladdrq->ifaces_list));
		} else {
			/* Should never happen */
			debug_net("- interface not found\n");
			return UL_NETLINK_ERROR;
		}
	}
	if (ulnetlink->addr.ifa_family == AF_INET) {
		ipq_list = &(ifaceq->ip_quality_list_4);
		ifaces_list_change = &(ifaceq->ifaces_list_change_4);
	} else {
	/* if (ulnetlink->addr.ifa_family == AF_INET6) */
		ipq_list = &(ifaceq->ip_quality_list_6);
		ifaces_list_change = &(ifaceq->ifaces_list_change_6);
	}

	list_for_each(li, ipq_list) {
		ipq = list_entry(li, struct ip_quality_item, entry);
		if (ipq->addr->address_len == ulnetlink->addr.address_len)
			if (memcmp(ipq->addr->address, ulnetlink->addr.address, ulnetlink->addr.address_len))
				break;
	}
	if (ipq == NULL) {
		debug_net("- address not found in the list\n");
	}

	if (ulnetlink->is_new) {
		ul_netlink_addr *uladdr;
#ifdef DEBUGGING
		fprintf(dbf, "network: + new address (address_len = %d)\n", ulnetlink->addr.address_len); fflush(dbf);
#endif
		/* FIXME: can fail. What happens if it is NULL? */
		uladdr = ul_netlink_addr_dup(&(ulnetlink->addr));
		if (ipq == NULL) {
			debug_net("+ allocating new address\n");
			ipq = malloc(sizeof(struct ip_quality_item));
			ipq->addr = uladdr;
			list_add_tail(&(ipq->entry), ipq_list);
			*ifaces_list_change = true;
		} else {
			debug_net("+ replacing address data\n");
			ul_netlink_addr_free(ipq->addr);
			ipq->addr = uladdr;
		}
		ipq->quality = evaluate_ip_quality(uladdr);
	} else {
		debug_net("address removed\n");
		/* Should not happen */
		if (ipq == NULL)
			return UL_NETLINK_ERROR;
		/* Delist the address */
		debug_net("- deleting address\n");
		*ifaces_list_change = true;
		list_del(&(ipq->entry));
		ul_netlink_addr_free(ipq->addr);
		free(ipq);
		if (list_empty(&(ifaceq->ip_quality_list_4)) && list_empty(&(ifaceq->ip_quality_list_6))) {
			debug_net("- deleted last IP in the interface, removing interface\n");
			list_del(&(ifaceq->entry));
			uladdrq->ifaces_count--;
			free(ifaceq);
		}
	}
	if (uladdrq->callback)
		return (*(uladdrq->callback))(ulnetlink);
	return UL_NETLINK_OK;
}

/* Initialize ul_netlink_data for use with netlink-addr-quality */
ul_netlink_rc ul_netlink_addr_quality_init(ul_netlink_data *ulnetlink, ul_netlink_callback callback, void *data)
{
	if (!(ulnetlink->data_addr = malloc(sizeof(struct ul_netlink_addr_quality_data))))
		return UL_NETLINK_ERROR;
	ulnetlink->callback_addr = callback_addr_quality;

	struct ul_netlink_addr_quality_data *uladdrq = UL_NETLINK_QUALITY_DATA(ulnetlink);
	uladdrq->callback = callback;
	uladdrq->callback_data = data;
	uladdrq->ifaces_count = 0;
	uladdrq->ifaces_skip_dump = false;
	INIT_LIST_HEAD(&(uladdrq->ifaces_list));
	return UL_NETLINK_OK;
}

/* Get best quality value from in the ip_quality_item list
 * ipq_list: List of IP addresses pf a particular interface and family
 * returns:
 *   best_valid: best ifa_valid validity time seen for the best quality
 *   best_valid_universe: best ifa_valid validity for IP_QUALITY_SCOPE_UNIVERSE quality
 *   return value: best quality seen */
static enum ip_quality_item_value get_quality_limit(struct list_head *ipq_list, uint32_t *best_valid, uint32_t *best_valid_universe) {
	struct list_head *li;
	struct ip_quality_item *ipq = NULL;
	uint32_t **best_valid_cur;
	enum ip_quality_item_value qlimit, qcur;

	qlimit = IP_QUALITY_BAD;
	*best_valid = 0;
	*best_valid_universe = 0;
	list_for_each(li, ipq_list) {
		ipq = list_entry(li, struct ip_quality_item, entry);
		qcur = ipq->quality;
		/* We do not discriminate between site and global
		 * addresses. Consider them as equally good and report
		 * both. */
		if (qcur == IP_QUALITY_SCOPE_UNIVERSE) {
			qcur = IP_QUALITY_SCOPE_SITE;
			best_valid_cur = &best_valid_universe;
		} else
			best_valid_cur = &best_valid;
		if (qlimit > qcur) {
			qlimit = qcur;
			**best_valid_cur = ipq->addr->ifa_valid;
		} else {
			if (ipq->addr->ifa_valid > 0) {
				if (ipq->addr->ifa_valid > **best_valid_cur)
					**best_valid_cur = ipq->addr->ifa_valid;
			}
		}
	}
	return qlimit;
}

static void print_good_addresses(struct list_head *ipq_list, FILE *out)
{
	struct list_head *li;
	struct ip_quality_item *ipq;
	enum ip_quality_item_value qlimit;
	uint32_t best_valid, best_valid_universe;

	qlimit = get_quality_limit(ipq_list, &best_valid, &best_valid_universe);
#ifdef DEBUGGING
	fprintf(out, " (quality limit %d)", qlimit); fflush(out);
#endif
	list_for_each(li, ipq_list) {
		ipq = list_entry(li, struct ip_quality_item, entry);

		if (ipq->quality <= qlimit &&
		    (ipq->quality == IP_QUALITY_SCOPE_UNIVERSE ?
		     (best_valid_universe == 0 || ipq->addr->ifa_valid == best_valid_universe) :
		     (best_valid == 0 || ipq->addr->ifa_valid == best_valid)))
			fprintf(out, " %s", ul_netlink_addr_ntop(ipq->addr, UL_NETLINK_ADDR_ADDRESS));
	}
}

/* Requires callback_data being a FILE */
static ul_netlink_rc ul_netlink_addr_quality_dump(ul_netlink_data *ulnetlink) {
	struct ul_netlink_addr_quality_data *uladdrq = UL_NETLINK_QUALITY_DATA(ulnetlink);
	FILE *out;
	struct list_head *li;
	struct iface_quality_item *ifaceq;
// FIXME: Too useful. Should be filled as a part of basic structure.
	static char ifname[IF_NAMESIZE];

	out = (FILE *)uladdrq->callback_data;
	fprintf(out, "======\n"); fflush(out);
	list_for_each(li, &(uladdrq->ifaces_list)) {
		ifaceq = list_entry(li, struct iface_quality_item, entry);

		fprintf(out, "%d %s:\n", ifaceq->ifa_index, if_indextoname(ifaceq->ifa_index, ifname));

		/* IPv4 */
		fprintf(out, "  IPv4"); fflush(out);
		print_good_addresses(&(ifaceq->ip_quality_list_4), out);
		fprintf(out, "\n");

		/* IPv6 */
		fprintf(out, "  IPv6"); fflush(out);
		print_good_addresses(&(ifaceq->ip_quality_list_6), out);
		fprintf(out, "\n");
	}
	return UL_NETLINK_OK;
}


#ifdef TEST_PROGRAM_NETLINK_ADDR_QUALITY
//include <stdio.h>
//include <net/if.h>
//include <netinet/in.h>
//include <arpa/inet.h>

int main(int argc __attribute__((__unused__)), char *argv[] __attribute__((__unused__)))
{
	int rc = 1;
	ul_netlink_rc ulrc;
	ul_netlink_data ulnetlink;
	FILE *out = stdout;
	dbf = stdout;
	/* Prepare netlink. */
	ul_netlink_init(&ulnetlink);
	if (ul_netlink_addr_quality_init(&ulnetlink, ul_netlink_addr_quality_dump, (void *)out) != UL_NETLINK_OK)
		return 1;

	/* Dump addresses */
	if (ul_netlink_open(&ulnetlink, 0) != UL_NETLINK_OK)
		return 1;
	if (ul_netlink_dump_request(&ulnetlink, RTM_GETADDR) != UL_NETLINK_OK)
		goto error;
	if (ul_netlink_process(&ulnetlink, false, true) != UL_NETLINK_DONE)
		goto error;
	puts("RTM_GETADDR dump finished.");

	/* Close and later open. See note in the ul_netlink_open() docs. */
	if (ul_netlink_close(&ulnetlink) != UL_NETLINK_OK)
		goto error;

	/* Monitor further changes */
	puts("Going to monitor mode.");
	if (ul_netlink_open(&ulnetlink, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR) != UL_NETLINK_OK)
		goto error;
	/* In this example UL_NETLINK_ABORT never appears, as callback does
	 * not use it. */
	ulrc = ul_netlink_process(&ulnetlink, false, true);
//	if (ulrc == UL_NETLINK_OK || ulrc == UL_NETLINK_ABORT)
	if (ulrc == UL_NETLINK_OK)
		rc = 0;
error:
	if (ul_netlink_close(&ulnetlink) !=  UL_NETLINK_OK)
		rc = 1;
	return rc;
}
#endif /* TEST_PROGRAM_NETLINK_ADDR_QUALITY */
