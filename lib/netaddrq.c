/*
 * Netlink address quality rating tree builder
 *
 * Copyright (C) 2025 Stanislav Brabec <sbrabec@suse.com>
 *
 * This program is freely distributable.
 *
 * This set of netlink callbacks kernel and creates
 * and/or maintains a linked list of requested type. Using callback fuctions
 * and custom data, it could be used for arbitraty purpose.
 *
 */

#include <net/if.h>
#include <netinet/in.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include "netaddrq.h"
#include "list.h"
#include "debug.h"

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

/*
 * Debug stuff (based on include/debug.h)
 */
static UL_DEBUG_DEFINE_MASK(netaddrq);
UL_DEBUG_DEFINE_MASKNAMES(netaddrq) = UL_DEBUG_EMPTY_MASKNAMES;

#define ULNETADDRQ_DEBUG_INIT	(1 << 1)
#define ULNETADDRQ_DEBUG_ADDR	(1 << 2)

#define DBG(m, x)       __UL_DBG(netaddrq, ULNETADDRQ_DEBUG_, m, x)
#define ON_DBG(m, x)    __UL_DBG_CALL(netaddrq, ULNETADDRQ_DEBUG_, m, x)

#define UL_DEBUG_CURRENT_MASK	UL_DEBUG_MASK(netaddrq)
#include "debugobj.h"

static void netaddrq_init_debug(void)
{
	if (netaddrq_debug_mask)
		return;
	__UL_INIT_DEBUG_FROM_ENV(netaddrq, ULNETADDRQ_DEBUG_, 0,
				 ULNETADDRQ_DEBUG);
}

static inline enum ul_netaddrq_ip_rating evaluate_ip_quality(struct ul_nl_addr *addr) {
	enum ul_netaddrq_ip_rating quality;
	switch (addr->ifa_scope) {
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
	if (addr->ifa_flags & IFA_F_TEMPORARY) {
		if (quality <= IP_QUALITY_F_TEMPORARY)
			quality = IP_QUALITY_F_TEMPORARY;
	}
	return quality;
}

static int callback_addr(struct ul_nl_data *nl __attribute__((__unused__))) {
	return 0;
}

/* Netlink callback evaluating the address quality and building the list of
 * interface lists */
static int callback_addrq(struct ul_nl_data *nl) {
	struct ul_netaddrq_data *addrq = UL_NETADDRQ_DATA(nl);
	struct list_head *li, *ipq_list;
	bool *ifaces_change;
	struct ul_netaddrq_iface *ifaceq = NULL;
	struct ul_netaddrq_ip *ipq = NULL;

	// FIXME: can fail
	callback_addr(nl);

	/* Search for interface in ifaces */
	addrq->nifaces = 0;

			debug_net(". callback_addrq()\n");
			printf("  nl->addr.ifa_index %d\n", nl->addr.ifa_index);
	list_for_each(li, &(addrq->ifaces)) {
		struct ul_netaddrq_iface *ifaceqq;
		ifaceqq = list_entry(li, struct ul_netaddrq_iface, entry);
			printf("  ifaceqq->ifa_index %d\n", ifaceqq->ifa_index);
		if (ifaceqq->ifa_index == nl->addr.ifa_index) {
			ifaceq = ifaceqq;
			debug_net("+ interface found in the list\n");
			break;
		}
		addrq->nifaces++;
	}

	if (ifaceq == NULL) {
		if (nl->rtm_event) {
			if (addrq->nifaces >= max_ifaces) {
				debug_net("+ too many interfaces\n");
				addrq->overflow = true;
				return UL_NL_IFACES_MAX;
			}
			debug_net("+ allocating new interface\n");
			/* FIXME: can fail */
			ifaceq = malloc(sizeof(struct ul_netaddrq_iface));
			INIT_LIST_HEAD(&(ifaceq->ip_quality_list_4));
			INIT_LIST_HEAD(&(ifaceq->ip_quality_list_6));
			ifaceq->ifa_index = nl->addr.ifa_index;
			printf("  index %d\n", ifaceq->ifa_index);
			/* FIXME: can fail */
			ifaceq->ifname = strdup(nl->addr.ifname);
			debug_net("+ allocating new interface\n");
			list_add_tail(&(ifaceq->entry), &(addrq->ifaces));
		} else {
			/* Should never happen, should be soft error? FIXME */
			debug_net("- interface not found\n");
			return UL_NL_SOFT_ERROR;
		}
	}
	if (nl->addr.ifa_family == AF_INET) {
		ipq_list = &(ifaceq->ip_quality_list_4);
		ifaces_change = &(ifaceq->ifaces_change_4);
	} else {
	/* if (nl->addr.ifa_family == AF_INET6) */
		ipq_list = &(ifaceq->ip_quality_list_6);
		ifaces_change = &(ifaceq->ifaces_change_6);
	}

	list_for_each(li, ipq_list) {
		ipq = list_entry(li, struct ul_netaddrq_ip, entry);
		if (ipq->addr->address_len == nl->addr.address_len)
			if (memcmp(ipq->addr->address, nl->addr.address, nl->addr.address_len))
				break;
	}
	if (ipq == NULL) {
		debug_net("- address not found in the list\n");
	}

	if (nl->rtm_event) {
		struct ul_nl_addr *addr;
#ifdef DEBUGGING
		fprintf(dbf, "network: + new address (address_len = %d)\n", nl->addr.address_len); fflush(dbf);
#endif
		/* FIXME: can fail. What happens if it is NULL? */
		addr = ul_nl_addr_dup(&(nl->addr));
		if (ipq == NULL) {
			debug_net("+ allocating new address\n");
			ipq = malloc(sizeof(struct ul_netaddrq_ip));
			ipq->addr = addr;
			list_add_tail(&(ipq->entry), ipq_list);
			*ifaces_change = true;
		} else {
			debug_net("+ replacing address data\n");
			ul_nl_addr_free(ipq->addr);
			ipq->addr = addr;
		}
		ipq->quality = evaluate_ip_quality(addr);
		fprintf(dbf, "  quality: %d\n", ipq->quality);
	} else {
		debug_net("address removed\n");
		/* Should not happen FIXME soft error?*/
		if (ipq == NULL)
			return UL_NL_SOFT_ERROR;
		/* Delist the address */
		debug_net("- deleting address\n");
		*ifaces_change = true;
		list_del(&(ipq->entry));
		ul_nl_addr_free(ipq->addr);
		free(ipq);
		if (list_empty(&(ifaceq->ip_quality_list_4)) && list_empty(&(ifaceq->ip_quality_list_6))) {
			debug_net("- deleted last IP in the interface, removing interface\n");
			list_del(&(ifaceq->entry));
			addrq->nifaces--;
			free(ifaceq->ifname);
			free(ifaceq);
		}
	}
	if (addrq->callback)
		return (*(addrq->callback))(nl);
	return 0;
}

/* Initialize ul_nl_data for use with netlink-addr-quality */
int ul_netaddrq_init(struct ul_nl_data *nl, ul_nl_callback callback, void *data)
{
	struct ul_netaddrq_data *addrq;

	netaddrq_init_debug();
	if (!(nl->data_addr = malloc(sizeof(struct ul_netaddrq_data))))
		return -1;
	nl->callback_addr = callback_addrq;
	addrq = UL_NETADDRQ_DATA(nl);
	addrq->callback = callback;
	addrq->callback_data = data;
	addrq->nifaces = 0;
	addrq->overflow = false;
	INIT_LIST_HEAD(&(addrq->ifaces));
	DBG(ADDR, ul_debugobj(addrq, "callback initialized"));
	return 0;
}

/* Get best quality value from in the ul_netaddrq_ip list
 * ipq_list: List of IP addresses pf a particular interface and family
 * returns:
 *   best_valid: best ifa_valid validity time seen for the best quality
 *   best_valid_universe: best ifa_valid validity for IP_QUALITY_SCOPE_UNIVERSE quality
 *   return value: best quality seen */
static enum ul_netaddrq_ip_rating get_quality_limit(struct list_head *ipq_list, uint32_t *best_valid, uint32_t *best_valid_universe) {
	struct list_head *li;
	struct ul_netaddrq_ip *ipq = NULL;
	uint32_t **best_valid_cur;
	enum ul_netaddrq_ip_rating qlimit, qcur;

	qlimit = IP_QUALITY_BAD;
	*best_valid = 0;
	*best_valid_universe = 0;
	list_for_each(li, ipq_list) {
		ipq = list_entry(li, struct ul_netaddrq_ip, entry);
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
	struct ul_netaddrq_ip *ipq;
	enum ul_netaddrq_ip_rating qlimit;
	uint32_t best_valid, best_valid_universe;

	qlimit = get_quality_limit(ipq_list, &best_valid, &best_valid_universe);
#ifdef DEBUGGING
	fprintf(out, " (quality limit %d)", qlimit); fflush(out);
#endif
	list_for_each(li, ipq_list) {
		ipq = list_entry(li, struct ul_netaddrq_ip, entry);

		if (ipq->quality <= qlimit &&
		    (ipq->quality == IP_QUALITY_SCOPE_UNIVERSE ?
		     (best_valid_universe == 0 || ipq->addr->ifa_valid == best_valid_universe) :
		     (best_valid == 0 || ipq->addr->ifa_valid == best_valid)))
			fprintf(out, " %s", ul_nl_addr_ntop(ipq->addr, UL_NL_ADDR_ADDRESS));
	}
}

/* Requires callback_data being a FILE */
static int ul_netaddrq_dump(struct ul_nl_data *nl) {
	struct ul_netaddrq_data *addrq = UL_NETADDRQ_DATA(nl);
	FILE *out;
	struct list_head *li;
	struct ul_netaddrq_iface *ifaceq;

	// FIXME: can fail
	out = (FILE *)addrq->callback_data;
	fprintf(out, "======\n"); fflush(out);
	list_for_each(li, &(addrq->ifaces)) {
		ifaceq = list_entry(li, struct ul_netaddrq_iface, entry);

		fprintf(out, "%d %s:\n", ifaceq->ifa_index, ifaceq->ifname);

		/* IPv4 */
		fprintf(out, "  IPv4"); fflush(out);
		print_good_addresses(&(ifaceq->ip_quality_list_4), out);
		fprintf(out, "\n");

		/* IPv6 */
		fprintf(out, "  IPv6"); fflush(out);
		print_good_addresses(&(ifaceq->ip_quality_list_6), out);
		fprintf(out, "\n");
	}
	return 0;
}


#ifdef TEST_PROGRAM_NETADDRQ
//include <stdio.h>
//include <net/if.h>
//include <netinet/in.h>
//include <arpa/inet.h>

int main(int argc __attribute__((__unused__)), char *argv[] __attribute__((__unused__)))
{
	int rc = 1;
	int ulrc; /* FIXME: ulrc x rc */
	struct ul_nl_data nl;
	FILE *out = stdout;
	dbf = stdout;
	/* Prepare netlink. */
	ul_nl_init(&nl);
	if ((ul_netaddrq_init(&nl, ul_netaddrq_dump, (void *)out)))
		// FIXME: real rc
		return -1;

	/* Dump addresses */
	if (ul_nl_open(&nl, 0))
		// FIXME: real rc
		return -1;
	if (ul_nl_request_dump(&nl, RTM_GETADDR))
		goto error;
	if (ul_nl_process(&nl, UL_NL_SYNC, UL_NL_LOOP) != UL_NL_DONE)
		goto error;
	puts("RTM_GETADDR dump finished.");

	/* Close and later open. See note in the ul_nl_open() docs. */
	if (ul_nl_close(&nl))
		goto error;

	/* Monitor further changes */
	puts("Going to monitor mode.");
	if (ul_nl_open(&nl, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR))
		goto error;
	/* In this example UL_NL_ABORT never appears, as callback does
	 * not use it. */
	ulrc = ul_nl_process(&nl, UL_NL_SYNC, UL_NL_LOOP);
//	if (ulrc == UL_NL_OK || ulrc == UL_NL_ABORT)
	if (!ulrc)
		rc = 0;
error:
	if ((ul_nl_close(&nl)))
		rc = 1;
	return rc;
}
#endif /* TEST_PROGRAM_NETADDRQ */
