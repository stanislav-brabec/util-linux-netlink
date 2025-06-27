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

/*
 * Debug stuff (based on include/debug.h)
 */
#define ULNETADDRQ_DEBUG_HELP	(1 << 0)
#define ULNETADDRQ_DEBUG_INIT	(1 << 1)
#define ULNETADDRQ_DEBUG_ADDRQ	(1 << 2)
#define ULNETADDRQ_DEBUG_LIST	(1 << 3)

#define ULNETADDRQ_DEBUG_ALL	0x0F

static UL_DEBUG_DEFINE_MASK(netaddrq);
UL_DEBUG_DEFINE_MASKNAMES(netaddrq) =
{
	{ "all", ULNETADDRQ_DEBUG_ALL,		"complete adddress processing" },
	{ "help", ULNETADDRQ_DEBUG_HELP,	"this help" },
	{ "addrq", ULNETADDRQ_DEBUG_ADDRQ,	"address rating" },
	{ "list", ULNETADDRQ_DEBUG_LIST,	"list processing" },

	{ NULL, 0 }
};

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

	ON_DBG(HELP, ul_debug_print_masks("ULNETADDRQ_DEBUG",
				UL_DEBUG_MASKNAMES(netaddrq)));
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

/* Netlink callback evaluating the address quality and building the list of
 * interface lists */
static int callback_addrq(struct ul_nl_data *nl) {
	struct ul_netaddrq_data *addrq = UL_NETADDRQ_DATA(nl);
	struct list_head *li, *ipq_list;
	struct ul_netaddrq_iface *ifaceq = NULL;
	struct ul_netaddrq_ip *ipq = NULL;
	int rc;
	bool *ifaces_change;

	DBG(LIST, ul_debugobj(addrq, "callback_addrq() for %s on %s",
			      ul_nl_addr_ntop(&(nl->addr), UL_NL_ADDR_ADDRESS),
			      nl->addr.ifname));
	if (addrq->callback_pre)
	{
		DBG(LIST, ul_debugobj(addrq, "callback_pre"));
		if ((rc = (*(addrq->callback_pre))(nl)))
			DBG(LIST, ul_debugobj(nl, "callback_pre rc != 0"));
	}

	/* Search for interface in ifaces */
	addrq->nifaces = 0;

	list_for_each(li, &(addrq->ifaces)) {
		struct ul_netaddrq_iface *ifaceqq;
		ifaceqq = list_entry(li, struct ul_netaddrq_iface, entry);
		if (ifaceqq->ifa_index == nl->addr.ifa_index) {
			ifaceq = ifaceqq;
			DBG(LIST, ul_debugobj(ifaceq,
					      "%s found in addrq",
					      nl->addr.ifname));
			break;
		}
		addrq->nifaces++;
	}

	if (ifaceq == NULL) {
		if (nl->rtm_event) {
			if (addrq->nifaces >= max_ifaces) {
				DBG(LIST, ul_debugobj(addrq,
						       "too many interfaces"));
				addrq->overflow = true;
				return UL_NL_IFACES_MAX;
			}
			DBG(LIST, ul_debugobj(addrq,
					       "new ifa_index in addrq"));
			if (!(ifaceq = malloc(sizeof(struct ul_netaddrq_iface))))
			{
				DBG(LIST, ul_debugobj(addrq,
						       "malloc() 1 failed"));
				return -1;
			}
			INIT_LIST_HEAD(&(ifaceq->ip_quality_list_4));
			INIT_LIST_HEAD(&(ifaceq->ip_quality_list_6));
			ifaceq->ifa_index = nl->addr.ifa_index;
			if (!(ifaceq->ifname = strdup(nl->addr.ifname)))
			{
				DBG(LIST, ul_debugobj(addrq,
						       "malloc() 2 failed"));
				free(ifaceq);
				return -1;
			}
			list_add_tail(&(ifaceq->entry), &(addrq->ifaces));
			DBG(LIST, ul_debugobj(ifaceq,
					       "new interface"));
		} else {
			/* Should never happen. */
			DBG(LIST, ul_debugobj(ifaceq,
					       "interface not found"));
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
			DBG(LIST, ul_debugobj(ipq_list,
					       "address not found in the list"));
	}

	/* From now on, rc is return code */
	rc = 0;
	if (UL_NL_IS_RTM_NEW(nl)) {
		struct ul_nl_addr *addr;

		addr = ul_nl_addr_dup(&(nl->addr));
		if (!addr) {
			DBG(LIST, ul_debugobj(addrq,
					       "ul_nl_addr_dup() failed"));
			rc = -1;
			goto error;
		}
		if (ipq == NULL) {
			if (!(ipq = malloc(sizeof(struct ul_netaddrq_ip))))
			{
				DBG(LIST, ul_debugobj(addrq,
						       "malloc() 3 failed"));
				rc = -1;
				ul_nl_addr_free(addr);
				goto error;
			}
			ipq->addr = addr;
			list_add_tail(&(ipq->entry), ipq_list);
			DBG(LIST, ul_debugobj(ipq, "new address"));
			*ifaces_change = true;
		} else {
			DBG(LIST, ul_debugobj(addrq, "updating address data"));
			ul_nl_addr_free(ipq->addr);
			ipq->addr = addr;
		}
		ipq->quality = evaluate_ip_quality(addr);
		DBG(ADDRQ, ul_debugobj(addrq, "%s rating: %hhd",
			      ul_nl_addr_ntop(&(nl->addr), UL_NL_ADDR_ADDRESS),
			      ipq->quality));
	} else {
		/* UL_NL_RTM_DEL */
		if (ipq == NULL)
		{
			/* Should not happen. */
			DBG(LIST, ul_debugobj(nl,
					      "UL_NL_RTM_DEL: unknown address"));
			return UL_NL_SOFT_ERROR;
		}
		/* Delist the address */
		DBG(LIST, ul_debugobj(ipq, "removing address"));
		*ifaces_change = true;
		list_del(&(ipq->entry));
		ul_nl_addr_free(ipq->addr);
		free(ipq);
	error:
		if (list_empty(&(ifaceq->ip_quality_list_4)) &&
		    list_empty(&(ifaceq->ip_quality_list_6))) {
		DBG(LIST,
		    ul_debugobj(ifaceq,
				"deleted last address, removing interface"));
			list_del(&(ifaceq->entry));
			addrq->nifaces--;
			free(ifaceq->ifname);
			free(ifaceq);
		}
	}
	if (!rc && addrq->callback_post)
	{
		DBG(LIST, ul_debugobj(addrq, "callback_post"));
		if ((rc = (*(addrq->callback_post))(nl)))
			DBG(LIST, ul_debugobj(nl, "callback_post rc != 0"));
	}
	return rc;
}

/* Initialize ul_nl_data for use with netlink-addr-quality */
int ul_netaddrq_init(struct ul_nl_data *nl, ul_nl_callback callback_pre,
		     ul_nl_callback callback_post, void *data)
{
	struct ul_netaddrq_data *addrq;

	netaddrq_init_debug();
	if (!(nl->data_addr = malloc(sizeof(struct ul_netaddrq_data))))
		return -1;
	nl->callback_addr = callback_addrq;
	addrq = UL_NETADDRQ_DATA(nl);
	addrq->callback_pre = callback_pre;
	addrq->callback_post = callback_post;
	addrq->callback_data = data;
	addrq->nifaces = 0;
	addrq->overflow = false;
	INIT_LIST_HEAD(&(addrq->ifaces));
	DBG(LIST, ul_debugobj(addrq, "callback initialized"));
	return 0;
}

/* Get best quality value from in the ul_netaddrq_ip list
 * ipq_list: List of IP addresses pf a particular interface and family
 * returns:
 *   best_valid: best ifa_valid validity time seen for the best quality
 *   best_valid_universe: best ifa_valid validity for IP_QUALITY_SCOPE_UNIVERSE
       quality
 *   return value: best quality seen */
static enum ul_netaddrq_ip_rating get_quality_threshold(struct list_head *ipq_list, uint32_t *best_valid, uint32_t *best_valid_universe) {
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

	qlimit = get_quality_threshold(ipq_list, &best_valid,
				       &best_valid_universe);
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
	/* Prepare netlink. */
	ul_nl_init(&nl);
	if ((ul_netaddrq_init(&nl, NULL, ul_netaddrq_dump, (void *)out)))
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
