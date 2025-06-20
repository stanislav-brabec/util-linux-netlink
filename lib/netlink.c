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
 * The code here just processes the netlink stream. To do something useful,
 * callback for a selected message type has to be defined.
 */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "netlink.h"
#include "debug.h"

/*
 * Debug stuff (based on include/debug.h)
 */
static UL_DEBUG_DEFINE_MASK(netlink);
UL_DEBUG_DEFINE_MASKNAMES(netlink) = UL_DEBUG_EMPTY_MASKNAMES;

#define NETLINK_DEBUG_INIT	(1 << 1)
#define NETLINK_DEBUG_MSG	(1 << 2)

#define DBG(m, x)       __UL_DBG(netlink, NETLINK_DEBUG_, m, x)
#define ON_DBG(m, x)    __UL_DBG_CALL(netlink, NETLINK_DEBUG_, m, x)

#define UL_DEBUG_CURRENT_MASK	UL_DEBUG_MASK(netlink)
#include "debugobj.h"

static void netlink_init_debug(void)
{
	if (netlink_debug_mask)
		return;
	__UL_INIT_DEBUG_FROM_ENV(netlink, NETLINK_DEBUG_, 0, NETLINK_DEBUG);
}

void ul_nl_init(struct ul_nl_data *nl) {
	memset(nl, 0, sizeof(struct ul_nl_data));
}

ul_nl_rc ul_nl_dump_request(struct ul_nl_data *nl, uint16_t nlmsg_type) {
	struct {
		struct nlmsghdr nh;
		struct rtgenmsg g;
	} req;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.g));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nh.nlmsg_type = nlmsg_type;
	req.g.rtgen_family = AF_NETLINK;

	nl->dumping = true;
	if (send(nl->fd, &req, req.nh.nlmsg_len, 0) == -1)
		return UL_NL_ERROR;
	return UL_NL_OK;
}

/* Expecting non-zero nl->callback_addr! */
static ul_nl_rc process_addr(struct ul_nl_data *nl, struct nlmsghdr *nh)
{
	struct ifaddrmsg *ifaddr;
	struct rtattr *attr;
	int len;
	bool has_local_address = false;
	ul_nl_rc ulrc = UL_NL_OK;

	memset(&(nl->addr), 0, sizeof(nl->addr));

	/* Process ifaddrmsg. */
	ifaddr = NLMSG_DATA(nh);

	nl->addr.ifa_family = ifaddr->ifa_family;
	nl->addr.ifa_scope = ifaddr->ifa_scope;
	nl->addr.ifa_index = ifaddr->ifa_index;
	nl->addr.ifa_flags = (uint32_t)(ifaddr->ifa_flags);

	/* Process rtattr. */
	len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifaddr));
	for (attr = IFA_RTA(ifaddr); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
		/* Proces most common rta attributes */
		switch (attr->rta_type) {
		case IFA_ADDRESS:
			nl->addr.ifa_address = RTA_DATA(attr);
			nl->addr.ifa_address_len = RTA_PAYLOAD(attr);
			if (!has_local_address) {
				nl->addr.address = RTA_DATA(attr);
				nl->addr.address_len = RTA_PAYLOAD(attr);
			}
			break;
		case IFA_LOCAL:
			/* Point to Point interface listens has local address
			 * and listens there */
			has_local_address = true;
			nl->addr.ifa_local = nl->addr.address = RTA_DATA(attr);
			nl->addr.ifa_local_len = nl->addr.address_len = RTA_PAYLOAD(attr);
			break;
		case IFA_CACHEINFO:
			struct ifa_cacheinfo *ci = (struct ifa_cacheinfo *)RTA_DATA(attr);
			nl->addr.ifa_valid = ci->ifa_valid;
			break;
		case IFA_FLAGS:
			nl->addr.ifa_flags = *(uint32_t *)(RTA_DATA(attr));
			break;
		}
	}
	ulrc = (*(nl->callback_addr))(nl);
	return ulrc;
}

static ul_nl_rc process_msg(struct ul_nl_data *nl, struct nlmsghdr *nh)
{
	ul_nl_rc ulrc = UL_NL_OK;

	nl->rtm_event = UL_NL_RTM_DEL;
	switch (nh->nlmsg_type) {
	case RTM_NEWADDR:
		nl->rtm_event = UL_NL_RTM_NEW;
		/* fallthrough */
	case RTM_DELADDR:
	/* If callback_addr is not set, skip process_addr */
	  if (nl->callback_addr)
		  ulrc = process_addr(nl, nh);
	  break;
	/* More can be implemented in future (e. g. RTM_NEWLINK, RTM_DELLINK etc.). */
	}
	return ulrc;
}

ul_nl_rc ul_nl_process(struct ul_nl_data *nl, bool asynchronous, bool wait_for_nlmsg_done)
{
	char buf[4096];
	struct sockaddr_nl snl;
	struct nlmsghdr *nh;
	int rc;

	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf)
	};
	struct msghdr msg = {
		.msg_name = &snl,
		.msg_namelen = sizeof(snl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0
	};

	while (1) {
		rc = recvmsg(nl->fd, &msg, (wait_for_nlmsg_done ? 0 : (asynchronous ? MSG_DONTWAIT : 0)));
		if (rc < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				return UL_NL_WOULDBLOCK;

			/* Failure, just stop listening for changes */
			nl->dumping = false;
			return UL_NL_ERROR;
		}

		for (nh = (struct nlmsghdr *)buf;
		     NLMSG_OK(nh, (unsigned int)rc);
		     nh = NLMSG_NEXT(nh, rc)) {
			if (nh->nlmsg_type == NLMSG_ERROR) {
				nl->dumping = false;
				return UL_NL_ERROR;
			}
			if (nh->nlmsg_type == NLMSG_DONE) {
				nl->dumping = false;
				return UL_NL_DONE;
			}

			process_msg(nl, nh);
		}
		if (!wait_for_nlmsg_done) {
			return UL_NL_OK;
		}
	}
}

ul_nl_rc ul_nl_open(struct ul_nl_data *nl, uint32_t nl_groups)
{
	struct sockaddr_nl addr = { 0, };
	int sock;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0)
		return UL_NL_ERROR;
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_groups = nl_groups;
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(sock);
		return UL_NL_ERROR;
	}
	nl->fd = sock;
	return UL_NL_OK;
}
	
ul_nl_rc ul_nl_close(struct ul_nl_data *nl) {
	if (close(nl->fd) == 0)
		return UL_NL_OK;
	return UL_NL_ERROR;
}

struct ul_nl_addr *ul_nl_addr_dup (struct ul_nl_addr *addr) {
	struct ul_nl_addr *newaddr;
	newaddr = malloc(sizeof(struct ul_nl_addr));
	if (!newaddr) goto error1;
	memcpy(newaddr, addr, sizeof(struct ul_nl_addr));
	if (addr->ifa_address_len) {
		newaddr->ifa_address = malloc(addr->ifa_address_len);
		if (!newaddr->ifa_address)
			goto error2;
		memcpy(newaddr->ifa_address, addr->ifa_address, addr->ifa_address_len);
	}
	if (addr->ifa_local_len) {
		newaddr->ifa_local = malloc(addr->ifa_local_len);
		if (!newaddr->ifa_local)
			goto error3;
		memcpy(newaddr->ifa_local, addr->ifa_local, addr->ifa_local_len);
	}
	if (&(addr->ifa_address) == &(addr->ifa_local))
		newaddr->address = newaddr->ifa_local;
	else
		newaddr->address = newaddr->ifa_address;
	return newaddr;
error3:
	free(newaddr->ifa_address);
error2:
	free(newaddr);
error1:
	return NULL;
}

void ul_nl_addr_free (struct ul_nl_addr *addr) {
	free(addr->ifa_address);
	free(addr->ifa_local);
	free(addr);
}

const char *ul_nl_addr_ntop (const struct ul_nl_addr *addr, int id) {
	const void **ifa_addr = (const void **)((const char *)addr + id);
	/* (INET6_ADDRSTRLEN-1) + (IF_NAMESIZE-1) + strlen("%") + 1 */
	static char addr_str[INET6_ADDRSTRLEN+IF_NAMESIZE];
	char *p;

	if (addr->ifa_family == AF_INET)
		return inet_ntop(AF_INET, *ifa_addr, addr_str, sizeof(addr_str));
	else {
	/* if (addr->ifa_family == AF_INET6) */
		if (addr->ifa_scope == RT_SCOPE_LINK) {
			inet_ntop(AF_INET6, *ifa_addr, addr_str, sizeof(addr_str));
			p = addr_str;
			while (*p) p++;
			*p++ = '%';
			if_indextoname(addr->ifa_index, p);
			return addr_str;
		} else
			return inet_ntop(AF_INET6, *ifa_addr, addr_str, sizeof(addr_str));
	}
}

#ifdef TEST_PROGRAM_NETLINK
#include <stdio.h>

static ul_nl_rc callback_addr(struct ul_nl_data *nl) {
	char *str;

	printf("%s address:\n", ((nl->rtm_event ? "Add" : "Delete")));
	printf("  interface: %s\n", ul_nl_addr_indextoname(&(nl->addr)));
	if (nl->addr.ifa_family == AF_INET)
		printf("  IPv4 %s\n",
		       ul_nl_addr_ntop(&(nl->addr), UL_NL_ADDR_ADDRESS));
	else
	/* if (nl->addr.ifa_family == AF_INET) */
		printf("  IPv6 %s\n",
		       ul_nl_addr_ntop(&(nl->addr), UL_NL_ADDR_ADDRESS));
	switch (nl->addr.ifa_scope) {
	case RT_SCOPE_UNIVERSE:	str = "global"; break;
	case RT_SCOPE_SITE:	str = "site"; break;
	case RT_SCOPE_LINK:	str = "link"; break;
	case RT_SCOPE_NOWHERE:	str = "nowhere"; break;
	default:		str = "other"; break;
	}
	printf("  scope: %s\n", str);
	printf("  valid: %d\n", nl->addr.ifa_valid);
	return UL_NL_OK;
}

int main(int argc __attribute__((__unused__)), char *argv[] __attribute__((__unused__)))
{
	int rc = 1;
	ul_nl_rc ulrc;
	struct ul_nl_data nl;

	/* Prepare netlink. */
	ul_nl_init(&nl);
	nl.callback_addr = callback_addr;

	/* Dump addresses */
	if (ul_nl_open(&nl, 0) != UL_NL_OK)
		return 1;
	if (ul_nl_dump_request(&nl, RTM_GETADDR) != UL_NL_OK)
		goto error;
	if (ul_nl_process(&nl, false, true) != UL_NL_DONE)
		goto error;
	puts("RTM_GETADDR dump finished.");

	/* Close and later open. See note in the ul_nl_open() docs. */
	if (ul_nl_close(&nl) != UL_NL_OK)
		goto error;

	/* Monitor further changes */
	puts("Going to monitor mode.");
	if (ul_nl_open(&nl, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR) != UL_NL_OK)
		goto error;
	/* In this example UL_NL_ABORT never appears, as callback does
	 * not use it. */
	ulrc = ul_nl_process(&nl, false, true);
//	if (ulrc == UL_NL_OK || ulrc == UL_NL_ABORT)
	if (ulrc == UL_NL_OK)
		rc = 0;
error:
	if (ul_nl_close(&nl) !=  UL_NL_OK)
		rc = 1;
	return rc;
}
#endif /* TEST_PROGRAM_NETLINK */
