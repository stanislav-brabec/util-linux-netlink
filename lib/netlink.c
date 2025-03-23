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

#include <sys/socket.h>

#include "netlink.h"

void ul_netlink_init(ul_netlink_data *ulnetlink) {
	INIT_LIST_HEAD(&ulnetlink->callbacks);
}

void ul_netlink_callback_add(ul_netlink_data *ulnetlink, ul_netlink_callback_data *callbackdata) {
	list_add(&callbackdata->list_item, &ulnetlink->callbacks);
}

ul_netlink_rc ul_netlink_dump_request(ul_netlink_data *ulnetlink, uint16_t nlmsg_type) {
	struct {
		struct nlmsghdr nh;
		struct rtgenmsg g;
	} req;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.g));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nh.nlmsg_type = nlmsg_type;
	req.g.rtgen_family = AF_NETLINK;

	if (send(ulnetlink->fd, &req, req.nh.nlmsg_len, 0) == -1)
		return UL_NETLINK_ERROR;
	return UL_NETLINK_OK;
}

ul_netlink_rc ul_netlink_process(ul_netlink_data *ulnetlink, bool asynchronous, bool wait_for_nlmsg_done)
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
		rc = recvmsg(ulnetlink->fd, &msg, (wait_for_nlmsg_done ? 0 : (asynchronous ? MSG_DONTWAIT : 0)));
		if (rc < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				return UL_NETLINK_WOULDBLOCK;

			/* Failure, just stop listening for changes */
			return UL_NETLINK_ERROR;
		}

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned int)rc); nh = NLMSG_NEXT(nh, rc)) {
			struct list_head *item;

			if (nh->nlmsg_type == NLMSG_ERROR) {
				return UL_NETLINK_ERROR;
			}
			if (nh->nlmsg_type == NLMSG_DONE)
				return UL_NETLINK_DONE;
			/* Process a single part of the netlink message. */
			list_for_each(item, &ulnetlink->callbacks) {
				ul_netlink_callback_data *callback;
				ul_netlink_rc ulrc;

				callback = list_entry(item, struct ul_netlink_callback_data, list_item);
				ulrc = (callback->call)(ulnetlink, nh, callback->data);
				if (ulrc != UL_NETLINK_OK)
					return ulrc;
			}
		}
		if (!wait_for_nlmsg_done) {
			return UL_NETLINK_OK;
		}
	}
}

ul_netlink_rc ul_netlink_open(ul_netlink_data *ulnetlink, uint32_t nl_groups)
{
	struct sockaddr_nl addr = { 0, };
	int sock;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0)
		return UL_NETLINK_ERROR;
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_groups = nl_groups;
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(sock);
		return UL_NETLINK_ERROR;
	}
	ulnetlink->fd = sock;
	return UL_NETLINK_OK;
}
	
ul_netlink_rc ul_netlink_close(ul_netlink_data *ulnetlink) {
	if (close(ulnetlink->fd) == 0)
		return UL_NETLINK_OK;
	return UL_NETLINK_ERROR;
}

#ifdef TEST_PROGRAM_NETLINK
#include <stdio.h>

static ul_netlink_rc callback(ul_netlink_data *ulnetlink __attribute__((__unused__)), struct nlmsghdr *nh, ul_netlink_callback_data *callbackdata __attribute__((__unused__))) {
	char *msg_type_name;

	/* Typical callback processes only ADD and DEL corresponding to a single SET or GET.
	* SET probably never appear as a message type
	* */
	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:	msg_type_name = "RTM_NEWLINK"; break;
	case RTM_DELLINK:	msg_type_name = "RTM_DELLINK"; break;
	case RTM_GETLINK:	msg_type_name = "RTM_GETLINK"; break;
	case RTM_SETLINK:	msg_type_name = "RTM_SETLINK"; break;
	case RTM_NEWADDR:	msg_type_name = "RTM_NEWADDR"; break;
	case RTM_DELADDR:	msg_type_name = "RTM_DELADDR"; break;
	case RTM_GETADDR:	msg_type_name = "RTM_GETADDR"; break;
	case RTM_NEWROUTE:	msg_type_name = "RTM_NEWROUTE"; break;
	case RTM_DELROUTE:	msg_type_name = "RTM_DELROUTE"; break;
	case RTM_GETROUTE:	msg_type_name = "RTM_GETROUTE"; break;
	case RTM_NEWNEIGH:	msg_type_name = "RTM_NEWNEIGH"; break;
	case RTM_DELNEIGH:	msg_type_name = "RTM_DELNEIGH"; break;
	case RTM_GETNEIGH:	msg_type_name = "RTM_GETNEIGH"; break;
	case RTM_NEWRULE:	msg_type_name = "RTM_NEWRULE"; break;
	case RTM_DELRULE:	msg_type_name = "RTM_DELRULE"; break;
	case RTM_GETRULE:	msg_type_name = "RTM_GETRULE"; break;
	case RTM_NEWQDISC:	msg_type_name = "RTM_NEWQDISC"; break;
	case RTM_DELQDISC:	msg_type_name = "RTM_DELQDISC"; break;
	case RTM_GETQDISC:	msg_type_name = "RTM_GETQDISC"; break;
	case RTM_NEWTCLASS:	msg_type_name = "RTM_NEWTCLASS"; break;
	case RTM_DELTCLASS:	msg_type_name = "RTM_DELTCLASS"; break;
	case RTM_GETTCLASS:	msg_type_name = "RTM_GETTCLASS"; break;
	case RTM_NEWTFILTER:	msg_type_name = "RTM_NEWTFILTER"; break;
	case RTM_DELTFILTER:	msg_type_name = "RTM_DELTFILTER"; break;
	case RTM_GETTFILTER:	msg_type_name = "RTM_GETTFILTER"; break;
	case RTM_NEWACTION:	msg_type_name = "RTM_NEWACTION"; break;
	case RTM_DELACTION:	msg_type_name = "RTM_DELACTION"; break;
	case RTM_GETACTION:	msg_type_name = "RTM_GETACTION"; break;
	case RTM_NEWPREFIX:	msg_type_name = "RTM_NEWPREFIX"; break;
	case RTM_GETMULTICAST:	msg_type_name = "RTM_GETMULTICAST"; break;
	case RTM_GETANYCAST:	msg_type_name = "RTM_GETANYCAST"; break;
	case RTM_NEWNEIGHTBL:	msg_type_name = "RTM_NEWNEIGHTBL"; break;
	case RTM_GETNEIGHTBL:	msg_type_name = "RTM_GETNEIGHTBL"; break;
	case RTM_SETNEIGHTBL:	msg_type_name = "RTM_SETNEIGHTBL"; break;
	case RTM_NEWNDUSEROPT:	msg_type_name = "RTM_NEWNDUSEROPT"; break;
	case RTM_NEWADDRLABEL:	msg_type_name = "RTM_NEWADDRLABEL"; break;
	case RTM_DELADDRLABEL:	msg_type_name = "RTM_DELADDRLABEL"; break;
	case RTM_GETADDRLABEL:	msg_type_name = "RTM_GETADDRLABEL"; break;
	case RTM_GETDCB:	msg_type_name = "RTM_GETDCB"; break;
	case RTM_SETDCB:	msg_type_name = "RTM_SETDCB"; break;
	case RTM_NEWNETCONF:	msg_type_name = "RTM_NEWNETCONF"; break;
	case RTM_DELNETCONF:	msg_type_name = "RTM_DELNETCONF"; break;
	case RTM_GETNETCONF:	msg_type_name = "RTM_GETNETCONF"; break;
	case RTM_NEWMDB:	msg_type_name = "RTM_NEWMDB"; break;
	case RTM_DELMDB:	msg_type_name = "RTM_DELMDB"; break;
	case RTM_GETMDB:	msg_type_name = "RTM_GETMDB"; break;
	case RTM_NEWNSID:	msg_type_name = "RTM_NEWNSID"; break;
	case RTM_DELNSID:	msg_type_name = "RTM_DELNSID"; break;
	case RTM_GETNSID:	msg_type_name = "RTM_GETNSID"; break;
	case RTM_NEWSTATS:	msg_type_name = "RTM_NEWSTATS"; break;
	case RTM_GETSTATS:	msg_type_name = "RTM_GETSTATS"; break;
	case RTM_SETSTATS:	msg_type_name = "RTM_SETSTATS"; break;
	case RTM_NEWCACHEREPORT: msg_type_name = "RTM_NEWCACHEREPORT"; break;
	case RTM_NEWCHAIN:	msg_type_name = "RTM_NEWCHAIN"; break;
	case RTM_DELCHAIN:	msg_type_name = "RTM_DELCHAIN"; break;
	case RTM_GETCHAIN:	msg_type_name = "RTM_GETCHAIN"; break;
	case RTM_NEWNEXTHOP:	msg_type_name = "RTM_NEWNEXTHOP"; break;
	case RTM_DELNEXTHOP:	msg_type_name = "RTM_DELNEXTHOP"; break;
	case RTM_GETNEXTHOP:	msg_type_name = "RTM_GETNEXTHOP"; break;
	case RTM_NEWLINKPROP:	msg_type_name = "RTM_NEWLINKPROP"; break;
	case RTM_DELLINKPROP:	msg_type_name = "RTM_DELLINKPROP"; break;
	case RTM_GETLINKPROP:	msg_type_name = "RTM_GETLINKPROP"; break;
	case RTM_NEWNVLAN:	msg_type_name = "RTM_NEWVLAN"; break;
	case RTM_DELVLAN:	msg_type_name = "RTM_DELVLAN"; break;
	case RTM_GETVLAN:	msg_type_name = "RTM_GETVLAN"; break;
	case RTM_NEWNEXTHOPBUCKET: msg_type_name = "RTM_NEWNEXTHOPBUCKET"; break;
	case RTM_DELNEXTHOPBUCKET: msg_type_name = "RTM_DELNEXTHOPBUCKET"; break;
	case RTM_GETNEXTHOPBUCKET: msg_type_name = "RTM_GETNEXTHOPBUCKET"; break;
	case RTM_NEWTUNNEL:	msg_type_name = "RTM_NEWTUNNEL"; break;
	case RTM_DELTUNNEL:	msg_type_name = "RTM_DELTUNNEL"; break;
	case RTM_GETTUNNEL:	msg_type_name = "RTM_GETTUNNEL"; break;
	default: {
		/* The example needs update from linux/rtnetlink.h */
		asprintf(&msg_type_name, "unknown type %d", nh->nlmsg_type);
		break;
	}}
	printf("Got netlink message: type %s, length %d\n", msg_type_name, nh->nlmsg_len);
	return UL_NETLINK_OK;
}

int main(int argc __attribute__((__unused__)), char *argv[] __attribute__((__unused__)))
{
	int rc = 1;
	ul_netlink_rc ulrc;
	ul_netlink_data ulnetlink;
	ul_netlink_callback_data ulcallbackdata = {
		.call = callback
	};

	ul_netlink_init(&ulnetlink);
	ul_netlink_callback_add(&ulnetlink, &ulcallbackdata);

	if (ul_netlink_open(&ulnetlink, 0) != UL_NETLINK_OK)
		return 1;
	if (ul_netlink_dump_request(&ulnetlink, RTM_GETADDR) != UL_NETLINK_OK)
		goto error;
	if (ul_netlink_process(&ulnetlink, false, true) != UL_NETLINK_DONE)
		goto error;
	puts("RTM_GETADDR dump finished.");
	if (ul_netlink_dump_request(&ulnetlink, RTM_GETLINK) != UL_NETLINK_OK)
		goto error;
	if (ul_netlink_process(&ulnetlink, false, true) != UL_NETLINK_DONE)
		goto error;
	puts("RTM_GETLINK dump finished.");
	puts("Going to monitor mode.");
	if (ul_netlink_close(&ulnetlink) != UL_NETLINK_OK)
		goto error;
	if (ul_netlink_open(&ulnetlink, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR) != UL_NETLINK_OK)
		goto error;
	/* In this example UL_NETLINK_ABORT never appears, as callback does not use it. */
	ulrc = ul_netlink_process(&ulnetlink, false, true);
	if (ulrc == UL_NETLINK_OK || ulrc == UL_NETLINK_ABORT)
		rc = 0;
error:
	if (ul_netlink_close(&ulnetlink) !=  UL_NETLINK_OK)
		rc = 1;
	return rc;
}
#endif /* TEST_PROGRAM_NETLINK */
