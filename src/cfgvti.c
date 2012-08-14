/*
 * cfgvti.c		"cfgvti".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *		Workaround to configure VTI till we iproute changes upstream.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/sockios.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <libnfnetlink/libnfnetlink.h>

static void usage(void) __attribute__((noreturn));

enum {
	ACT_INVALID =	0,
	ACT_ADD =	1,
};

#ifndef  IFLA_VTI_UNSPEC
/* VTI-mode i_flags */
#define VTI_ISVTI 0x0001

enum {
        IFLA_VTI_UNSPEC,
        IFLA_VTI_LINK,
        IFLA_VTI_IKEY,
        IFLA_VTI_OKEY,
        IFLA_VTI_LOCAL,
        IFLA_VTI_REMOTE,
        __IFLA_VTI_MAX,
};

#define IFLA_VTI_MAX    (__IFLA_VTI_MAX - 1)
#endif /* IFLA_VTI_UNSPEC */

#define NEXT_ARG() do { argv++; if (--argc <= 0) usage(); } while(0)

void usage(void)
{
	fprintf(stderr, "Usage: cfgvti add name NAME key 'mark' remote IPADDR local IPADDR\n");
	exit(-1);
}

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
          int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n",maxlen);
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}


static int rtnl_sendmsg(int fd, struct nlmsghdr *n)
{
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = (void *)n,
		.iov_len = n->nlmsg_len,
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];
	int status;
	struct nlmsghdr *h;
	uint32_t seq;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	seq = n->nlmsg_seq = random();

	n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(fd, &msg, 0);
	if (status < 0) {
		fprintf(stderr, "Cannot talk to rtnetlink (%d)\n", status);
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	iov.iov_base = buf;

	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			fprintf(stderr, "rtnetlink receive error %s (%d)\n",
				strerror(errno), errno);
			return -1;
		}
		if (status == 0) {
			fprintf(stderr, "EOF on netlink\n");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			fprintf(stderr, "sender address length == %d\n", msg.msg_namelen);
			return -1;
		}
		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "Truncated message\n");
					return -1;
				}
		                fprintf(stderr, "!!!malformed message: len=%d\n", len);
		                return -1;
			}

			if (nladdr.nl_pid != 0 ||
			    h->nlmsg_pid !=  getpid() ||
			    h->nlmsg_seq != seq) {
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
				if (l < sizeof(struct nlmsgerr)) {
					fprintf(stderr, "ERROR truncated\n");
				} else {
					errno = -err->error;
					if (errno == 0)
						return 0;
					fprintf(stderr, "RTNETLINK answers %s (%d)\n", strerror(errno), errno);
				}
				return -1;
			}

			fprintf(stderr, "Unexpected reply!!!\n");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
	return 0;
}

static int action_add (int fd, char *name, struct in_addr *saddr, struct in_addr *daddr, uint32_t key)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[1024];
	} req;
	int len;
	struct rtattr *data, *linkinfo;
	char type[] = "vti";

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_type = RTM_NEWLINK;
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	req.i.ifi_family = AF_UNSPEC;

	/* Name */
	len = strlen(name) + 1;
	if (len > IFNAMSIZ)
		return -1;
	addattr_l(&req.n, 1024, IFLA_IFNAME, name, len);

	/* Type */
	linkinfo = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, 1024, IFLA_LINKINFO, NULL, 0);
	addattr_l(&req.n, 1024, IFLA_INFO_KIND, type, strlen(type));

	/* Data */
	data = NLMSG_TAIL(&req.n);
	addattr_l(&req.n, 1024, IFLA_INFO_DATA, NULL, 0);
	addattr_l(&req.n, 1024, IFLA_VTI_IKEY, &key, sizeof(key));
	addattr_l(&req.n, 1024, IFLA_VTI_OKEY, &key, sizeof(key));
	addattr_l(&req.n, 1024, IFLA_VTI_LOCAL, saddr, 4);
	addattr_l(&req.n, 1024, IFLA_VTI_REMOTE, daddr, 4);
	data->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)data;

	linkinfo->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)linkinfo;

	return(rtnl_sendmsg(fd, &req.n));
}


int main (int argc, char *argv[])
{
	char *name = NULL;
	uint32_t mark = 0, action = ACT_INVALID;
	struct in_addr saddr = {.s_addr = 0 }, daddr = { .s_addr = 0 };
	int rtnl_soc, rval = 0;

	argc--; argv++;

	while (argc > 0) {
		if (strcmp(*argv, "add") == 0) {
			if (action != ACT_INVALID) {
				fprintf(stderr, "multiple actions given\n");
				usage();
			}
			action = ACT_ADD;
		} else if (strcmp(*argv, "name") == 0) {
			NEXT_ARG();
			name = *argv;
		} else if (strcmp(*argv, "del") == 0) {
			if (action != ACT_INVALID) {
				fprintf(stderr, "multiple actions given\n");
				usage();
			}
			fprintf(stderr, "Invalid action \"del\"\n");
			exit(-1);
		} else if (strcmp(*argv, "key") == 0) {
			uint32_t uval;

			NEXT_ARG();
			if (strchr(*argv, '.')) {
				struct in_addr tmp;
				if (!inet_aton(*argv, &tmp)) {
					fprintf(stderr, "Invalid value for \"key\" %s\n",
						*argv);
					exit(-1);
				}
				uval = htonl(tmp.s_addr);
			} else {
				errno = 0;
				uval = strtoul(*argv, 0, 0);
				if (errno) {
					fprintf(stderr,
						"Invalid \"mark\" %s\n", *argv);
					exit(-1);
				}
				uval = htonl(uval);
			}
			mark = uval;
		} else if (strcmp(*argv, "remote") == 0) {
			NEXT_ARG();
			if (!inet_aton(*argv, &daddr)) {
				fprintf(stderr, "Invalid \"remote\" address %s\n",
					*argv);
				exit(-1);
			}
		} else if (strcmp(*argv, "local") == 0) {
			NEXT_ARG();
			if (!inet_aton(*argv, &saddr)) {
				fprintf(stderr, "Invalid \"remote\" address %s\n",
					*argv);
				exit(-1);
			}
		} else
			usage();
		argc--; argv++;
	}
	if (action == ACT_INVALID)
		usage();

	/* open the rtnetlink socket */
	rtnl_soc = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (rtnl_soc < 0) {
		fprintf(stderr, "Failed to open the rt_netlink socket. %s\n", strerror(errno));
		exit (-1);
	}

	switch(action) {
		case ACT_ADD:
			if (name == NULL || mark <= 0 || saddr.s_addr == 0 || daddr.s_addr == 0) {
				fprintf(stderr, "Invalid values for \"add\"\n");
				usage();
			}
			rval = action_add(rtnl_soc, name, &saddr, &daddr, mark);
		break;

		default:
			usage();
		break;
	}
	close(rtnl_soc);
	
	exit (rval);
}
