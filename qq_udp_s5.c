/**
 * @file udp_proxy_s5.c
 *
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "debug.h"
#include "dnsquery.h"
#include "proxy.h"

#include "qq.h"
#include "qq_udp_s5.h"

struct PHB {
	PurpleProxyConnectFunction callback;
	gpointer data;
	gchar *host;
	gint port;
	gint inpa;
	PurpleProxyInfo *gpi;
	PurpleAccount *account;
	gint udpsock;
	gpointer sockbuf;
};

static void qq_s5_canread_again(gpointer data, gint source, PurpleInputCondition cond)
{
	unsigned char buf[512];
	struct PHB *phb = data;
	struct sockaddr_in sin;
	int len, error;
	socklen_t errlen;
	int flags;

	purple_input_remove(phb->inpa);
	purple_debug(PURPLE_DEBUG_INFO, "socks5 proxy", "Able to read again.\n");

	len = read(source, buf, 10);
	if (len < 10) {
		purple_debug(PURPLE_DEBUG_WARNING, "socks5 proxy", "or not...\n");
		close(source);

		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

			phb->callback(phb->data, source, NULL);
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}
	if ((buf[0] != 0x05) || (buf[1] != 0x00)) {
		if ((buf[0] == 0x05) && (buf[1] < 0x09))
			purple_debug(PURPLE_DEBUG_ERROR, "socks5 proxy", "socks5 error: %x\n", buf[1]);
		else
			purple_debug(PURPLE_DEBUG_ERROR, "socks5 proxy", "Bad data.\n");
		close(source);

		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

			phb->callback(phb->data, -1, _("Unable to connect"));
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}

	sin.sin_family = AF_INET;
	memcpy(&sin.sin_addr.s_addr, buf + 4, 4);
	memcpy(&sin.sin_port, buf + 8, 2);

	if (connect(phb->udpsock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) < 0) {
		purple_debug(PURPLE_DEBUG_INFO, "s5_canread_again", "connect failed: %s\n", g_strerror(errno));
		close(phb->udpsock);
		close(source);
		g_free(phb->host);
		g_free(phb);
		return;
	}

	error = ETIMEDOUT;
	purple_debug(PURPLE_DEBUG_INFO, "QQ", "Connect didn't block\n");
	errlen = sizeof(error);
	if (getsockopt(phb->udpsock, SOL_SOCKET, SO_ERROR, &error, &errlen) < 0) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "getsockopt failed.\n");
		close(phb->udpsock);
		return;
	}
	flags = fcntl(phb->udpsock, F_GETFL);
	fcntl(phb->udpsock, F_SETFL, flags & ~O_NONBLOCK);

	if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {
		phb->callback(phb->data, phb->udpsock, NULL);
	}

	g_free(phb->host);
	g_free(phb);
}

static void qq_s5_sendconnect(gpointer data, gint source)
{
	unsigned char buf[512];
	struct PHB *phb = data;
	struct sockaddr_in sin, ctlsin;
	int port; 
	socklen_t ctllen;
	int flags;

	purple_debug(PURPLE_DEBUG_INFO, "s5_sendconnect", "remote host is %s:%d\n", phb->host, phb->port);

	buf[0] = 0x05;
	buf[1] = 0x03;		/* udp relay */
	buf[2] = 0x00;		/* reserved */
	buf[3] = 0x01;		/* address type -- ipv4 */
	memset(buf + 4, 0, 0x04);

	ctllen = sizeof(ctlsin);
	if (getsockname(source, (struct sockaddr *) &ctlsin, &ctllen) < 0) {
		purple_debug(PURPLE_DEBUG_INFO, "QQ", "getsockname: %s\n", g_strerror(errno));
		close(source);
		g_free(phb->host);
		g_free(phb);
		return;
	}

	phb->udpsock = socket(PF_INET, SOCK_DGRAM, 0);
	purple_debug(PURPLE_DEBUG_INFO, "s5_sendconnect", "UDP socket=%d\n", phb->udpsock);
	if (phb->udpsock < 0) {
		close(source);
		g_free(phb->host);
		g_free(phb);
		return;
	}

	flags = fcntl(phb->udpsock, F_GETFL);
	fcntl(phb->udpsock, F_SETFL, flags | O_NONBLOCK);

	port = g_ntohs(ctlsin.sin_port) + 1;
	while (1) {
		inet_aton("0.0.0.0", &(sin.sin_addr));
		sin.sin_family = AF_INET;
		sin.sin_port = g_htons(port);
		if (bind(phb->udpsock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
			port++;
			if (port > 65500) {
				close(source);
				g_free(phb->host);
				g_free(phb);
				return;
			}
		} else
			break;
	}

	memset(buf + 4, 0, 0x04);
	memcpy(buf + 8, &(sin.sin_port), 0x02);

	if (write(source, buf, 10) < 10) {
		close(source);
		purple_debug(PURPLE_DEBUG_INFO, "s5_sendconnect", "packet too small\n");

		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {
			phb->callback(phb->data, -1, _("Unable to connect"));
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}

	phb->inpa = purple_input_add(source, PURPLE_INPUT_READ, qq_s5_canread_again, phb);
}

static void qq_s5_readauth(gpointer data, gint source, PurpleInputCondition cond)
{
	unsigned char buf[512];
	struct PHB *phb = data;

	purple_input_remove(phb->inpa);
	purple_debug(PURPLE_DEBUG_INFO, "socks5 proxy", "Got auth response.\n");

	if (read(source, buf, 2) < 2) {
		close(source);

		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

			phb->callback(phb->data, -1, _("Unable to connect"));
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}

	if ((buf[0] != 0x01) || (buf[1] != 0x00)) {
		close(source);

		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

			phb->callback(phb->data, -1, _("Unable to connect"));
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}

	qq_s5_sendconnect(phb, source);
}

static void qq_s5_canread(gpointer data, gint source, PurpleInputCondition cond)
{
	unsigned char buf[512];
	struct PHB *phb;
	int ret;

	phb = data;

	purple_input_remove(phb->inpa);
	purple_debug(PURPLE_DEBUG_INFO, "socks5 proxy", "Able to read.\n");

	ret = read(source, buf, 2);
	if (ret < 2) {
		purple_debug(PURPLE_DEBUG_INFO, "s5_canread", "packet smaller than 2 octet\n");
		close(source);

		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

			phb->callback(phb->data, -1, _("Unable to connect"));
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}

	if ((buf[0] != 0x05) || (buf[1] == 0xff)) {
		purple_debug(PURPLE_DEBUG_INFO, "s5_canread", "unsupport\n");
		close(source);

		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

			phb->callback(phb->data, -1, _("Unable to connect"));
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}

	if (buf[1] == 0x02) {
		unsigned int i, j;

		i = strlen(purple_proxy_info_get_username(phb->gpi));
		j = strlen(purple_proxy_info_get_password(phb->gpi));

		buf[0] = 0x01;	/* version 1 */
		buf[1] = i;
		memcpy(buf + 2, purple_proxy_info_get_username(phb->gpi), i);
		buf[2 + i] = j;
		memcpy(buf + 2 + i + 1, purple_proxy_info_get_password(phb->gpi), j);

		if (write(source, buf, 3 + i + j) < 3 + i + j) {
			close(source);

			if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

				phb->callback(phb->data, -1, _("Unable to connect"));
			}

			g_free(phb->host);
			g_free(phb);
			return;
		}

		phb->inpa = purple_input_add(source, PURPLE_INPUT_READ, qq_s5_readauth, phb);
	} else {
		purple_debug(PURPLE_DEBUG_INFO, "s5_canread", "calling s5_sendconnect\n");
		qq_s5_sendconnect(phb, source);
	}
}

static void qq_s5_create_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	unsigned char buf[512];
	int i;
	struct PHB *phb = data;
	socklen_t len;
	int error = ETIMEDOUT;
	int flags;

	purple_debug(PURPLE_DEBUG_INFO, "socks5 proxy", "Connected.\n");

	if (phb->inpa > 0)
		purple_input_remove(phb->inpa);

	len = sizeof(error);
	if (getsockopt(source, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
		purple_debug(PURPLE_DEBUG_INFO, "getsockopt", "%s\n", g_strerror(errno));
		close(source);
		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

			phb->callback(phb->data, -1, _("Unable to connect"));
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}
	flags = fcntl(source, F_GETFL);
	fcntl(source, F_SETFL, flags & ~O_NONBLOCK);

	i = 0;
	buf[0] = 0x05;		/* SOCKS version 5 */

	if (purple_proxy_info_get_username(phb->gpi) != NULL) {
		buf[1] = 0x02;	/* two methods */
		buf[2] = 0x00;	/* no authentication */
		buf[3] = 0x02;	/* username/password authentication */
		i = 4;
	} else {
		buf[1] = 0x01;
		buf[2] = 0x00;
		i = 3;
	}

	if (write(source, buf, i) < i) {
		purple_debug(PURPLE_DEBUG_INFO, "write", "%s\n", g_strerror(errno));
		purple_debug(PURPLE_DEBUG_ERROR, "socks5 proxy", "Unable to write\n");
		close(source);

		if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

			phb->callback(phb->data, -1, _("Unable to connect"));
		}

		g_free(phb->host);
		g_free(phb);
		return;
	}

	phb->inpa = purple_input_add(source, PURPLE_INPUT_READ, qq_s5_canread, phb);
}

static void qq_udp_create_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	struct PHB *phb = data;
	socklen_t len;
	int error=0, ret;

	purple_debug_info("proxy", "Connected.\n");

	len = sizeof(error);

	/*
	 * getsockopt after a non-blocking connect returns -1 if something is
	 * really messed up (bad descriptor, usually). Otherwise, it returns 0 and
	 * error holds what connect would have returned if it blocked until now.
	 * Thus, error == 0 is success, error == EINPROGRESS means "try again",
	 * and anything else is a real error.
	 *
	 * (error == EINPROGRESS can happen after a select because the kernel can
	 * be overly optimistic sometimes. select is just a hint that you might be
	 * able to do something.)
	 */
	ret = getsockopt(source, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret == 0 && error == EINPROGRESS)
		return; /* we'll be called again later */
	if (ret < 0 || error != 0) {
		if(ret!=0) 
			error = errno;
		close(source);
		purple_input_remove(phb->inpa);

		purple_debug_error("proxy", "getsockopt SO_ERROR check: %s\n", g_strerror(error));

		phb->callback(phb->data, -1, _("Unable to connect"));
		return;
	}

	purple_input_remove(phb->inpa);

	if (phb->account == NULL || purple_account_get_connection(phb->account) != NULL) {

		phb->callback(phb->data, source, NULL);
	}

	g_free(phb->host);
	g_free(phb);
}

static gboolean qq_get_hosts(GSList *hosts, struct sockaddr_in *addr, gint *addr_size)
{
	if (!hosts || !hosts->data)
		return FALSE;

	*addr_size = GPOINTER_TO_INT(hosts->data);

	hosts = g_slist_remove(hosts, hosts->data);
	memcpy(addr, hosts->data, *addr_size);
	g_free(hosts->data);
	hosts = g_slist_remove(hosts, hosts->data);
	while(hosts) {
		hosts = g_slist_remove(hosts, hosts->data);
		g_free(hosts->data);
		hosts = g_slist_remove(hosts, hosts->data);
	}

	return TRUE;
}

static gint qq_s5_create(struct PHB *phb, struct sockaddr *addr, socklen_t addrlen)
{
	gint fd;
	int flags;

	purple_debug(PURPLE_DEBUG_INFO, "QQ",
		   "Connecting to %s:%d via %s:%d using SOCKS5\n",
		   phb->host, phb->port, purple_proxy_info_get_host(phb->gpi), purple_proxy_info_get_port(phb->gpi));

	if ((fd = socket(addr->sa_family, SOCK_STREAM, 0)) < 0)
		return -1;

	purple_debug(PURPLE_DEBUG_INFO, "QQ", "proxy_sock5 return fd=%d\n", fd);

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (connect(fd, addr, addrlen) < 0) {
		if ((errno == EINPROGRESS) || (errno == EINTR)) {
			purple_debug(PURPLE_DEBUG_WARNING, "QQ", "Connect in asynchronous mode.\n");
			phb->inpa = purple_input_add(fd, PURPLE_INPUT_WRITE, qq_s5_create_cb, phb);
		} else {
			close(fd);
			return -1;
		}
	} else {
		purple_debug(PURPLE_DEBUG_MISC, "QQ", "Connect in blocking mode.\n");
		flags = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
		qq_s5_create_cb(phb, fd, PURPLE_INPUT_WRITE);
	}

	return fd;
}

static void qq_dnsquery_socks5_cb(GSList *hosts, gpointer data, const char *error_message)
{
	struct PHB *phb = (struct PHB *) data;
	struct sockaddr_in addr;
	gint addr_size, ret = -1;

	if(qq_get_hosts(hosts, &addr, &addr_size))
		ret = qq_s5_create(phb, (struct sockaddr *) &addr, addr_size);

	if (ret < 0) {
		phb->callback(phb->data, -1, _("Unable to connect"));
		g_free(phb->host);
		g_free(phb);
	}
}

/* returns -1 if fails, otherwise returns the file handle */
static gint qq_udp_create(struct PHB *phb, struct sockaddr *addr, socklen_t addrlen)
{
	gint fd = -1;
	int flags;

	purple_debug(PURPLE_DEBUG_INFO, "QQ", "Using UDP without proxy\n");
	fd = socket(PF_INET, SOCK_DGRAM, 0);

	if (fd < 0) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ Redirect", 
				"Unable to create socket: %s\n", g_strerror(errno));
		return -1;
	}

	/* we use non-blocking mode to speed up connection */
	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	/* From Unix-socket-FAQ: http://www.faqs.org/faqs/unix-faq/socket/
	 *
	 * If a UDP socket is unconnected, which is the normal state after a
	 * bind() call, then send() or write() are not allowed, since no
	 * destination is available; only sendto() can be used to send data.
	 *   
	 * Calling connect() on the socket simply records the specified address
	 * and port number as being the desired communications partner. That
	 * means that send() or write() are now allowed; they use the destination
	 * address and port given on the connect call as the destination of packets.
	 */
	if (connect(fd, addr, addrlen) < 0) {
		/* [EINPROGRESS]
		 *    The socket is marked as non-blocking and the connection cannot be 
		 *    completed immediately. It is possible to select for completion by 
		 *    selecting the socket for writing.
		 * [EINTR]
		 *    A signal interrupted the call. 
		 *    The connection is established asynchronously.
		 */
		if ((errno == EINPROGRESS) || (errno == EINTR)) {
			purple_debug(PURPLE_DEBUG_WARNING, "QQ", "Connect in asynchronous mode.\n");
			phb->inpa = purple_input_add(fd, PURPLE_INPUT_WRITE, qq_udp_create_cb, phb);
		} else {
			purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Connection failed: %d\n", g_strerror(errno));
			close(fd);
			return -1;
		}		/* if errno */
	} else {		/* connect returns 0 */
		purple_debug(PURPLE_DEBUG_INFO, "QQ", "Connected.\n");
		flags = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
		phb->callback(phb->data, fd, NULL);
	}

	return fd;
}

static void qq_dnsquery_cb(GSList *hosts, gpointer data, const char *error_message)
{
	struct PHB *phb = (struct PHB *) data;
	PurpleConnection *gc = (PurpleConnection *) phb->data;
	qq_data *qd = (qq_data *) gc->proto_data;
	struct sockaddr_in addr;
	gint addr_size, ret = -1;

	if(qq_get_hosts(hosts, &addr, &addr_size)) {
		switch (purple_proxy_info_get_type(phb->gpi)) {
			case PURPLE_PROXY_NONE:
				ret = qq_udp_create(phb, (struct sockaddr *) &addr, addr_size);
				break;
			case PURPLE_PROXY_SOCKS5:
				ret = 0;
				if (purple_proxy_info_get_host(phb->gpi) == NULL || 
						purple_proxy_info_get_port(phb->gpi) == 0) {
					purple_debug(PURPLE_DEBUG_ERROR, "QQ", 
							"Use of socks5 proxy selected but host or port info doesn't exist.\n");
					ret = -1;
				} else {
					/* as the destination is always QQ server during the session, 
					 * we can set dest_sin here, instead of qq_s5_canread_again */
					memcpy(&qd->dest_sin, &addr, addr_size);
					if (purple_dnsquery_a(purple_proxy_info_get_host(phb->gpi),
								purple_proxy_info_get_port(phb->gpi),
								qq_dnsquery_socks5_cb, phb) == NULL)
						ret = -1;
				}
				break;
			default:
				purple_debug(PURPLE_DEBUG_WARNING, "QQ", 
						"Proxy type %i is unsupported, not using a proxy.\n",
						purple_proxy_info_get_type(phb->gpi));
				ret = qq_udp_create(phb, (struct sockaddr *) &addr, addr_size);
		}
	}

	if (ret < 0) {
		phb->callback(gc, -1, _("Unable to connect"));
		g_free(phb->host);
		g_free(phb);
	}
}

/* returns -1 if dns lookup fails, otherwise returns 0 */
gint qq_connect_by_udp(PurpleAccount *account,
		const gchar *server, guint16 port, 
		void callback(gpointer, gint, const gchar *error_message), 
		PurpleConnection *gc)
{
	PurpleProxyInfo *info;
	struct PHB *phb;
	qq_data *qd = (qq_data *) gc->proto_data;

	g_return_val_if_fail(gc != NULL && qd != NULL, -1);

	info = purple_proxy_get_setup(account);

	phb = g_new0(struct PHB, 1);
	phb->host = g_strdup(server);
	phb->port = port;
	phb->account = account;
	phb->gpi = info;
	phb->callback = callback;
	phb->data = gc;
	qd->proxy_type = purple_proxy_info_get_type(phb->gpi);

	purple_debug(PURPLE_DEBUG_INFO, "QQ", "Choosing proxy type %d\n", 
			purple_proxy_info_get_type(phb->gpi));

	if (purple_dnsquery_a(server, port, qq_dnsquery_cb, phb) == NULL) {
		phb->callback(gc, -1, _("Unable to connect"));
		g_free(phb->host);
		g_free(phb);
		return -1;
	} else {
		return 0;
	}
}

