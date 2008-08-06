/**
 * @file qq_network.c
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

#include "cipher.h"
#include "debug.h"
#include "internal.h"

#ifdef _WIN32
#define random rand
#define srandom srand
#endif

#include "buddy_info.h"
#include "buddy_list.h"
#include "buddy_opt.h"
#include "buddy_status.h"
#include "group_free.h"
#include "char_conv.h"
#include "crypt.h"
#include "group_network.h"
#include "header_info.h"
#include "keep_alive.h"
#include "im.h"
#include "login_logout.h"
#include "packet_parse.h"
#include "qq_network.h"
#include "sendqueue.h"
#include "sys_msg.h"
#include "utils.h"

typedef struct _packet_before_login packet_before_login;

struct _packet_before_login {
	guint8 *buf;
	gint len;
};

/* These functions are used only in development phase */
/*
   static void _qq_show_socket(gchar *desc, gint fd) {
   struct sockaddr_in sin;
   socklen_t len = sizeof(sin);
   getsockname(fd, (struct sockaddr *)&sin, &len);
   purple_debug(PURPLE_DEBUG_INFO, desc, "%s:%d\n",
   inet_ntoa(sin.sin_addr), g_ntohs(sin.sin_port));
   }
   */

/* QQ 2003iii uses double MD5 for the pwkey to get the session key */
static guint8 *encrypt_account_password(const gchar *pwd)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;

	guchar pwkey_tmp[QQ_KEY_LENGTH];

	cipher = purple_ciphers_find_cipher("md5");
	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar *) pwd, strlen(pwd));
	purple_cipher_context_digest(context, sizeof(pwkey_tmp), pwkey_tmp, NULL);
	purple_cipher_context_destroy(context);
	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, pwkey_tmp, QQ_KEY_LENGTH);
	purple_cipher_context_digest(context, sizeof(pwkey_tmp), pwkey_tmp, NULL);
	purple_cipher_context_destroy(context);

	return g_memdup(pwkey_tmp, QQ_KEY_LENGTH);
}

/* default process, decrypt and dump */
static void packet_process_unknow(guint8 *buf, gint buf_len, guint16 cmd, guint16 seq, PurpleConnection *gc)
{
	qq_data *qd;
	guint8 *data;
	gchar *msg_utf8 = NULL;
	gint len;

	g_return_if_fail(buf != NULL && buf_len != 0);

	qd = (qq_data *) gc->proto_data;
	len = buf_len;
	data = g_newa(guint8, len);

	qq_show_packet("Processing unknown packet", buf, len);
	if (qq_decrypt(buf, buf_len, qd->session_key, data, &len)) {
		qq_hex_dump(PURPLE_DEBUG_WARNING, "QQ",
				data, len,
				">>> [%d] %s -> [default] decrypt and dump",
				seq, qq_get_cmd_desc(cmd));
		msg_utf8 = try_dump_as_gbk(data, len);
		if (msg_utf8) {
			g_free(msg_utf8);
		}
	} else {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Fail decrypt packet with default process\n");
	}
}

/* check whether one sequence number is duplicated or not
 * return TRUE if it is duplicated, otherwise FALSE */
static gboolean check_packet_set_window(guint16 seq, PurpleConnection *gc)
{
	qq_data *qd;
	guint8 *byte, mask;

	qd = (qq_data *) gc->proto_data;
	byte = &(qd->window[seq / 8]);
	mask = (1 << (seq % 8));

	if ((*byte) & mask)
		return TRUE;	/* check mask */
	(*byte) |= mask;
	return FALSE;		/* set mask */
}

/* process the incoming packet from qq_pending */
static void packet_process(guint8 *buf, gint buf_len, PurpleConnection *gc)
{
	qq_data *qd;
	gpointer trans;
	gint bytes_notread, bytes_expected, bytes;
	guint16 buf_len_read;	/* two bytes in the begining of TCP packet */
	packet_before_login *b4_packet;
	struct {
		guint8 header_tag;
		guint16 source_tag;
		guint16 cmd;
		guint16 seq;		/* can be ack_seq or send_seq, depends on cmd */
	} header;

	g_return_if_fail(buf != NULL && buf_len > 0);

	qd = (qq_data *) gc->proto_data;
	bytes_expected = qd->use_tcp ? QQ_TCP_HEADER_LENGTH : QQ_UDP_HEADER_LENGTH;

	if (buf_len < bytes_expected) {
		qq_hex_dump(PURPLE_DEBUG_ERROR, "QQ",
				buf, buf_len,
				"Received packet is too short, dump and drop");
		return;
	}

	/* initialize */
	bytes = 0;
	/* QQ TCP packet returns first 2 bytes the length of this packet */
	if (qd->use_tcp) {
		bytes += qq_get16(&buf_len_read, buf + bytes);
		if (buf_len_read != buf_len) {	/* wrong */
			purple_debug
				(PURPLE_DEBUG_ERROR,
				 "QQ",
				 "TCP read %d bytes, header says %d bytes, use header anyway\n", buf_len, buf_len_read);
			buf_len = buf_len_read;	/* we believe header is more accurate */
		}
	}

	/* now goes the normal QQ packet as UDP packet */
	bytes += qq_get8(&header.header_tag, buf + bytes);
	bytes += qq_get16(&header.source_tag, buf + bytes);
	bytes += qq_get16(&header.cmd, buf + bytes);
	bytes += qq_get16(&header.seq, buf + bytes);

	if (bytes != bytes_expected) {	/* read error */
		purple_debug(PURPLE_DEBUG_ERROR, "QQ",
				"Fail reading packet header, expect %d bytes, read %d bytes\n", 
				bytes_expected, bytes);
		return;
	}

	if ((buf[buf_len - 1] != QQ_PACKET_TAIL) || (header.header_tag != QQ_PACKET_TAG)) {
		qq_hex_dump(PURPLE_DEBUG_ERROR, "QQ",
			buf, buf_len,
			"Unknown QQ proctocol, dump and drop");
		return;
	}

	if (QQ_DEBUG)
		purple_debug(PURPLE_DEBUG_INFO, "QQ",
				"==> [%05d] %s, from (%s)\n",
				header.seq, qq_get_cmd_desc(header.cmd), qq_get_source_str(header.source_tag));

	if (header.cmd != QQ_CMD_LOGIN && header.cmd != QQ_CMD_REQUEST_LOGIN_TOKEN) {
		if (!qd->logged_in) {	/* packets before login */
			b4_packet = g_new0(packet_before_login, 1);
			/* must duplicate, buffer will be freed after exiting this function */
			b4_packet->buf = g_memdup(buf, buf_len);
			b4_packet->len = buf_len;
			if (qd->before_login_packets == NULL)
				qd->before_login_packets = g_queue_new();
			g_queue_push_head(qd->before_login_packets, b4_packet);
			return;	/* do not process it now */
		} else if (!g_queue_is_empty(qd->before_login_packets)) {
			/* logged_in, but we have packets before login */
			b4_packet = (packet_before_login *)
			g_queue_pop_head(qd->before_login_packets);
			packet_process(b4_packet->buf, b4_packet->len, gc);
			/* in fact this is a recursive call,  
			 * all packets before login will be processed before goes on */
			g_free(b4_packet->buf);	/* the buf is duplicated, need to be freed */
			g_free(b4_packet);
		}
	}

	/* this is the length of all the encrypted data (also remove tail tag */
	bytes_notread = buf_len - bytes - 1;

	/* whether it is an ack */
	switch (header.cmd) {
		case QQ_CMD_RECV_IM:
		case QQ_CMD_RECV_MSG_SYS:
		case QQ_CMD_RECV_MSG_FRIEND_CHANGE_STATUS:
			/* server intiated packet, we need to send ack and check duplicaion 
			 * this must be put after processing b4_packet
			 * as these packets will be passed in twice */
			if (check_packet_set_window(header.seq, gc)) {
				purple_debug(PURPLE_DEBUG_WARNING,
						"QQ", "dup [%05d] %s, discard...\n", header.seq, qq_get_cmd_desc(header.cmd));
				return;
			}
			break;
		default:{	/* ack packet, we need to update sendqueue */
				/* we do not check duplication for server ack */
				trans = qq_trans_find(qd, header.seq);
				if (trans != NULL) {
					qq_trans_remove(qd, trans);
				}
				if (QQ_DEBUG)
					purple_debug(PURPLE_DEBUG_INFO, "QQ",
							"ack [%05d] %s, remove from sendqueue\n",
							header.seq, qq_get_cmd_desc(header.cmd));
			}
	}

	/* now process the packet */
	switch (header.cmd) {
		case QQ_CMD_KEEP_ALIVE:
			qq_process_keep_alive_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_UPDATE_INFO:
			qq_process_modify_info_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_ADD_FRIEND_WO_AUTH:
			qq_process_add_buddy_reply(buf + bytes, bytes_notread, header.seq, gc);
			break;
		case QQ_CMD_DEL_FRIEND:
			qq_process_remove_buddy_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_REMOVE_SELF:
			qq_process_remove_self_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_BUDDY_AUTH:
			qq_process_add_buddy_auth_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_GET_USER_INFO:
			qq_process_get_info_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_CHANGE_ONLINE_STATUS:
			qq_process_change_status_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_SEND_IM:
			qq_process_send_im_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_RECV_IM:
			qq_process_recv_im(buf + bytes, bytes_notread, header.seq, gc);
			break;
		case QQ_CMD_LOGIN:
			qq_process_login_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_GET_FRIENDS_LIST:
			qq_process_get_buddies_list_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_GET_FRIENDS_ONLINE:
			qq_process_get_buddies_online_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_GROUP_CMD:
			qq_process_group_cmd_reply(buf + bytes, bytes_notread, header.seq, gc);
			break;
		case QQ_CMD_GET_ALL_LIST_WITH_GROUP:
			qq_process_get_all_list_with_group_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_GET_LEVEL:
			qq_process_get_level_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_REQUEST_LOGIN_TOKEN:
			qq_process_request_login_token_reply(buf + bytes, bytes_notread, gc);
			break;
		case QQ_CMD_RECV_MSG_SYS:
			qq_process_msg_sys(buf + bytes, bytes_notread, header.seq, gc);
			break;
		case QQ_CMD_RECV_MSG_FRIEND_CHANGE_STATUS:
			qq_process_friend_change_status(buf + bytes, bytes_notread, gc);
			break;
		default:
			packet_process_unknow(buf + bytes, bytes_notread, header.cmd, header.seq, gc);
			break;
	}
}

static void tcp_can_write(gpointer data, gint source, PurpleInputCondition cond)
{
}

static void tcp_pending(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc;
	qq_data *qd;
	guint8 *buf;
	gint len;

	gc = (PurpleConnection *) data;

	if(cond != PURPLE_INPUT_READ) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Socket error"));
		return;
	}

	qd = (qq_data *) gc->proto_data;
	buf = g_newa(guint8, MAX_PACKET_SIZE);

	/* here we have UDP proxy suppport */
	len = read(qd->fd, buf, MAX_PACKET_SIZE);
	if (len <= 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to read from socket"));
		return;
	}
	
	packet_process(buf, len, gc);
}

static void udp_pending(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc;
	qq_data *qd;
	guint8 *buf;
	gint len;

	gc = (PurpleConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	if(cond != PURPLE_INPUT_READ) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Socket error"));
		return;
	}

	qd = (qq_data *) gc->proto_data;
	g_return_if_fail(qd->fd >= 0);
	
	buf = g_newa(guint8, MAX_PACKET_SIZE);

	/* here we have UDP proxy suppport */
	len = read(qd->fd, buf, MAX_PACKET_SIZE);
	if (len <= 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to read from socket"));
		return;
	}

	packet_process(buf, len, gc);
}

static gboolean trans_timeout(gpointer data)
{
	PurpleConnection *gc;
	qq_data *qd;
	guint8 *buf;
	gint len = 0;
	guint16 cmd;
	gint retries = 0;
	int index;
	
	gc = (PurpleConnection *) data;
	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, TRUE);

	qd = (qq_data *) gc->proto_data;
	
	index = 0;
	buf = g_newa(guint8, MAX_PACKET_SIZE);

	do {
		// purple_debug(PURPLE_DEBUG_ERROR, "QQ", "scan begin %d\n", index);
		memset(buf, 0, MAX_PACKET_SIZE);
		len = qq_trans_scan(qd, &index, buf, MAX_PACKET_SIZE, &cmd, &retries);
		if (len <= 0) {
			// qq_trans_scan meet the end
			break;
		}
		// index = -1, when get last record of transactions
		
		// purple_debug(PURPLE_DEBUG_ERROR, "QQ", "retries %d next index %d\n", retries, index);
		if (retries > 0) {
			qq_proxy_write(qd, buf, len);
			continue;
		}

		// retries <= 0
		switch (cmd) {
		case QQ_CMD_KEEP_ALIVE:
			if (qd->logged_in) {
				purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Connection lost!\n");
				purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Connection lost"));
				qd->logged_in = FALSE;
			}
			break;
		case QQ_CMD_LOGIN:
		case QQ_CMD_REQUEST_LOGIN_TOKEN:
			if (!qd->logged_in)	{
				/* cancel login progress */
				purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Login failed, no reply"));
			}
			break;
		default:
			purple_debug(PURPLE_DEBUG_WARNING, "QQ", 
				"%s packet lost.\n", qq_get_cmd_desc(cmd));
		}
	} while (index >= 0);

	return TRUE;		/* if return FALSE, timeout callback stops */
}

/* the callback function after socket is built
 * we setup the qq protocol related configuration here */
static void qq_connect_cb(gpointer data, gint source, const gchar *error_message)
{
	qq_data *qd;
	PurpleConnection *gc;
	gchar *buf;
	const gchar *passwd;

	gc = (PurpleConnection *) data;

	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		close(source);
		return;
	}

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	if (source < 0) {	/* socket returns -1 */
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_message);
		return;
	}

	qd = (qq_data *) gc->proto_data;

	/*
	   _qq_show_socket("Got login socket", source);
	   */

	/* QQ use random seq, to minimize duplicated packets */
	srandom(time(NULL));
	qd->send_seq = random() & 0x0000ffff;
	qd->fd = source;
	qd->logged_in = FALSE;
	qd->channel = 1;
	qd->uid = strtol(purple_account_get_username(purple_connection_get_account(gc)), NULL, 10);

	/* now generate md5 processed passwd */
	passwd = purple_account_get_password(purple_connection_get_account(gc));
	g_return_if_fail(qd->pwkey == NULL);
	qd->pwkey = encrypt_account_password(passwd);

	g_return_if_fail(qd->resend_timeout == 0);
	/* call trans_timeout every 5 seconds */
	qd->resend_timeout = purple_timeout_add(5000, trans_timeout, gc);
	
	gc->inpa = purple_input_add(qd->fd, PURPLE_INPUT_READ, udp_pending, gc);

	/* Update the login progress status display */
	buf = g_strdup_printf("Login as %d", qd->uid);
	purple_connection_update_progress(gc, buf, 1, QQ_CONNECT_STEPS);
	g_free(buf);

	qq_send_packet_request_login_token(gc);
}

static void udp_can_write(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc;
	qq_data *qd;
	socklen_t len;
	int error=0, ret;

	gc = (PurpleConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;


	purple_debug_info("proxy", "Connected.\n");

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
	len = sizeof(error);
	ret = getsockopt(source, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret == 0 && error == EINPROGRESS)
		return; /* we'll be called again later */
		
	purple_input_remove(qd->tx_handle);
	qd->tx_handle = 0;
	if (ret < 0 || error != 0) {
		if(ret != 0) 
			error = errno;

		close(source);

		purple_debug_error("proxy", "getsockopt SO_ERROR check: %s\n", g_strerror(error));

		qq_connect_cb(gc, -1, _("Unable to connect"));
		return;
	}

	qq_connect_cb(gc, source, NULL);
}

static void udp_host_resolved(GSList *hosts, gpointer data, const char *error_message) {
	PurpleConnection *gc;
	qq_data *qd;
	struct sockaddr server_addr;
	int addr_size;
	gint fd = -1;
	int flags;

	gc = (PurpleConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;

	// udp_query_data must be set as NULL.
	// Otherwise purple_dnsquery_destroy in qq_disconnect cause glib double free error
	qd->udp_query_data = NULL;

	if (!hosts || !hosts->data) {
		purple_connection_error_reason(gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Couldn't resolve host"));
		return;
	}

	addr_size = GPOINTER_TO_INT(hosts->data);
	hosts = g_slist_remove(hosts, hosts->data);
	memcpy(&server_addr, hosts->data, addr_size);
	g_free(hosts->data);
	
	hosts = g_slist_remove(hosts, hosts->data);
	while(hosts) {
		hosts = g_slist_remove(hosts, hosts->data);
		g_free(hosts->data);
		hosts = g_slist_remove(hosts, hosts->data);
	}

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", 
				"Unable to create socket: %s\n", g_strerror(errno));
		return;
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
	if (connect(fd, &server_addr, addr_size) >= 0) {
		purple_debug(PURPLE_DEBUG_INFO, "QQ", "Connected.\n");
		flags = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
		qq_connect_cb(gc, fd, NULL);
		return;
	}
	
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
			qd->tx_handle = purple_input_add(fd, PURPLE_INPUT_WRITE, udp_can_write, gc);
			return;
		}

	purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Connection failed: %d\n", g_strerror(errno));
	close(fd);
}

/* establish a generic QQ connection 
 * TCP/UDP, and direct/redirected */
void qq_connect(PurpleAccount *account, const gchar *hostname, guint16 port, 
		gboolean use_tcp)
{
	PurpleConnection *gc;
	qq_data *qd;

	g_return_if_fail(hostname != NULL);
	g_return_if_fail(port > 0);

	gc = purple_account_get_connection(account);
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;

	qd->fd = -1;
	qd->tx_handle = 0;
	
	qd->before_login_packets = g_queue_new();

	g_return_if_fail(qd->real_hostname == NULL);
	qd->real_hostname = g_strdup(hostname);
	qd->real_port = port;

	/* QQ connection via UDP/TCP. 
	* Now use Purple proxy function to provide TCP proxy support,
	* and qq_udp_proxy.c to add UDP proxy support (thanks henry) */
	if(qd->use_tcp) {

		/* TODO: is there a good default grow size? */
		qd->tcp_txbuf = purple_circ_buffer_new(0);

   		purple_debug(PURPLE_DEBUG_INFO, "QQ", "TCP Connect to %s:%d\n",
   			qd->real_hostname, qd->real_port);
		if (purple_proxy_connect(NULL, account,
				qd->real_hostname, qd->real_port, qq_connect_cb, gc) == NULL) {
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to connect."));
		}
		return;
	}
	
	purple_debug(PURPLE_DEBUG_INFO, "QQ", "UDP Connect to %s:%d\n",
		qd->real_hostname, qd->real_port);

	g_return_if_fail(qd->udp_query_data == NULL);
	qd->udp_query_data = purple_dnsquery_a(qd->real_hostname, qd->real_port,
		udp_host_resolved, gc);
	if (qd->udp_query_data == NULL) {
		purple_connection_error_reason(qd->gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Could not resolve hostname"));
	}
}

/* clean up qq_data structure and all its components
 * always used before a redirectly connection */
void qq_disconnect(PurpleConnection *gc)
{
	qq_data *qd;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	/* finish  all I/O */
	if (qd->fd >= 0 && qd->logged_in) {
		qq_send_packet_logout(gc);
	}

	if (qd->resend_timeout > 0) {
		purple_timeout_remove(qd->resend_timeout);
		qd->resend_timeout = 0;
	}

	if (gc->inpa > 0) {
		purple_input_remove(gc->inpa);
		gc->inpa = 0;
	}

	if (qd->fd >= 0) {
		close(qd->fd);
		qd->fd = -1;
	}
	if(qd->tcp_txbuf != NULL) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "destroy tcp_txbuf\n");
		purple_circ_buffer_destroy(qd->tcp_txbuf);
	}
	if (qd->tx_handle) {
		purple_input_remove(qd->tx_handle);
		qd->tx_handle = 0;
	}

	if (qd->udp_query_data != NULL) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "destroy udp_query_data\n");
		purple_dnsquery_destroy(qd->udp_query_data);
		qd->udp_query_data = NULL;
	}

	purple_debug(PURPLE_DEBUG_ERROR, "QQ", "destroy transactions\n");
	qq_trans_remove_all(qd);
	
	if (qd->real_hostname) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "free real_hostname\n");
		g_free(qd->real_hostname);
		qd->real_hostname = NULL;
	}
	if (qd->inikey) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "free inikey\n");
		g_free(qd->inikey);
		qd->inikey = NULL;
	}
	if (qd->pwkey) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "free pwkey\n");
		g_free(qd->pwkey);
		qd->pwkey = NULL;
	}
	if (qd->session_key) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "free session_key\n");
		g_free(qd->session_key);
		qd->session_key = NULL;
	}
	if (qd->session_md5) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "free session_md5\n");
		g_free(qd->session_md5);
		qd->session_md5 = NULL;
	}
	if (qd->my_ip) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "free my_ip\n");
		g_free(qd->my_ip);
		qd->my_ip = NULL;
	}

	qq_b4_packets_free(qd);
	qq_group_packets_free(qd);
	qq_group_free_all(qd);
	qq_add_buddy_request_free(qd);
	qq_info_query_free(qd);
	qq_buddies_list_free(gc->account, qd);
}

/* send packet with proxy support */
gint qq_proxy_write(qq_data *qd, guint8 *data, gint len)
{
	gint ret;

	g_return_val_if_fail(qd != NULL && qd->fd >= 0 && data != NULL && len > 0, -1);

	purple_debug(PURPLE_DEBUG_INFO, "QQ", "Send %d bytes to socket %d\n", len, qd->fd);
	/* TCP sock5 may be processed twice
	 * so we need to check qd->use_tcp as well */
	if ((!qd->use_tcp)) {	/* UDP */
		errno = 0;
		ret = send(qd->fd, data, len, 0);
	} else {
		errno = 0;
		ret = send(qd->fd, data, len, 0);
	}

	if (ret < 0 && errno == EAGAIN)
		return ret;
	else if (ret < 0) {
		/* TODO: what to do here - do we really have to disconnect? */
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Send failed: %d, %s\n", errno, g_strerror(errno));
		//purple_connection_error_reason(qd->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, g_strerror(errno));
	}
	return ret;
}

/* clean up the packets before login */
void qq_b4_packets_free(qq_data *qd)
{
	packet_before_login *b4_packet;
	g_return_if_fail(qd != NULL);
	/* now clean up my own data structures */
	if (qd->before_login_packets != NULL) {
		while (NULL != (b4_packet = g_queue_pop_tail(qd->before_login_packets))) {
			g_free(b4_packet->buf);
			g_free(b4_packet);
		}
		g_queue_free(qd->before_login_packets);
	}
}

/* create qq packet header with given sequence
 * return the number of bytes in header if succeeds
 * return -1 if there is any error */
gint _create_packet_head_seq(guint8 *buf, PurpleConnection *gc, 
		guint16 cmd, gboolean is_auto_seq, guint16 *seq)
{
	qq_data *qd;
	gint bytes_expected, bytes;

	g_return_val_if_fail(buf != NULL, -1);

	qd = (qq_data *) gc->proto_data;
	if (is_auto_seq)
		*seq = ++(qd->send_seq);

	bytes = 0;
	bytes_expected = (qd->use_tcp) ? QQ_TCP_HEADER_LENGTH : QQ_UDP_HEADER_LENGTH;

	/* QQ TCP packet has two bytes in the begining defines packet length
	 * so I leave room here for size */
	if (qd->use_tcp) {
		bytes += qq_put16(buf + bytes, 0x0000);
	}
	/* now comes the normal QQ packet as UDP */
	bytes += qq_put8(buf + bytes, QQ_PACKET_TAG);
	bytes += qq_put16(buf + bytes, QQ_CLIENT);
	bytes += qq_put16(buf + bytes, cmd);
	bytes += qq_put16(buf + bytes, *seq);

	if (bytes != bytes_expected) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ",
				"Fail create qq header, expect %d bytes, written %d bytes\n", bytes_expected, bytes);
		bytes = -1;
	}
	return bytes;
}

/* for those need ack and resend no ack feed back from server
 * return number of bytes written to the socket,
 * return -1 if there is any error */
gint qq_send_packet(PurpleConnection *gc, guint8 *buf, gint len, guint16 cmd)
{
	qq_data *qd;
	gint bytes_sent = 0;

	qd = (qq_data *) gc->proto_data;

	if (qd->use_tcp) {
		if (len > MAX_PACKET_SIZE) {
			purple_debug(PURPLE_DEBUG_ERROR, "QQ",
					"xxx [%05d] %s, %d bytes is too large, do not send\n",
					qq_get_cmd_desc(cmd), qd->send_seq, len);
			return -1;
		} else {	/* I update the len for TCP packet */
			/* set TCP packet length
			 * _create_packet_head_seq has reserved two byte for storing pkt length, ccpaging */
			qq_put16(buf, len);
		}
	}

	/* bytes actually returned */
	bytes_sent = qq_proxy_write(qd, buf, len);

	/* put to queue, for matching server reply usage */
	qq_trans_append(qd, buf, len, cmd);

	/* for debugging, s3e, 20070622 */
	qq_show_packet("QQ_SEND_PACKET", buf, len);
	purple_debug(PURPLE_DEBUG_INFO, "QQ", "%d bytes written to the socket.\n", bytes_sent);

	return bytes_sent;
}

/* send the packet generated with the given cmd and data
 * return the number of bytes sent to socket if succeeds
 * return -1 if there is any error */
gint qq_send_cmd(PurpleConnection *gc, guint16 cmd,
		gboolean is_auto_seq, guint16 seq, gboolean need_ack, guint8 *data, gint len)
{
	qq_data *qd;
	guint8 *buf, *encrypted_data;
	guint16 seq_ret;
	gint encrypted_len, bytes, bytes_header, bytes_expected, bytes_sent;

	qd = (qq_data *) gc->proto_data;
	g_return_val_if_fail(qd->session_key != NULL, -1);

	buf = g_newa(guint8, MAX_PACKET_SIZE);
	encrypted_len = len + 16;	/* at most 16 bytes more */
	encrypted_data = g_newa(guint8, encrypted_len);

	qq_encrypt(data, len, qd->session_key, encrypted_data, &encrypted_len);

	seq_ret = seq;

	bytes = 0;
	bytes += _create_packet_head_seq(buf + bytes, gc, cmd, is_auto_seq, &seq_ret);
	if (bytes <= 0) {
		/* _create_packet_head_seq warned before */
		return -1;
	}
	
	bytes_header = bytes;
	bytes_expected = 4 + encrypted_len + 1;
	bytes += qq_put32(buf + bytes, (guint32) qd->uid);
	bytes += qq_putdata(buf + bytes, encrypted_data, encrypted_len);
	bytes += qq_put8(buf + bytes, QQ_PACKET_TAIL);

	if ((bytes - bytes_header) != bytes_expected) {	/* bad packet */
		purple_debug(PURPLE_DEBUG_ERROR, "QQ",
				"Fail creating packet, expect %d bytes, written %d bytes\n",
				bytes_expected, bytes - bytes_header);
		return -1;
	}

	/* if it does not need ACK, we send ACK manually several times */
	if (need_ack)   /* my request, send it */
		bytes_sent = qq_send_packet(gc, buf, bytes, cmd);
	else		/* server's request, send ACK */
		bytes_sent = qq_proxy_write(qd, buf, bytes);

	if (QQ_DEBUG)
		purple_debug(PURPLE_DEBUG_INFO, "QQ",
				"<== [%05d] %s, %d bytes\n", seq_ret, qq_get_cmd_desc(cmd), bytes_sent);
	return bytes_sent;
}
