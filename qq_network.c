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

#include "buddy_info.h"
#include "group_info.h"
#include "group_free.h"
#include "qq_crypt.h"
#include "header_info.h"
#include "qq_base.h"
#include "buddy_list.h"
#include "packet_parse.h"
#include "qq_network.h"
#include "qq_trans.h"
#include "utils.h"
#include "qq_process.h"

#define QQ_DEFAULT_PORT					8000

/* set QQ_CONNECT_MAX to 1, when test reconnecting */
#define QQ_CONNECT_MAX						3
#define QQ_CONNECT_INTERVAL			2
#define QQ_CONNECT_CHECK					5
#define QQ_KEEP_ALIVE_INTERVAL		60
#define QQ_TRANS_INTERVAL				10

gboolean connect_to_server(PurpleConnection *gc, gchar *server, gint port);

static qq_connection *connection_find(qq_data *qd, int fd) {
	qq_connection *ret = NULL;
	GSList *entry = qd->openconns;
	while(entry) {
		ret = entry->data;
		if(ret->fd == fd) return ret;
		entry = entry->next;
	}
	return NULL;
}

static qq_connection *connection_create(qq_data *qd, int fd) {
	qq_connection *ret = g_new0(qq_connection, 1);
	ret->fd = fd;
	qd->openconns = g_slist_append(qd->openconns, ret);
	return ret;
}

static void connection_remove(qq_data *qd, int fd) {
	qq_connection *conn = connection_find(qd, fd);
	qd->openconns = g_slist_remove(qd->openconns, conn);

	g_return_if_fail( conn != NULL );

	purple_debug_info("QQ", "Close socket %d\n", conn->fd);
	if(conn->input_handler > 0)	purple_input_remove(conn->input_handler);
	if(conn->can_write_handler > 0)	purple_input_remove(conn->can_write_handler);

	if (conn->fd >= 0)	close(conn->fd);
	if(conn->tcp_txbuf != NULL) 	purple_circ_buffer_destroy(conn->tcp_txbuf);
	if (conn->tcp_rxqueue != NULL)	g_free(conn->tcp_rxqueue);

	g_free(conn);
}

static void connection_free_all(qq_data *qd) {
	qq_connection *ret = NULL;
	GSList *entry = qd->openconns;
	while(entry) {
		ret = entry->data;
		connection_remove(qd, ret->fd);
		entry = qd->openconns;
	}
}
static gboolean set_new_server(qq_data *qd)
{
	gint count;
	gint index;
	GList *it = NULL;

 	g_return_val_if_fail(qd != NULL, FALSE);

	if (qd->servers == NULL) {
		purple_debug_info("QQ", "Server list is NULL\n");
		return FALSE;
	}

	/* remove server used before */
	if (qd->curr_server != NULL) {
		purple_debug_info("QQ",
			"Remove current [%s] from server list\n", qd->curr_server);
   		qd->servers = g_list_remove(qd->servers, qd->curr_server);
   		qd->curr_server = NULL;
    }

	count = g_list_length(qd->servers);
	purple_debug_info("QQ", "Server list has %d\n", count);
	if (count <= 0) {
		/* no server left, disconnect when result is false */
		qd->servers = NULL;
		return FALSE;
	}

	/* get new server */
	index  = rand() % count;
	it = g_list_nth(qd->servers, index);
    qd->curr_server = it->data;		/* do not free server_name */
    if (qd->curr_server == NULL || strlen(qd->curr_server) <= 0 ) {
		purple_debug_info("QQ", "Server name at %d is empty\n", index);
		return FALSE;
	}

	purple_debug_info("QQ", "set new server to %s\n", qd->curr_server);
	return TRUE;
}

static gint packet_get_header(guint8 *header_tag,  guint16 *source_tag,
	guint16 *cmd, guint16 *seq, guint8 *buf)
{
	gint bytes = 0;
	bytes += qq_get8(header_tag, buf + bytes);
	bytes += qq_get16(source_tag, buf + bytes);
	bytes += qq_get16(cmd, buf + bytes);
	bytes += qq_get16(seq, buf + bytes);
	return bytes;
}

static gboolean connect_check(gpointer data)
{
	PurpleConnection *gc = (PurpleConnection *) data;
	qq_data *qd;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, FALSE);
	qd = (qq_data *) gc->proto_data;

	if (qd->connect_watcher > 0) {
		purple_timeout_remove(qd->connect_watcher);
		qd->connect_watcher = 0;
	}

	if (qd->fd >= 0 && qd->token != NULL && qd->token_len >= 0) {
		purple_debug_info("QQ", "Connect ok\n");
		return FALSE;
	}

	qd->connect_watcher = purple_timeout_add_seconds(0, qq_connect_later, gc);
	return FALSE;
}

/* Warning: qq_connect_later destory all connection
 *  Any function should be care of use qq_data after call this function
 *  Please conside tcp_pending and udp_pending */
gboolean qq_connect_later(gpointer data)
{
	PurpleConnection *gc = (PurpleConnection *) data;
	qq_data *qd;
	char *server;
	int port;
	gchar **segments;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, FALSE);
	qd = (qq_data *) gc->proto_data;

	if (qd->check_watcher > 0) {
		purple_timeout_remove(qd->check_watcher);
		qd->check_watcher = 0;
	}
	qq_disconnect(gc);

	if (qd->redirect_ip.s_addr != 0) {
		/* redirect to new server */
		server = g_strdup_printf("%s:%d", inet_ntoa(qd->redirect_ip), qd->redirect_port);
		qd->servers = g_list_append(qd->servers, server);
		qd->curr_server = server;

		qd->redirect_ip.s_addr = 0;
		qd->redirect_port = 0;
		qd->connect_retry = QQ_CONNECT_MAX;
	}

	if (qd->curr_server == NULL || strlen (qd->curr_server) == 0 || qd->connect_retry <= 0) {
		if ( set_new_server(qd) != TRUE) {
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					_("Failed to connect all servers"));
			return FALSE;
		}
		qd->connect_retry = QQ_CONNECT_MAX;
	}

	segments = g_strsplit_set(qd->curr_server, ":", 0);
	server = g_strdup(segments[0]);
	port = atoi(segments[1]);
	if (port <= 0) {
		purple_debug_info("QQ", "Port not define in %s\n", qd->curr_server);
		port = QQ_DEFAULT_PORT;
	}
	g_strfreev(segments);

	qd->connect_retry--;
	if ( !connect_to_server(gc, server, port) ) {
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to connect."));
	}

	qd->check_watcher = purple_timeout_add_seconds(QQ_CONNECT_CHECK, connect_check, gc);
	return FALSE;	/* timeout callback stops */
}

/* process the incoming packet from qq_pending */
static gboolean packet_process(PurpleConnection *gc, guint8 *buf, gint buf_len)
{
	qq_data *qd;
	gint bytes, bytes_not_read;

	gboolean prev_update_status;

	guint8 header_tag;
	guint16 source_tag;
	guint16 cmd;
	guint16 seq;		/* May be ack_seq or send_seq, depends on cmd */
	guint8 room_cmd;
	guint32 room_id;
	gint update_class;
	guint32 ship32;

	qq_transaction *trans;

	g_return_val_if_fail(buf != NULL && buf_len > 0, TRUE);

	qd = (qq_data *) gc->proto_data;

	/* Len, header and tail tag have been checked before */
	bytes = 0;
	bytes += packet_get_header(&header_tag, &source_tag, &cmd, &seq, buf + bytes);

#if 1
		purple_debug_info("QQ", "==> [%05d] 0x%04X %s, source tag 0x%04X len %d\n",
				seq, cmd, qq_get_cmd_desc(cmd), source_tag, buf_len);
#endif
	/* this is the length of all the encrypted data (also remove tail tag) */
	bytes_not_read = buf_len - bytes - 1;

	/* ack packet, we need to update send tranactions */
	/* we do not check duplication for server ack */
	trans = qq_trans_find_rcved(gc, cmd, seq);
	if (trans == NULL) {
		/* new server command */
		qq_trans_add_server_cmd(gc, cmd, seq, buf + bytes, bytes_not_read);
		if ( qd->is_finish_update ) {
			qq_proc_cmd_server(gc, cmd, seq, buf + bytes, bytes_not_read);
		}
		return TRUE;
	}

	if (qq_trans_is_dup(trans)) {
		purple_debug_info("QQ", "dup [%05d] %s, discard...\n", seq, qq_get_cmd_desc(cmd));
		return TRUE;
	}

	if (qq_trans_is_server(trans)) {
		if ( qd->is_finish_update ) {
			qq_proc_cmd_server(gc, cmd, seq, buf + bytes, bytes_not_read);
		}
		return TRUE;
	}

	update_class = qq_trans_get_class(trans);
	ship32 = qq_trans_get_ship(trans);

	prev_update_status = qd->is_finish_update;
	switch (cmd) {
		case QQ_CMD_TOKEN:
			if (qq_process_token_reply(gc, buf + bytes, bytes_not_read) == QQ_TOKEN_REPLY_OK) {
				qq_send_packet_login(gc);
			}
			break;
		case QQ_CMD_LOGIN:
			qq_proc_cmd_login(gc, buf + bytes, bytes_not_read);
			/* check is redirect or not, and do it now */
			if (qd->redirect_ip.s_addr != 0) {
				if (qd->check_watcher > 0) {
					purple_timeout_remove(qd->check_watcher);
					qd->check_watcher = 0;
				}
				if (qd->connect_watcher > 0)	purple_timeout_remove(qd->connect_watcher);
				qd->connect_watcher = purple_timeout_add_seconds(QQ_CONNECT_INTERVAL, qq_connect_later, gc);
				return FALSE;	/* do nothing after this function and return now */
			}
			break;
		case QQ_CMD_ROOM:
			room_cmd = qq_trans_get_room_cmd(trans);
			room_id = qq_trans_get_room_id(trans);
#if 1
			purple_debug_info("QQ", "%s (0x%02X) for room %d, len %d\n",
					qq_get_room_cmd_desc(room_cmd), room_cmd, room_id, buf_len);
#endif
			qq_proc_room_cmd_reply(gc, seq, room_cmd, room_id, buf + bytes, bytes_not_read, update_class, ship32);
			break;
		default:
			qq_proc_cmd_reply(gc, cmd, seq, buf + bytes, bytes_not_read, update_class, ship32);
			break;
	}

	if (prev_update_status != qd->is_finish_update && qd->is_finish_update == TRUE) {
		/* is_login, but we have packets before login */
		qq_trans_process_before_login(gc);
		return TRUE;
	}
	return TRUE;
}

static void tcp_pending(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = (PurpleConnection *) data;
	qq_data *qd;
	qq_connection *conn;
	guint8 buf[1024];		/* set to 16 when test  tcp_rxqueue */
	gint buf_len;
	gint bytes;

	guint8 *pkt;
	guint16 pkt_len;

	gchar *error_msg;
	guint8 *jump;
	gint jump_len;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	if(cond != PURPLE_INPUT_READ) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Socket error"));
		return;
	}

	conn = connection_find(qd, source);
	g_return_if_fail(conn != NULL);

	/* test code, not using tcp_rxqueue
	memset(pkt,0, sizeof(pkt));
	buf_len = read(qd->fd, pkt, sizeof(pkt));
	if (buf_len > 2) {
		packet_process(gc, pkt + 2, buf_len - 2);
	}
	return;
	*/

	buf_len = read(source, buf, sizeof(buf));
	if (buf_len < 0) {
		if (errno == EAGAIN)
			/* No worries */
			return;

		error_msg = g_strdup_printf(_("Lost connection with server:\n%d, %s"), errno, g_strerror(errno));
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg);
		g_free(error_msg);
		return;
	} else if (buf_len == 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Server closed the connection."));
		return;
	}

	/* keep alive will be sent in 30 seconds since last_receive
	 *  QQ need a keep alive packet in every 60 seconds
	 gc->last_received = time(NULL);
	*/
	/* purple_debug_info("TCP_PENDING", "Read %d bytes, rxlen is %d\n", buf_len, conn->tcp_rxlen); */
	conn->tcp_rxqueue = g_realloc(conn->tcp_rxqueue, buf_len + conn->tcp_rxlen);
	memcpy(conn->tcp_rxqueue + conn->tcp_rxlen, buf, buf_len);
	conn->tcp_rxlen += buf_len;

	pkt = g_newa(guint8, MAX_PACKET_SIZE);
	while (PURPLE_CONNECTION_IS_VALID(gc)) {
		if (qd->openconns == NULL) {
			break;
		}
		if (conn->tcp_rxqueue == NULL) {
			conn->tcp_rxlen = 0;
			break;
		}
		if (conn->tcp_rxlen < QQ_TCP_HEADER_LENGTH) {
			break;
		}

		bytes = 0;
		bytes += qq_get16(&pkt_len, conn->tcp_rxqueue + bytes);
		if (conn->tcp_rxlen < pkt_len) {
			break;
		}

		/* purple_debug_info("TCP_PENDING", "Packet len=%d, rxlen=%d\n", pkt_len, conn->tcp_rxlen); */
		if ( pkt_len < QQ_TCP_HEADER_LENGTH
		    || *(conn->tcp_rxqueue + bytes) != QQ_PACKET_TAG
			|| *(conn->tcp_rxqueue + pkt_len - 1) != QQ_PACKET_TAIL) {
			/* HEY! This isn't even a QQ. What are you trying to pull? */
			purple_debug_warning("TCP_PENDING", "Packet error, no header or tail tag\n");

			jump = memchr(conn->tcp_rxqueue + 1, QQ_PACKET_TAIL, conn->tcp_rxlen - 1);
			if ( !jump ) {
				purple_debug_warning("TCP_PENDING", "Failed to find next tail, clear receive buffer\n");
				g_free(conn->tcp_rxqueue);
				conn->tcp_rxqueue = NULL;
				conn->tcp_rxlen = 0;
				return;
			}

			/* jump and over QQ_PACKET_TAIL */
			jump_len = (jump - conn->tcp_rxqueue) + 1;
			purple_debug_warning("TCP_PENDING", "Find next tail at %d, jump %d\n", jump_len, jump_len + 1);
			g_memmove(conn->tcp_rxqueue, jump, conn->tcp_rxlen - jump_len);
			conn->tcp_rxlen -= jump_len;
			continue;
		}

		memset(pkt, 0, MAX_PACKET_SIZE);
		g_memmove(pkt, conn->tcp_rxqueue + bytes, pkt_len - bytes);

		/* jump to next packet */
		conn->tcp_rxlen -= pkt_len;
		if (conn->tcp_rxlen) {
			/* purple_debug_info("TCP_PENDING", "shrink tcp_rxqueue to %d\n", conn->tcp_rxlen);	*/
			jump = g_memdup(conn->tcp_rxqueue + pkt_len, conn->tcp_rxlen);
			g_free(conn->tcp_rxqueue);
			conn->tcp_rxqueue = jump;
		} else {
			/* purple_debug_info("TCP_PENDING", "free tcp_rxqueue\n"); */
			g_free(conn->tcp_rxqueue);
			conn->tcp_rxqueue = NULL;
		}

		if (pkt == NULL) {
			continue;
		}
		/* packet_process may call disconnect and destory data like conn
		 * do not call packet_process before jump,
		 * break if packet_process return FALSE */
		if (packet_process(gc, pkt, pkt_len - bytes) == FALSE) {
			purple_debug_info("TCP_PENDING", "Connection has been destory\n");
			break;
		}
	}
}

static void udp_pending(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = (PurpleConnection *) data;
	qq_data *qd;
	guint8 *buf;
	gint buf_len;

	gc = (PurpleConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	if(cond != PURPLE_INPUT_READ) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Socket error"));
		return;
	}

	buf = g_newa(guint8, MAX_PACKET_SIZE);

	/* here we have UDP proxy suppport */
	buf_len = read(source, buf, MAX_PACKET_SIZE);
	if (buf_len <= 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to read from socket"));
		return;
	}

	/* keep alive will be sent in 30 seconds since last_receive
	 *  QQ need a keep alive packet in every 60 seconds
	 gc->last_received = time(NULL);
	*/

	if (buf_len < QQ_UDP_HEADER_LENGTH) {
		if (buf[0] != QQ_PACKET_TAG || buf[buf_len - 1] != QQ_PACKET_TAIL) {
			qq_hex_dump(PURPLE_DEBUG_ERROR, "UDP_PENDING",
					buf, buf_len,
					"Received packet is too short, or no header and tail tag");
			return;
		}
	}

	/* packet_process may call disconnect and destory data like conn
	 * do not call packet_process before jump,
	 * break if packet_process return FALSE */
	packet_process(gc, buf, buf_len);
}

static gint udp_send_out(PurpleConnection *gc, guint8 *data, gint data_len)
{
	qq_data *qd;
	gint ret;

	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;

#if 0
	purple_debug_info("UDP_SEND_OUT", "Send %d bytes to socket %d\n", data_len, qd->fd);
#endif

	errno = 0;
	ret = send(qd->fd, data, data_len, 0);
	if (ret < 0 && errno == EAGAIN) {
		return ret;
	}

	if (ret < 0) {
		/* TODO: what to do here - do we really have to disconnect? */
		purple_debug_error("UDP_SEND_OUT", "Send failed: %d, %s\n", errno, g_strerror(errno));
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, g_strerror(errno));
	}
	return ret;
}

static void tcp_can_write(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = (PurpleConnection *) data;
	qq_data *qd;
	qq_connection *conn;
	int ret, writelen;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	conn = connection_find(qd, source);
	g_return_if_fail(conn != NULL);

	writelen = purple_circ_buffer_get_max_read(conn->tcp_txbuf);
	if (writelen == 0) {
		purple_input_remove(conn->can_write_handler);
		conn->can_write_handler = 0;
		return;
	}

	ret = write(source, conn->tcp_txbuf->outptr, writelen);
	purple_debug_info("TCP_CAN_WRITE", "total %d bytes is sent %d\n", writelen, ret);

	if (ret < 0 && errno == EAGAIN)
		return;
	else if (ret < 0) {
		/* TODO: what to do here - do we really have to disconnect? */
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		                               _("Write Error"));
		return;
	}

	purple_circ_buffer_mark_read(conn->tcp_txbuf, ret);
}

static gint tcp_send_out(PurpleConnection *gc, guint8 *data, gint data_len)
{
	qq_data *qd;
	qq_connection *conn;
	gint ret;

	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;

	conn = connection_find(qd, qd->fd);
	g_return_val_if_fail(conn, -1);

#if 0
	purple_debug_info("TCP_SEND_OUT", "Send %d bytes to socket %d\n", data_len, qd->fd);
#endif

	if (conn->can_write_handler == 0) {
		ret = write(qd->fd, data, data_len);
	} else {
		ret = -1;
		errno = EAGAIN;
	}

	/*
	purple_debug_info("TCP_SEND_OUT",
		"Socket %d, total %d bytes is sent %d\n", qd->fd, data_len, ret);
	*/
	if (ret < 0 && errno == EAGAIN) {
		/* socket is busy, send later */
		purple_debug_info("TCP_SEND_OUT", "Socket is busy and send later\n");
		ret = 0;
	} else if (ret <= 0) {
		/* TODO: what to do here - do we really have to disconnect? */
		purple_debug_error("TCP_SEND_OUT",
			"Send to socket %d failed: %d, %s\n", qd->fd, errno, g_strerror(errno));
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, g_strerror(errno));
		return ret;
	}

	if (ret < data_len) {
		purple_debug_info("TCP_SEND_OUT",
			"Add %d bytes to buffer\n", data_len - ret);
		if (conn->can_write_handler == 0) {
			conn->can_write_handler = purple_input_add(qd->fd, PURPLE_INPUT_WRITE, tcp_can_write, gc);
		}
		purple_circ_buffer_append(conn->tcp_txbuf, data + ret, data_len - ret);
	}
	return ret;
}

static gboolean network_timeout(gpointer data)
{
	PurpleConnection *gc = (PurpleConnection *) data;
	qq_data *qd;
	gboolean is_lost_conn;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, TRUE);
	qd = (qq_data *) gc->proto_data;

	is_lost_conn = qq_trans_scan(gc);
	if (is_lost_conn) {
		purple_connection_error_reason(gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Connection lost"));
		return TRUE;
	}

	if ( !qd->is_login ) {
		return TRUE;
	}

	qd->itv_count.keep_alive--;
	if (qd->itv_count.keep_alive <= 0) {
		qd->itv_count.keep_alive = qd->itv_config.keep_alive;
		qq_send_packet_keep_alive(gc);
		return TRUE;
	}

	if (qd->itv_config.update <= 0) {
		return TRUE;
	}

	qd->itv_count.update--;
	if (qd->itv_count.update <= 0) {
		qd->itv_count.update = qd->itv_config.update;
		qq_update_online(gc, 0);
		return TRUE;
	}

	return TRUE;		/* if return FALSE, timeout callback stops */
}

static void do_request_token(PurpleConnection *gc)
{
	qq_data *qd;
	gchar *conn_msg;
	const gchar *passwd;

	/* _qq_show_socket("Got login socket", source); */

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	/* QQ use random seq, to minimize duplicated packets */
	srand(time(NULL));
	qd->send_seq = rand() & 0xffff;

	qd->is_login = FALSE;
	qd->is_finish_update = FALSE;
	qd->channel = 1;
	qd->uid = strtol(purple_account_get_username(purple_connection_get_account(gc)), NULL, 10);

	/* now generate md5 processed passwd */
	passwd = purple_account_get_password(purple_connection_get_account(gc));

	/* use twice-md5 of user password as session key since QQ 2003iii */
	qq_get_md5(qd->password_twice_md5, sizeof(qd->password_twice_md5),
		(guint8 *)passwd, strlen(passwd));
	qq_get_md5(qd->password_twice_md5, sizeof(qd->password_twice_md5),
		qd->password_twice_md5, sizeof(qd->password_twice_md5));

	g_return_if_fail(qd->network_watcher == 0);
	qd->network_watcher = purple_timeout_add_seconds(qd->itv_config.resend, network_timeout, gc);

	/* Update the login progress status display */
	conn_msg = g_strdup_printf(_("Request token"));
	purple_connection_update_progress(gc, conn_msg, 2, QQ_CONNECT_STEPS);
	g_free(conn_msg);

	qq_send_packet_token(gc);
}

/* the callback function after socket is built
 * we setup the qq protocol related configuration here */
static void connect_cb(gpointer data, gint source, const gchar *error_message)
{
	PurpleConnection *gc;
	qq_data *qd;
	PurpleAccount *account ;
	qq_connection *conn;

	gc = (PurpleConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;
	account = purple_connection_get_account(gc);

	/* conn_data will be destoryed */
	qd->conn_data = NULL;

	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		purple_debug_info("QQ_CONN", "Invalid connection\n");
		close(source);
		return;
	}

	if (source < 0) {	/* socket returns -1 */
		purple_debug_info("QQ_CONN",
				"Could not establish a connection with the server:\n%s\n",
				error_message);
		if (qd->connect_watcher > 0)	purple_timeout_remove(qd->connect_watcher);
		qd->connect_watcher = purple_timeout_add_seconds(QQ_CONNECT_INTERVAL, qq_connect_later, gc);
		return;
	}

	/* _qq_show_socket("Got login socket", source); */
	qd->fd = source;
	conn = connection_create(qd, source);
	if (qd->use_tcp) {
		conn->input_handler = purple_input_add(source, PURPLE_INPUT_READ, tcp_pending, gc);
	} else {
		conn->input_handler = purple_input_add(source, PURPLE_INPUT_READ, udp_pending, gc);
	}

	do_request_token( gc );
}

gboolean connect_to_server(PurpleConnection *gc, gchar *server, gint port)
{
	PurpleAccount *account ;
	qq_data *qd;
	gchar *conn_msg;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, FALSE);
	account = purple_connection_get_account(gc);
	qd = (qq_data *) gc->proto_data;

	if (server == NULL || strlen(server) == 0 || port == 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Invalid server or port"));
		return FALSE;
	}

	conn_msg = g_strdup_printf( _("Connecting server %s, retries %d"), server, port);
	purple_connection_update_progress(gc, conn_msg, 1, QQ_CONNECT_STEPS);
	g_free(conn_msg);

	purple_debug_info("QQ", "Connect to %s:%d\n", server, port);

	if (qd->conn_data != NULL) {
		purple_proxy_connect_cancel(qd->conn_data);
		qd->conn_data = NULL;
	}
	if (qd->use_tcp) {
		qd->conn_data = purple_proxy_connect(gc, account, server, port, connect_cb, gc);
	} else {
		qd->conn_data = purple_proxy_connect_udp(gc, account, server, port, connect_cb, gc);
	}
	if ( qd->conn_data == NULL ) {
		purple_debug_error("QQ", _("Couldn't create socket"));
		return FALSE;
	}
	return TRUE;
}

/* clean up qq_data structure and all its components
 * always used before a redirectly connection */
void qq_disconnect(PurpleConnection *gc)
{
	qq_data *qd;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	purple_debug_info("QQ", "Disconnecting ...\n");

	if (qd->network_watcher > 0) {
		purple_debug_info("QQ", "Remove network watcher\n");
		purple_timeout_remove(qd->network_watcher);
		qd->network_watcher = 0;
	}

	/* finish  all I/O */
	if (qd->fd >= 0 && qd->is_login) {
		qq_send_packet_logout(gc);
	}

	/* not connected */
	if (qd->conn_data != NULL) {
		purple_debug_info("QQ", "Connect cancel\n");
		purple_proxy_connect_cancel(qd->conn_data);
		qd->conn_data = NULL;
	}
	connection_free_all(qd);
	qd->fd = -1;

	qq_trans_remove_all(gc);

	if (qd->token) {
		purple_debug_info("QQ", "free token\n");
		g_free(qd->token);
		qd->token = NULL;
		qd->token_len = 0;
	}
	memset(qd->inikey, 0, sizeof(qd->inikey));
	memset(qd->password_twice_md5, 0, sizeof(qd->password_twice_md5));
	memset(qd->session_key, 0, sizeof(qd->session_key));
	memset(qd->session_md5, 0, sizeof(qd->session_md5));

	qd->my_ip.s_addr = 0;

	qq_group_free_all(qd);
	qq_add_buddy_request_free(qd);
	qq_info_query_free(qd);
	qq_buddies_list_free(gc->account, qd);
}

static gint packet_encap(qq_data *qd, guint8 *buf, gint maxlen, guint16 cmd, guint16 seq,
	guint8 *data, gint data_len)
{
	gint bytes = 0;
	g_return_val_if_fail(qd != NULL && buf != NULL && maxlen > 0, -1);
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	/* QQ TCP packet has two bytes in the begining defines packet length
	 * so leave room here to store packet size */
	if (qd->use_tcp) {
		bytes += qq_put16(buf + bytes, 0x0000);
	}
	/* now comes the normal QQ packet as UDP */
	bytes += qq_put8(buf + bytes, QQ_PACKET_TAG);
	bytes += qq_put16(buf + bytes, QQ_CLIENT);
	bytes += qq_put16(buf + bytes, cmd);

	bytes += qq_put16(buf + bytes, seq);

	bytes += qq_put32(buf + bytes, qd->uid);
	bytes += qq_putdata(buf + bytes, data, data_len);
	bytes += qq_put8(buf + bytes, QQ_PACKET_TAIL);

	/* set TCP packet length at begin of the packet */
	if (qd->use_tcp) {
		qq_put16(buf, bytes);
	}

	return bytes;
}

/* data has been encrypted before */
static gint packet_send_out(PurpleConnection *gc, guint16 cmd, guint16 seq, guint8 *data, gint data_len)
{
	qq_data *qd;
	guint8 *buf;
	gint buf_len;
	gint bytes_sent;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *)gc->proto_data;
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	buf = g_newa(guint8, MAX_PACKET_SIZE);
	memset(buf, 0, MAX_PACKET_SIZE);
	buf_len = packet_encap(qd, buf, MAX_PACKET_SIZE, cmd, seq, data, data_len);
	if (buf_len <= 0) {
		return -1;
	}

	if (qd->use_tcp) {
		bytes_sent = tcp_send_out(gc, buf, buf_len);
	} else {
		bytes_sent = udp_send_out(gc, buf, buf_len);
	}

	return bytes_sent;
}

gint qq_send_cmd_encrypted(PurpleConnection *gc, guint16 cmd, guint16 seq,
	guint8 *data, gint data_len, gboolean need_ack)
{
	gint send_len;

#if 1
		purple_debug_info("QQ", "<== [%05d], %s(0x%04X), datalen %d\n",
				seq, qq_get_cmd_desc(cmd), cmd, data_len);
#endif

	send_len = packet_send_out(gc, cmd, seq, data, data_len);
	if (need_ack)  {
		qq_trans_add_client_cmd(gc, cmd, seq, data, data_len, 0, 0);
	}
	return send_len;
}

/* Encrypt data with session_key, and send packet out */
static gint send_cmd_detail(PurpleConnection *gc, guint16 cmd, guint16 seq,
	guint8 *data, gint data_len, gboolean need_ack, gint update_class, guint32 ship32)
{
	qq_data *qd;
	guint8 *encrypted_data;
	gint encrypted_len;
	gint bytes_sent;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *)gc->proto_data;
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	/* at most 16 bytes more */
	encrypted_data = g_newa(guint8, data_len + 16);
	encrypted_len = qq_encrypt(encrypted_data, data, data_len, qd->session_key);
	if (encrypted_len < 16) {
		purple_debug_error("QQ_ENCRYPT", "Error len %d: [%05d] 0x%04X %s\n",
				encrypted_len, seq, cmd, qq_get_cmd_desc(cmd));
		return -1;
	}

	bytes_sent = packet_send_out(gc, cmd, seq, encrypted_data, encrypted_len);

	if (need_ack)  {
		qq_trans_add_client_cmd(gc, cmd, seq, encrypted_data, encrypted_len, update_class, ship32);
	}
	return bytes_sent;
}

gint qq_send_cmd_mess(PurpleConnection *gc, guint16 cmd, guint8 *data, gint data_len,
		gint update_class, guint32 ship32)
{
	qq_data *qd;
	guint16 seq;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	seq = ++qd->send_seq;
#if 1
		purple_debug_info("QQ", "<== [%05d], %s(0x%04X), datalen %d\n",
				seq, qq_get_cmd_desc(cmd), cmd, data_len);
#endif
	return send_cmd_detail(gc, cmd, seq, data, data_len, TRUE, update_class, ship32);
}

/* set seq and need_ack, then call send_cmd_detail */
gint qq_send_cmd(PurpleConnection *gc, guint16 cmd, guint8 *data, gint data_len)
{
	qq_data *qd;
	guint16 seq;
	gboolean need_ack;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	if (cmd != QQ_CMD_LOGOUT) {
		seq = ++qd->send_seq;
		need_ack = TRUE;
	} else {
		seq = 0xFFFF;
		need_ack = FALSE;
	}
#if 1
		purple_debug_info("QQ", "<== [%05d], %s(0x%04X), datalen %d\n",
				seq, qq_get_cmd_desc(cmd), cmd, data_len);
#endif
	return send_cmd_detail(gc, cmd, seq, data, data_len, need_ack, 0, 0);
}

/* set seq and need_ack, then call send_cmd_detail */
gint qq_send_server_reply(PurpleConnection *gc, guint16 cmd, guint16 seq, guint8 *data, gint data_len)
{
#if 1
		purple_debug_info("QQ", "<== [SRV-%05d], %s(0x%04X), datalen %d\n",
				seq, qq_get_cmd_desc(cmd), cmd, data_len);
#endif
	return send_cmd_detail(gc, cmd, seq, data, data_len, FALSE, 0, 0);
}

static gint send_room_cmd(PurpleConnection *gc, guint8 room_cmd, guint32 room_id,
		guint8 *data, gint data_len, gint update_class, guint32 ship32)
{
	qq_data *qd;
	guint8 *buf;
	gint buf_len;
	guint8 *encrypted_data;
	gint encrypted_len;
	gint bytes_sent;
	guint16 seq;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;

	buf = g_newa(guint8, MAX_PACKET_SIZE);
	memset(buf, 0, MAX_PACKET_SIZE);

	/* encap room_cmd and room id to buf*/
	buf_len = 0;
	buf_len += qq_put8(buf + buf_len, room_cmd);
	if (room_id != 0) {
		/* id 0 is for QQ Demo Group, now there are not existed*/
		buf_len += qq_put32(buf + buf_len, room_id);
	}
	if (data != NULL && data_len > 0) {
		buf_len += qq_putdata(buf + buf_len, data, data_len);
	}

	qd->send_seq++;
	seq = qd->send_seq;

	/* Encrypt to encrypted_data with session_key */
	/* at most 16 bytes more */
	encrypted_data = g_newa(guint8, buf_len + 16);
	encrypted_len = qq_encrypt(encrypted_data, buf, buf_len, qd->session_key);
	if (encrypted_len < 16) {
		purple_debug_error("QQ_ENCRYPT", "Error len %d: [%05d] %s (0x%02X)\n",
				encrypted_len, seq, qq_get_room_cmd_desc(room_cmd), room_cmd);
		return -1;
	}

	bytes_sent = packet_send_out(gc, QQ_CMD_ROOM, seq, encrypted_data, encrypted_len);
#if 1
		/* qq_show_packet("QQ_SEND_DATA", buf, buf_len); */
		purple_debug_info("QQ",
				"<== [%05d], %s (0x%02X) to room %d, datalen %d\n",
				seq, qq_get_room_cmd_desc(room_cmd), room_cmd, room_id, buf_len);
#endif

	qq_trans_add_room_cmd(gc, seq, room_cmd, room_id, buf, buf_len, update_class, ship32);
	return bytes_sent;
}

gint qq_send_room_cmd_mess(PurpleConnection *gc, guint8 room_cmd, guint32 room_id,
		guint8 *data, gint data_len, gint update_class, guint32 ship32)
{
	return send_room_cmd(gc, room_cmd, room_id, data, data_len, update_class, ship32);
}

gint qq_send_room_cmd(PurpleConnection *gc, guint8 room_cmd, guint32 room_id,
		guint8 *data, gint data_len)
{
	return send_room_cmd(gc, room_cmd, room_id, data, data_len, 0, 0);
}

gint qq_send_room_cmd_noid(PurpleConnection *gc, guint8 room_cmd,
		guint8 *data, gint data_len)
{
	return send_room_cmd(gc, room_cmd, 0, data, data_len, 0, 0);
}

gint qq_send_room_cmd_only(PurpleConnection *gc, guint8 room_cmd, guint32 room_id)
{
	g_return_val_if_fail(room_cmd > 0 && room_id > 0, -1);
	return send_room_cmd(gc, room_cmd, room_id, NULL, 0, 0, 0);
}
