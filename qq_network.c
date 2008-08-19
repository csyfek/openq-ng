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

/* set QQ_RECONNECT_MAX to 1, when test reconnecting */
#define QQ_RECONNECT_MAX					4
#define QQ_RECONNECT_INTERVAL		3000
#define QQ_KEEP_ALIVE_INTERVAL		60000
#define QQ_TRANS_INTERVAL				10000

void tcp_connect_cb(gpointer data, gint source, const gchar *error_message);
void tcp_redirect_connect_cb(gpointer data, gint source, const gchar *error_message);
void udp_host_resolved(GSList *hosts, gpointer data, const char *error_message);
void do_request_token(PurpleConnection *gc);

static qq_connection *connection_find(PurpleConnection *gc, int fd)
{
	qq_data *qd = (qq_data *) gc->proto_data;
	qq_connection *ret = NULL;
	GList *entry = qd->openconns;
	while(entry) {
		ret = entry->data;
		if(ret->fd == fd) {
			return ret;
		}
		entry = entry->next;
	}
	return NULL;
}

static qq_connection *connection_create(PurpleConnection *gc)
{
	qq_data *qd;
	qq_connection *ret = g_new0(qq_connection, 1);
	
	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, NULL);
	qd = (qq_data *) gc->proto_data;

	memset(ret, 0, sizeof(qq_connection));
	ret->gc = gc;
	ret->fd = -1;
	qd->openconns = g_list_append(qd->openconns, ret);
	return ret;
}

static void connection_free(PurpleConnection *gc, qq_connection*conn)
{
	qq_data *qd = (qq_data *) gc->proto_data;

	g_return_if_fail( conn != NULL );

	qd->openconns = g_list_remove(qd->openconns, conn);

	purple_debug_info("QQ", "Close socket %d\n", conn->fd);

	if(conn->input_handler) purple_input_remove(conn->input_handler);
	if(conn->can_write_handler) purple_input_remove(conn->can_write_handler);

	if (conn->conn_data != NULL) {
		purple_debug_info("QQ", "purple_proxy_connect_cancel on %d\n", conn->fd);
		purple_proxy_connect_cancel(conn->conn_data);
		conn->conn_data = NULL;
		conn->fd = -1;
	}
	if (conn->dns_data != NULL) {
		purple_debug_info("QQ", "purple_dnsquery_destroy on %d\n", conn->fd);
		purple_dnsquery_destroy(conn->dns_data);
		conn->dns_data = NULL;
		conn->fd = -1;
	}
	if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}

	if(conn->tcp_txbuf != NULL) {
		purple_circ_buffer_destroy(conn->tcp_txbuf);
		conn->tcp_txbuf = NULL;
	}

	if (conn->tcp_rxqueue != NULL) {
		g_free(conn->tcp_rxqueue);
		conn->tcp_rxqueue = NULL;
		conn->tcp_rxlen = 0;
	}

	g_free(conn);
}

static void connection_free_all(PurpleConnection *gc)
{
	qq_data *qd = (qq_data *) gc->proto_data;
	qq_connection *conn = NULL;
	int count = 0;
	
	purple_debug_info("QQ", "destroy all connections ...\n");
	while(qd->openconns != NULL) {
		conn = (qq_connection *) (qd->openconns->data);
		connection_free(gc, conn);
		count++;
	}
	purple_debug_info("QQ", "destroy all %d connections\n", count);
}

static gboolean connect_to_server(PurpleConnection *gc, gchar *server, gint port)
{
	PurpleAccount *account ;
	qq_data *qd;
	gchar *conn_msg;
	qq_connection *conn;
	
	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, FALSE);
	account = purple_connection_get_account(gc);
	qd = (qq_data *) gc->proto_data;

	conn_msg = g_strdup_printf( _("Connecting server %s, retries %d"), server, port);
	purple_connection_update_progress(gc, conn_msg, 1, QQ_CONNECT_STEPS);
	g_free(conn_msg);

	conn = connection_create( gc );
	if(qd->use_tcp) {
   		purple_debug_info("QQ", "TCP Connect to %s:%d\n", server, port);

		conn->conn_data = purple_proxy_connect(gc, account, server, port, tcp_connect_cb, conn);
		if ( conn->conn_data == NULL ) {
			purple_debug_error("QQ", "Unable to connect.");
			return FALSE;
		}
		return TRUE;
	}
	
	purple_debug_info("QQ", "UDP Connect to %s:%d\n", server, port);
	conn->dns_data = purple_dnsquery_a(server, port, udp_host_resolved, conn);
	if ( conn->dns_data == NULL ) {
		purple_debug_error("QQ", "Could not resolve hostname");
		return FALSE;
	}
	return TRUE;
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
	if (qd->server_name != NULL) {
		purple_debug_info("QQ", "Remove previous server [%s]\n", qd->server_name);
   		qd->servers = g_list_remove(qd->servers, qd->server_name);
   		g_free(qd->server_name);
   		qd->server_name = NULL;
    }
	
	count = g_list_length(qd->servers);
	purple_debug_info("QQ", "Server list has %d\n", count);
	if (count <= 0) {
		/* no server left, disconnect when result is false */
		qd->servers = NULL;
		return FALSE;
	}
	
	/* get new server */
	index  = random() % count;
	it = g_list_nth(qd->servers, index);
    if (it->data == NULL || strlen(it->data) <= 0 ) {
		purple_debug_info("QQ", "Server name at %d is empty\n", index);
		return FALSE;
	}
	
	qd->server_name = g_strdup(it->data);
	qd->server_port = qd->default_port;
 	qd->reconn_times = QQ_RECONNECT_MAX;

	purple_debug_info("QQ", "set new server to %s:%d\n", qd->server_name, qd->server_port);
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

static gboolean redirect_to_server(PurpleConnection *gc, gchar *server, gint port)
{
	PurpleAccount *account ;
	qq_data *qd;
	gchar *conn_msg;
	qq_connection *conn;
	
	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, FALSE);
	account = purple_connection_get_account(gc);
	qd = (qq_data *) gc->proto_data;

	conn_msg = g_strdup_printf( _("Connecting server %s, retries %d"), server, port);
	purple_connection_update_progress(gc, conn_msg, 1, QQ_CONNECT_STEPS);
	g_free(conn_msg);

	conn = connection_create( gc );
	if(qd->use_tcp) {
   		purple_debug_info("QQ", "TCP Connect to %s:%d\n", server, port);

		conn->conn_data = purple_proxy_connect(gc, account, server, port, tcp_redirect_connect_cb, conn);
		if ( conn->conn_data == NULL ) {
			purple_debug_error("QQ", "Unable to connect.");
			/*
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to connect."));
			*/
			return FALSE;
		}
		return TRUE;
	}
	
	purple_debug_info("QQ", "UDP Connect to %s:%d\n", server, port);
	conn->dns_data =  purple_dnsquery_a( server, port, udp_host_resolved, conn );
	if ( conn->dns_data == NULL ) {
		purple_debug_error("QQ", "Could not resolve hostname");
		/*
		purple_connection_error_reason(qd->gc,
			PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Could not resolve hostname"));
		*/
		return FALSE;
	}
	return TRUE;
}

static gboolean redirect_later_cb(gpointer data)
{
	PurpleConnection *gc;
	qq_data *qd;

	gc = (PurpleConnection *) data;
	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, FALSE);
	qd = (qq_data *) gc->proto_data;

	qd->reconn_watcher = 0;

	if (qd->redirect_ip.s_addr == 0 || qd->redirect_port == 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Invalid redirect server."));
		return FALSE;
	}

	if ( !redirect_to_server(gc, inet_ntoa(qd->redirect_ip), qd->redirect_port) ) {
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to redirect server."));
	}
	return FALSE;	/* timeout callback stops */
}

static void redirect_later(PurpleConnection *gc)
{
	qq_data *qd;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

 	/* Do not disconnect previous server here */
	qq_disconnect(gc);

	qd->reconn_times--;
	if (qd->redirect_ip.s_addr == 0 || qd->reconn_times < 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					_("Failed to redirect server"));
		/*
		purple_debug_info("QQ",
			"Connect to new server %s:%d next retries %d in %d ms\n",
			qd->server_name, qd->server_port,
			qd->reconn_times, QQ_RECONNECT_INTERVAL);

		qq_connect(gc->account);
		*/
		return;
	}

	qd->reconn_watcher = purple_timeout_add(QQ_RECONNECT_INTERVAL,
		redirect_later_cb, gc);
}

void tcp_redirect_connect_cb(gpointer data, gint source, const gchar *error_message)
{
	qq_connection *conn = data;
	PurpleConnection *gc;
	qq_data *qd;
	PurpleAccount *account ;

	g_return_if_fail(conn != NULL);
	gc = conn->gc;
	account = purple_connection_get_account(gc);

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	/* PurpleProxyConnectData should be destory by purple after this callback*/
	conn->conn_data = NULL;
	conn->fd = source;
	
	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		purple_debug_info("QQ_CONN", "Invalid connection\n");
		return;
	}

	if (source < 0) {	/* socket returns -1 */
		redirect_later(gc);
		return;
	}

	purple_debug_info("QQ_CONN", "Got redirect connection %d\n", source);

	qd->redirect_ip.s_addr = 0;
	qd->conn = conn;
	do_request_token(gc);
}

/* process the incoming packet from qq_pending */
static void packet_process(PurpleConnection *gc, int fd, guint8 *buf, gint buf_len)
{
	qq_data *qd;
	gint bytes, bytes_not_read;

	gboolean prev_login_status;
	
	guint8 header_tag;
	guint16 source_tag;
	guint16 cmd;
	guint16 seq;		/* May be ack_seq or send_seq, depends on cmd */
	
	guint8 room_cmd;
	guint32 room_id;

	guint8 ret_token;
	gchar *error_msg = NULL;

	qq_transaction *trans;

	g_return_if_fail(buf != NULL && buf_len > 0);

	qd = (qq_data *) gc->proto_data;

	prev_login_status = qd->logged_in;

	/* Len, header and tail tag have been checked before */
	bytes = 0;
	bytes += packet_get_header(&header_tag, &source_tag, &cmd, &seq, buf + bytes);

#if 1
		purple_debug_info("QQ", "==> [%05d] 0x%04X %s, source tag 0x%04X len %d\n",
				seq, cmd, qq_get_cmd_desc(cmd), source_tag, buf_len);
#endif	
	bytes_not_read = buf_len - bytes - 1;

	/* ack packet, we need to update send tranactions */
	/* we do not check duplication for server ack */
	trans = qq_trans_find_rcved(gc, fd, cmd, seq);
	if (trans == NULL) {
		/* new server command */
		qq_trans_add_server_cmd(gc, fd, cmd, seq, buf + bytes, bytes_not_read);
		if ( qd->logged_in ) {
			qq_proc_cmd_server(gc, cmd, seq, buf + bytes, bytes_not_read);
		}
		return;
	}

	if (qq_trans_is_dup(trans)) {
		purple_debug(PURPLE_DEBUG_WARNING,
				"QQ", "dup [%05d] %s, discard...\n", seq, qq_get_cmd_desc(cmd));
		return;
	}

	if (qq_trans_is_server(trans)) {
		if ( qd->logged_in ) {
			qq_proc_cmd_server(gc, cmd, seq, buf + bytes, bytes_not_read);
		}
		return;
	}

	/* this is the length of all the encrypted data (also remove tail tag */
	if (cmd == QQ_CMD_TOKEN) {
		ret_token = qq_process_token_reply(gc, error_msg, buf + bytes, bytes_not_read);
		if (ret_token != QQ_TOKEN_REPLY_OK) {
			if (error_msg == NULL) {
				error_msg = g_strdup_printf( _("Invalid token reply code, 0x%02X"), ret_token);
			}
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg);
			g_free(error_msg);
			return;
		}
		qq_send_packet_login(gc);
	} else if (cmd == QQ_CMD_ROOM) {
		room_cmd = qq_trans_get_room_cmd(trans);
		room_id = qq_trans_get_room_id(trans);
#if 1
		purple_debug_info("QQ", "%s (0x%02X ) for room %d, len %d\n",
				qq_get_room_cmd_desc(room_cmd), room_cmd, room_id, buf_len);
#endif	
		qq_proc_room_cmd_reply(gc, seq, room_cmd, room_id, buf + bytes, bytes_not_read);
	} else {
		qq_proc_cmd_reply(gc, cmd, seq, buf + bytes, bytes_not_read);
	}
	
	/* check is redirect or not, and do it now */
	if (qd->redirect_ip.s_addr != 0) {
	 	qd->reconn_times = QQ_RECONNECT_MAX;
		redirect_later(gc);
		return;
	}

	if (prev_login_status != qd->logged_in && qd->logged_in == TRUE) {
		/* logged_in, but we have packets before login */
		qq_trans_process_before_login(gc);
	}
}

static void tcp_pending(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc;
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

	gc = (PurpleConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	if(cond != PURPLE_INPUT_READ) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Socket error"));
		return;
	}

	qd = (qq_data *) gc->proto_data;
	conn = connection_find(gc, source);
	if(!conn) {
		purple_debug_error("TCP_CAN_WRITE", "Connection not found!\n");
		return;
	}
	
	/* test code, not using tcp_rxqueue
	memset(pkt,0, sizeof(pkt));
	buf_len = read(qd->fd, pkt, sizeof(pkt));
	if (buf_len > 2) {
		packet_process(gc, pkt + 2, buf_len - 2);
	}
	return;
	*/
	
	buf_len = read(conn->fd, buf, sizeof(buf));
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
	/*
	purple_debug_info("TCP_PENDING",
			   "Read %d bytes from socket, rxlen is %d\n", buf_len, qd->tcp_rxlen);
	*/
	conn->tcp_rxqueue = g_realloc(conn->tcp_rxqueue, buf_len + conn->tcp_rxlen);
	memcpy(conn->tcp_rxqueue + conn->tcp_rxlen, buf, buf_len);
	conn->tcp_rxlen += buf_len;
	
	pkt = g_newa(guint8, MAX_PACKET_SIZE);
	while (1) {
		if (conn->tcp_rxlen < QQ_TCP_HEADER_LENGTH) {
			break;
		}
		
		bytes = 0;
		bytes += qq_get16(&pkt_len, conn->tcp_rxqueue + bytes);
		if (conn->tcp_rxlen < pkt_len) {
			break;
		}

		/* 
		purple_debug_info("TCP_PENDING",
				   "Packet len is %d bytes, rxlen is %d\n", pkt_len, qd->tcp_rxlen);
		*/
		if ( pkt_len < QQ_TCP_HEADER_LENGTH
		    || *(conn->tcp_rxqueue + bytes) != QQ_PACKET_TAG
			|| *(conn->tcp_rxqueue + pkt_len - 1) != QQ_PACKET_TAIL) {
			/* HEY! This isn't even a QQ. What are you trying to pull? */

			purple_debug_error("TCP_PENDING",
				 "Packet error, failed to check header and tail tag\n");

			jump = memchr(conn->tcp_rxqueue + 1, QQ_PACKET_TAIL, conn->tcp_rxlen - 1);
			if ( !jump ) {
				purple_debug_info("TCP_PENDING",
				 	"Failed to find next QQ_PACKET_TAIL, clear receive buffer\n");
				g_free(conn->tcp_rxqueue);
				conn->tcp_rxqueue = NULL;
				conn->tcp_rxlen = 0;
				return;
			}

			/* jump and over QQ_PACKET_TAIL */
			jump_len = (jump - conn->tcp_rxqueue) + 1;
			purple_debug_info("TCP_PENDING",
				"Find next QQ_PACKET_TAIL at %d, jump %d bytes\n", jump_len, jump_len + 1);
			g_memmove(conn->tcp_rxqueue, jump, conn->tcp_rxlen - jump_len);
			conn->tcp_rxlen -= jump_len;
			continue;
		}

		memset(pkt, 0, MAX_PACKET_SIZE);
		g_memmove(pkt, conn->tcp_rxqueue + bytes, pkt_len - bytes);
		
		/* jump to next packet */
		conn->tcp_rxlen -= pkt_len;
		if (conn->tcp_rxlen) {
			/*
			purple_debug_error("TCP_PENDING", "shrink tcp_rxqueue to %d\n", qd->tcp_rxlen);		
			*/
			jump = g_memdup(conn->tcp_rxqueue + pkt_len, conn->tcp_rxlen);
			g_free(conn->tcp_rxqueue);
			conn->tcp_rxqueue = jump;
		} else {
			/* purple_debug_error("TCP_PENDING", "free tcp_rxqueue\n"); */
			g_free(conn->tcp_rxqueue);
			conn->tcp_rxqueue = NULL;
		}

		if (pkt == NULL) {
			continue;
		}
		/* do not call packet_process before jump 
		 * packet_process may call disconnect and destory tcp_rxqueue */
		packet_process(gc, conn->fd, pkt, pkt_len - bytes);
	}
}

static void udp_pending(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc;
	qq_data *qd;
	qq_connection *conn;
	guint8 *buf;
	gint buf_len;

	gc = (PurpleConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	if(cond != PURPLE_INPUT_READ) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Socket error"));
		return;
	}

	qd = (qq_data *) gc->proto_data;
	conn = connection_find(gc, source);
	if(!conn) {
		purple_debug_error("TCP_CAN_WRITE", "Connection not found!\n");
		return;
	}
	
	buf = g_newa(guint8, MAX_PACKET_SIZE);

	/* here we have UDP proxy suppport */
	buf_len = read(conn->fd, buf, MAX_PACKET_SIZE);
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
	
	packet_process(gc, conn->fd, buf, buf_len);
}

static gint udp_send_out(PurpleConnection *gc, int fd, guint8 *data, gint data_len)
{
	qq_data *qd;
	gint ret;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;

	g_return_val_if_fail(qd != NULL, -1);
	g_return_val_if_fail(fd >= 0, -1);
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	/*
	purple_debug_info("UDP_SEND_OUT", "Send %d bytes to socket %d\n", data_len, qd->fd);
	*/
	
	errno = 0;
	ret = send(fd, data, data_len, 0);
	if (ret < 0 && errno == EAGAIN) {
		return ret;
	}
	
	if (ret < 0) {
		/* TODO: what to do here - do we really have to disconnect? */
		purple_debug_error("UDP_SEND_OUT", "Send failed: %d, %s\n", errno, g_strerror(errno));
		purple_connection_error_reason(qd->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, g_strerror(errno));
	}
	return ret;
}

static void tcp_can_write(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = (PurpleConnection *)data;
	qq_data *qd;
	int ret, writelen;
	qq_connection *conn;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;
	
	conn = connection_find(gc, source);
	if(!conn) {
		purple_debug_error("TCP_CAN_WRITE", "Connection not found!\n");
		return;
	}

	if (conn->tcp_txbuf == NULL) {
		purple_debug_error("TCP_CAN_WRITE", "Nothing to write!\n");
		return;
	}

	writelen = purple_circ_buffer_get_max_read(conn->tcp_txbuf);
	if (writelen == 0) {
		purple_input_remove(conn->can_write_handler);
		conn->can_write_handler = 0;
		return;
	}

	ret = write(conn->fd, conn->tcp_txbuf->outptr, writelen);
	purple_debug_error("TCP_CAN_WRITE", "total %d bytes is sent %d\n", writelen, ret);

	if (ret < 0 && errno == EAGAIN)
		return;
	else if (ret < 0) {
		/* TODO: what to do here - do we really have to disconnect? */
		purple_connection_error_reason(qd->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
		                               _("Write Error"));
		return;
	}

	purple_circ_buffer_mark_read(conn->tcp_txbuf, ret);
}

static gint tcp_send_out(PurpleConnection *gc, int fd, guint8 *data, gint data_len)
{
	qq_data *qd;
	qq_connection *conn;
	gint ret;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;

	g_return_val_if_fail(fd >= 0, -1);
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	conn = connection_find(gc, fd);
	if(!conn) {
		purple_debug_error("TCP_SEND_OUT", "Connection %d not found!\n", fd);
		return -1;
	}
	
	/*
	purple_debug_info("TCP_SEND_OUT", "Send %d bytes to socket %d\n", data_len, qd->fd);
	 */

	if (conn->can_write_handler == 0) {
		ret = write(conn->fd, data, data_len);
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
		purple_debug_info("TCP_SEND_OUT", "Socket %d is busy and send later\n", conn->fd);
		ret = 0;
	} else if (ret <= 0) {
		/* TODO: what to do here - do we really have to disconnect? */
		purple_debug_error("TCP_SEND_OUT",
			"Send to socket %d failed: %d, %s\n", conn->fd, errno, g_strerror(errno));
		purple_connection_error_reason(qd->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, g_strerror(errno));
		return ret;
	}

	if (ret < data_len) {
		purple_debug_info("TCP_SEND_OUT",
			"Add %d bytes to buffer\n", data_len - ret);
		if (conn->can_write_handler == 0) {
			conn->can_write_handler = purple_input_add(conn->fd, PURPLE_INPUT_WRITE, tcp_can_write, gc);
		}
		if (conn->tcp_txbuf == NULL) {
			/* TODO: is there a good default grow size? */
			purple_debug_info("QQ", "Create tcp_txbuf\n");
			conn->tcp_txbuf = purple_circ_buffer_new(0);
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

	if ( !qd->logged_in ) {
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
		qq_send_packet_get_buddies_online(gc, 0);

		qq_send_cmd_group_all_get_online_members(gc);
		return TRUE;
	}

	return TRUE;		/* if return FALSE, timeout callback stops */
}

void do_request_token(PurpleConnection *gc)
{
	qq_data *qd;
	gchar *conn_msg;
	const gchar *passwd;

	/* _qq_show_socket("Got login socket", source); */

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;
	g_return_if_fail(qd->conn != NULL);

	/* QQ use random seq, to minimize duplicated packets */
	srandom(time(NULL));
	qd->send_seq = random() & 0xffff;

	qd->logged_in = FALSE;
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
	qd->network_watcher = purple_timeout_add(qd->itv_config.resend *1000, network_timeout, gc);
	
	//purple_debug_info("QQ_CONN", "Got first connection %d\n", qd->conn->fd);
	if (qd->use_tcp) {
		qd->conn->input_handler
			= purple_input_add(qd->conn->fd, PURPLE_INPUT_READ, tcp_pending, gc);
	} else {
		qd->conn->input_handler
			= purple_input_add(qd->conn->fd, PURPLE_INPUT_READ, udp_pending, gc);
	}
	//gc->inpa = qd->conn->input_handler;
	
	/* Update the login progress status display */
	conn_msg = g_strdup_printf("Login as %d", qd->uid);
	purple_connection_update_progress(gc, conn_msg, QQ_CONNECT_STEPS - 1, QQ_CONNECT_STEPS);
	g_free(conn_msg);

	//purple_debug_info("QQ_CONN", "Got first connection %d\n", qd->conn->fd);
	qq_send_packet_token(gc, qd->conn->fd);
}

/* the callback function after socket is built
 * we setup the qq protocol related configuration here */
void tcp_connect_cb(gpointer data, gint source, const gchar *error_message)
{
	qq_connection *conn = data;
	PurpleConnection *gc;
	qq_data *qd;
	PurpleAccount *account ;

	g_return_if_fail(conn != NULL);
	gc = conn->gc;
	account = purple_connection_get_account(gc);

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	/* PurpleProxyConnectData should be destory by purple after this callback*/
	conn->conn_data = NULL;
	conn->fd = source;
	
	if (!PURPLE_CONNECTION_IS_VALID(gc)  || source < 0) {
		purple_debug_info("QQ_CONN", "Invalid connection\n");
		connection_free(gc, conn);
		if (qd->openconns == NULL) {
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Couldn't resolve host"));
		}
		return;
	}

	/*
	if (qd->redirect_ip.s_addr != 0) {
		purple_debug_info("QQ_CONN", "Got connection in redirecting, close %d\n", source);
		close(source);
		return;
	}
	*/
	
	if (qd->conn != NULL) {
		purple_debug_info("QQ_CONN", "Got connection before, close %d\n", conn->fd);
		connection_free(gc, conn);
		return;
	}
	
	purple_debug_info("QQ_CONN", "Got first connection %d\n", source);

	qd->conn = conn;
	//purple_debug_info("QQ_CONN", "Got first connection %d\n", qd->conn->fd);
	do_request_token( gc );
}

static void udp_can_write(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = (PurpleConnection *) data;
	qq_data *qd;
	qq_connection *conn;
	socklen_t len;
	int error=0, ret;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;
	
	conn = connection_find(gc, source);
	if(!conn) {
		purple_debug_error("UDP_CAN_WRITE", "Connection not found!\n");
		return;
	}

	purple_debug_info("UDP_CAN_WRITE", "Connected.\n");

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
		
	purple_input_remove(conn->can_write_handler);
	conn->can_write_handler = 0;
	if (ret < 0 || error != 0) {
		if(ret != 0) 
			error = errno;

		close(source);
		purple_debug_error("UDP_CAN_WRITE", "getsockopt SO_ERROR check: %s\n", g_strerror(error));
		return;
	}

	if (qd->conn != NULL) {
		purple_debug_info("UDP_CAN_WRITE", "Got connection before, close %d\n", source);
		close(source);
		return;
	}

	qq_disconnect( gc );
	//qd->conn = connection_create(gc, source);
	do_request_token(gc);
}

void udp_host_resolved(GSList *hosts, gpointer data, const char *error_message)
{
	PurpleConnection *gc;
	qq_data *qd;
	struct sockaddr server_addr;
	int addr_size;
	gint fd = -1;
	int flags;
	qq_connection *conn;

	gc = (PurpleConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	if (!hosts || !hosts->data) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
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
		purple_debug_error("QQ", "Unable to create socket: %s\n", g_strerror(errno));
		return;
	}

	//conn = connection_create(gc, fd);

	/* we use non-blocking mode to speed up connection */
	flags = fcntl(conn->fd, F_GETFL);
	fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK);

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
	if (connect(conn->fd, &server_addr, addr_size) >= 0) {
		purple_debug_info("QQ", "Connected.\n");
		flags = fcntl(conn->fd, F_GETFL);
		fcntl(conn->fd, F_SETFL, flags & ~O_NONBLOCK);
		//connect_cb(gc, conn->fd, NULL);
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
			purple_debug_warning("QQ", "Connect in asynchronous mode.\n");
			conn->can_write_handler = purple_input_add(fd, PURPLE_INPUT_WRITE, udp_can_write, gc);
			return;
	}

	purple_debug_error("QQ", "Connection failed: %s\n", g_strerror(errno));
	close(fd);
}

void qq_connect_express(PurpleAccount *account)
{
	PurpleConnection *gc;
	qq_data *qd;
	GList *it;
	int conn_count = 0;
	gchar *server_name;

	gc = purple_account_get_connection(account);
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;
	purple_connection_update_progress(gc, _("Connecting all servers..."), 1, QQ_CONNECT_STEPS);

	it = qd->servers;
	while(it) {
		if (it->data != NULL && strlen(it->data) != 0) {
			server_name = it->data;
			if ( connect_to_server(gc, server_name, qd->default_port) ) {
				conn_count++;
			}
		}
		it = it->next;
	}

	if (conn_count <= 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to connect."));
		return;
	}
	
}

/* establish a generic QQ connection 
 * TCP/UDP, and direct/redirected */
void qq_connect(PurpleAccount *account)
{
	PurpleConnection *gc;
	qq_data *qd;

	gc = purple_account_get_connection(account);
	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;

	/* test set_new_server
	while (set_new_server(qd)) {
   		purple_debug_info("QQ_TEST",
   			"New server %s:%d  Redirect %s:%d\n",
   			qd->server_name, qd->user_port, inet_ntoa(qd->redirect_ip, qd->redirect_ip);
	}
	purple_debug_info("QQ_TEST", "qd->servers %lu\n",
 			qd->servers);
 	exit(1);
	*/
	if (qd->server_name == NULL) {
		/* must be first call this function */
		set_new_server(qd);
	} else {
		if (qd->redirect_ip.s_addr != 0) {
			g_free(qd->server_name);

			qd->server_name = g_strdup( inet_ntoa(qd->redirect_ip) );
			qd->server_port = qd->redirect_port;
			
   			purple_debug_info("QQ", "Redirect to %s:%d\n",
   				qd->server_name, qd->server_port);
   		}
		qd->redirect_ip.s_addr = 0;
	}

	if (qd->server_name == NULL || qd->server_port == 0) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Failed to connect server"));
		return;
	}

	/* QQ connection via UDP/TCP. 
	* Now use Purple proxy function to provide TCP proxy support,
	* and qq_udp_proxy.c to add UDP proxy support (thanks henry) */
	if ( ! connect_to_server(gc, qd->server_name, qd->server_port) ) {
			purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Unable to connect."));
	}
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
		purple_debug_info("QQ", "Close network_watcher\n");
		purple_timeout_remove(qd->network_watcher);
		qd->network_watcher = 0;
	}

	/* finish  all I/O */
	if (qd->conn != NULL && qd->conn->fd >= 0) {
		if (qd->logged_in) {
			purple_debug_info("QQ", "Logout\n");
			qq_send_packet_logout(gc);
		}
	}
	
	if (gc->inpa > 0) {
		purple_debug_info("QQ", "Close input handle\n");
		//purple_input_remove(gc->inpa);
		gc->inpa = 0;
	}

	connection_free_all(gc);
	qd->conn = NULL;

	if (qd->reconn_watcher > 0) {
		purple_timeout_remove(qd->reconn_watcher);
		qd->reconn_watcher = 0;
	}

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

static gint encap(qq_data *qd, guint8 *buf, gint maxlen, guint16 cmd, guint16 seq, 
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
gint qq_send_data(PurpleConnection *gc, int fd, guint16 cmd, guint16 seq, gboolean need_ack,
	guint8 *data, gint data_len)
{
	qq_data *qd = (qq_data *)gc->proto_data;
	guint8 *buf;
	gint buf_len;
	gint bytes_sent;

	g_return_val_if_fail(qd != NULL, -1);
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	buf = g_newa(guint8, MAX_PACKET_SIZE);
	memset(buf, 0, MAX_PACKET_SIZE);
	buf_len = encap(qd, buf, MAX_PACKET_SIZE, cmd, seq, data, data_len);
	if (buf_len <= 0) {
		return -1;
	}

	if (qd->use_tcp) {
		bytes_sent = tcp_send_out(gc, fd, buf, buf_len);
	} else {
		bytes_sent = udp_send_out(gc, fd, buf, buf_len);
	}

	if (need_ack)  {
		qq_trans_add_client_cmd(gc, fd, cmd, seq, data, data_len);
	}
	
#if 1
		/* qq_show_packet("QQ_SEND_DATA", buf, buf_len); */
		purple_debug_info("QQ", "<== [%05d], 0x%04X %s, total %d bytes is sent %d\n", 
				seq, cmd, qq_get_cmd_desc(cmd), buf_len, bytes_sent);
#endif
	return bytes_sent;
}

/* Encrypt data with session_key, then call qq_send_data */
gint qq_send_cmd_detail(PurpleConnection *gc, guint16 cmd, guint16 seq, gboolean need_ack,
	guint8 *data, gint data_len)
{
	qq_data *qd = (qq_data *)gc->proto_data;
	guint8 *encrypted_data;
	gint encrypted_len;

	g_return_val_if_fail(qd != NULL, -1);
	g_return_val_if_fail(qd->conn != NULL && qd->conn->fd >= 0, -1);
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	/* at most 16 bytes more */
	encrypted_data = g_newa(guint8, data_len + 16);
#if 0
	purple_debug_info("QQ_ENCRYPT",
			"Before %d: [%05d] 0x%04X %s\n",
			data_len, seq, cmd, qq_get_cmd_desc(cmd));
#endif
	encrypted_len = qq_encrypt(encrypted_data, data, data_len, qd->session_key);
	if (encrypted_len < 16) {
		purple_debug_error("QQ_ENCRYPT", "Error len %d: [%05d] 0x%04X %s\n",
				encrypted_len, seq, cmd, qq_get_cmd_desc(cmd));
		return -1;
	}

#if 0
	purple_debug_info("QQ_ENCRYPT", "After %d: [%05d] 0x%04X %s\n",
			encrypted_len, seq, cmd, qq_get_cmd_desc(cmd));
#endif
	return qq_send_data(gc, qd->conn->fd, cmd, seq, need_ack, encrypted_data, encrypted_len);
}

/* set seq and need_ack, then call qq_send_cmd_detail */
gint qq_send_cmd(PurpleConnection *gc, guint16 cmd, guint8 *data, gint data_len)
{
	qq_data *qd = (qq_data *)gc->proto_data;
	g_return_val_if_fail(qd != NULL, -1);
	g_return_val_if_fail(data != NULL && data_len > 0, -1);

	qd->send_seq++;
	return qq_send_cmd_detail(gc, cmd, qd->send_seq, TRUE, data, data_len);
}

gint qq_send_room_cmd_noid(PurpleConnection *gc, guint8 room_cmd, 
		guint8 *data, gint data_len)
{
	return qq_send_room_cmd(gc, room_cmd, 0, data, data_len);
}

gint qq_send_room_cmd_only(PurpleConnection *gc, guint8 room_cmd, guint32 room_id)
{
	g_return_val_if_fail(room_cmd > 0 && room_id > 0, -1);
	return qq_send_room_cmd(gc, room_cmd, room_id, NULL, 0);
}

gint qq_send_room_cmd(PurpleConnection *gc, guint8 room_cmd, guint32 room_id,
		guint8 *data, gint data_len)
{
	qq_data *qd;
	int fd;

	guint8 *buf;
	gint buf_len;
	guint8 *encrypted_data;
	gint encrypted_len;
	gint bytes_sent;
	guint16 seq;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;

	g_return_val_if_fail(qd->conn != NULL && qd->conn->fd >= 0, -1);
	fd = qd->conn->fd;

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
		purple_debug_error("QQ_ENCRYPT",
				"Error len %d: [%05d] %s (0x%02X)\n",
				encrypted_len, seq, qq_get_room_cmd_desc(room_cmd), room_cmd);
		return -1;
	}

	/* Encap header to buf */
	buf_len = encap(qd, buf, MAX_PACKET_SIZE, QQ_CMD_ROOM, seq, encrypted_data, encrypted_len);
	if (buf_len <= 0) {
		return -1;
	}

	if (qd->use_tcp) {
		bytes_sent = tcp_send_out(gc, fd, buf, buf_len);
	} else {
		bytes_sent = udp_send_out(gc, fd, buf, buf_len);
	}

	qq_trans_add_room_cmd(gc, fd, seq, room_cmd, room_id, buf, buf_len);
	
#if 1
		/* qq_show_packet("QQ_SEND_DATA", buf, buf_len); */
		purple_debug_info("QQ",
				"<== [%05d], %s (0x%02X) to room %d, total %d bytes is sent %d\n", 
				seq, qq_get_room_cmd_desc(room_cmd), room_cmd, room_id,
				buf_len, bytes_sent);
#endif
	return bytes_sent;
}
