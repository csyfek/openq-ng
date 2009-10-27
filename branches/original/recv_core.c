/**
* The QQ2003C protocol plugin
 *
 * for gaim
 *
 * Copyright (C) 2004 Puzzlebird
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// START OF FILE
/*****************************************************************************/
#include "debug.h"		// gaim_debug
#include "internal.h"		// _("get_text")

#include "utils.h"		// hex_dump_to_str
#include "packet_parse.h"	// MAX_PACKET_SIZE
#include "buddy_info.h"		// qq_process_modify_info_reply
#include "buddy_list.h"		// qq_process_get_buddies_list_reply
#include "buddy_opt.h"		// qq_process_add_buddy_reply
#include "buddy_status.h"	// qq_process_friend_change_status
#include "char_conv.h"		// qq_to_utf8
#include "crypt.h"		// qq_crypt
#include "group_network.h"	// qq_process_group_cmd_reply
#include "header_info.h"	// cmd alias
#include "keep_alive.h"		// qq_process_keep_alive_reply
#include "im.h"			// qq_process_send_im_reply
#include "login_logout.h"	// qq_process_login_reply
#include "qq_proxy.h"		// qq_proxy_read
#include "recv_core.h"
#include "sendqueue.h"		// qq_sendqueue_remove
#include "sys_msg.h"		// qq_process_msg_sys

typedef struct _packet_before_login packet_before_login;
typedef struct _qq_recv_msg_header qq_recv_msg_header;

struct _packet_before_login {
	guint8 *buf;
	gint len;
};

struct _qq_recv_msg_header {
	guint8 header_tag;
	guint16 source_tag;
	guint16 cmd;
	guint16 seq;		// can be ack_seq or send_seq, depends on cmd
};

/*****************************************************************************/
// check whether one sequence number is duplicated or not
// return TRUE if it is duplicated, otherwise FALSE
gboolean _qq_check_packet_set_window(guint16 seq, GaimConnection * gc)
{
	qq_data *qd;
	gchar *byte, mask;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL, FALSE);
	qd = (qq_data *) gc->proto_data;
	byte = &(qd->window[seq / 8]);
	mask = (1 << (seq % 8));

	if ((*byte) & mask)
		return TRUE;	// check mask
	(*byte) |= mask;
	return FALSE;		// set mask
}				// _qq_check_packet_set_window

/*****************************************************************************/
// default process, decrypt and dump
void _qq_process_packet_default(guint8 * buf, gint buf_len, guint16 cmd, guint16 seq, GaimConnection * gc) {

	qq_data *qd;
	guint8 *data;
	gchar *msg_utf8;
	gint len;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	g_return_if_fail(buf != NULL && buf_len != 0);

	qd = (qq_data *) gc->proto_data;
	len = buf_len;
	data = g_newa(guint8, len);
	msg_utf8 = NULL;

	if (qq_crypt(DECRYPT, buf, buf_len, qd->session_key, data, &len)) {
		gaim_debug(GAIM_DEBUG_WARNING, "QQ",
			   ">>> [%d] %s, %d bytes -> [default] decrypt and dump\n%s",
			   seq, qq_get_cmd_desc(cmd), buf_len, hex_dump_to_str(data, len));
		try_dump_as_gbk(data, len);
	} else
		gaim_debug(GAIM_DEBUG_ERROR, "QQ", "Fail decrypt packet with default process\n");

}				// _qq_process_packet_default

/*****************************************************************************/
// process the incoming packet from qq_pending
void _qq_packet_process(guint8 * buf, gint buf_len, GaimConnection * gc)
{
	qq_data *qd;
	gint len, bytes_expected, bytes_read;
	guint16 buf_len_read;	// two bytes in the begining of TCP packet
	guint8 *cursor;
	qq_recv_msg_header header;
	packet_before_login *b4_packet;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	g_return_if_fail(buf != NULL && buf_len > 0);

	qd = (qq_data *) gc->proto_data;
	bytes_expected = qd->use_tcp ? QQ_TCP_HEADER_LENGTH : QQ_UDP_HEADER_LENGTH;

	if (buf_len < bytes_expected) {
		gaim_debug(GAIM_DEBUG_ERROR,
			   "QQ", "Received packet is too short, dump and drop\n%s", hex_dump_to_str(buf, buf_len));
		return;
	}
	// initialize
	cursor = buf;
	bytes_read = 0;

	// QQ TCP packet returns first 2 bytes the length of this packet
	if (qd->use_tcp) {
		bytes_read += read_packet_w(buf, &cursor, buf_len, &buf_len_read);
		if (buf_len_read != buf_len) {	// wrong
			gaim_debug
			    (GAIM_DEBUG_ERROR,
			     "QQ",
			     "TCP read %d bytes, header says %d bytes, use header anyway\n", buf_len, buf_len_read);
			buf_len = buf_len_read;	// we believe header is more accurate
		}		// if buf_len_read
	}			// if use_tcp

	// now goes the normal QQ packet as UDP packet
	bytes_read += read_packet_b(buf, &cursor, buf_len, &header.header_tag);
	bytes_read += read_packet_w(buf, &cursor, buf_len, &header.source_tag);
	bytes_read += read_packet_w(buf, &cursor, buf_len, &header.cmd);
	bytes_read += read_packet_w(buf, &cursor, buf_len, &header.seq);

	if (bytes_read != bytes_expected) {	// read error
		gaim_debug(GAIM_DEBUG_ERROR, "QQ",
			   "Fail reading packet header, expect %d bytes, read %d bytes\n", bytes_expected, bytes_read);
		return;
	}			// if bytes_read

	if ((buf[buf_len - 1] != QQ_PACKET_TAIL) || (header.header_tag != QQ_PACKET_TAG)) {
		gaim_debug(GAIM_DEBUG_ERROR,
			   "QQ", "Unknown QQ proctocol, dump and drop\n%s", hex_dump_to_str(buf, buf_len));
		return;
	}			// if header_tag

	if (QQ_DEBUG)
		gaim_debug(GAIM_DEBUG_INFO, "QQ",
			   "==> [%05d] %s, from (%s)\n",
			   header.seq, qq_get_cmd_desc(header.cmd), qq_get_source_str(header.source_tag));
	//add "&& header.cmd != QQ_CMD_GET_LOGIN_TOKEN" by Yuan Qingyun for QQ 2006 with SP1
	if (header.cmd != QQ_CMD_LOGIN && header.cmd != QQ_CMD_GET_LOGIN_TOKEN) {
		if (!qd->logged_in) {	// packets before login
			b4_packet = g_new0(packet_before_login, 1);
			// must duplicate, buffer will be freed after exiting this function
			b4_packet->buf = g_memdup(buf, buf_len);
			b4_packet->len = buf_len;
			if (qd->before_login_packets == NULL)
				qd->before_login_packets = g_queue_new();
			g_queue_push_head(qd->before_login_packets, b4_packet);
			return;	// do not process it now
		} else if (!g_queue_is_empty(qd->before_login_packets)) {
			// logged_in, but we have packets before login
			b4_packet = (packet_before_login *)
			    g_queue_pop_head(qd->before_login_packets);
			_qq_packet_process(b4_packet->buf, b4_packet->len, gc);
			// in fact this is a recursive call, 
			// all packets before login will be processed before goes on
			g_free(b4_packet->buf);	// the buf is duplicated, need to be freed
			g_free(b4_packet);
		}		// if logged_in
	}			//if header.cmd != QQ_CMD_LOGIN

	// this is the length of all the encrypted data (also remove tail tag
	len = buf_len - (bytes_read) - 1;

	// whether it is an ack
	switch (header.cmd) {
	case QQ_CMD_RECV_IM:
	case QQ_CMD_RECV_MSG_SYS:
	case QQ_CMD_RECV_MSG_FRIEND_CHANGE_STATUS:
		// server intiated packet, we need to send ack and check duplicaion
		// this must be put after processing b4_packet
		// as these packets will be passed in twice
		if (_qq_check_packet_set_window(header.seq, gc)) {
			gaim_debug(GAIM_DEBUG_WARNING,
				   "QQ", "dup [%05d] %s, discard...\n", header.seq, qq_get_cmd_desc(header.cmd));
			return;
		}
		break;
	default:{		// ack packet, we need to update sendqueue
			// we do not check duplication for server ack
			qq_sendqueue_remove(qd, header.seq);
			if (QQ_DEBUG)
				gaim_debug(GAIM_DEBUG_INFO, "QQ",
					   "ack [%05d] %s, remove from sendqueue\n",
					   header.seq, qq_get_cmd_desc(header.cmd));
		}		// default
	}			// switch header.cmd

	// now process the packet
	switch (header.cmd) {
	case QQ_CMD_KEEP_ALIVE:
		qq_process_keep_alive_reply(cursor, len, gc);
		break;
	case QQ_CMD_UPDATE_INFO:
		qq_process_modify_info_reply(cursor, len, gc);
		break;
	case QQ_CMD_ADD_FRIEND_WO_AUTH:
		qq_process_add_buddy_reply(cursor, len, header.seq, gc);
		break;
	case QQ_CMD_DEL_FRIEND:
		qq_process_remove_buddy_reply(cursor, len, gc);
		break;
	case QQ_CMD_REMOVE_SELF:
		qq_process_remove_self_reply(cursor, len, gc);
		break;
	case QQ_CMD_BUDDY_AUTH:
		qq_process_add_buddy_auth_reply(cursor, len, gc);
		break;
	case QQ_CMD_GET_USER_INFO:
		qq_process_get_info_reply(cursor, len, gc);
		break;
	case QQ_CMD_CHANGE_ONLINE_STATUS:
		qq_process_change_status_reply(cursor, len, gc);
		break;
	case QQ_CMD_SEND_IM:
		qq_process_send_im_reply(cursor, len, gc);
		break;
	case QQ_CMD_RECV_IM:
		qq_process_recv_im(cursor, len, header.seq, gc);
		break;
	case QQ_CMD_LOGIN:
		qq_process_login_reply(cursor, len, gc);
		break;
	case QQ_CMD_GET_FRIENDS_LIST:
		qq_process_get_buddies_list_reply(cursor, len, gc);
		break;
	case QQ_CMD_GET_FRIENDS_ONLINE:
		qq_process_get_buddies_online_reply(cursor, len, gc);
		break;
	case QQ_CMD_GROUP_CMD:
		qq_process_group_cmd_reply(cursor, len, header.seq, gc);
		break;
	case QQ_CMD_RECV_MSG_SYS:
		qq_process_msg_sys(cursor, len, header.seq, gc);
		break;
	case QQ_CMD_RECV_MSG_FRIEND_CHANGE_STATUS:
		qq_process_friend_change_status(cursor, len, gc);
		break;
	case QQ_CMD_GET_LOGIN_TOKEN://add by Yuan Qingyun for QQ 2006 with SP1
		qq_process_login_token_relay(cursor, len, gc);
		break;
	default:
		_qq_process_packet_default(cursor, len, header.cmd, header.seq, gc);
		break;
	}			// switch header.cmd
}				// _qq_packet_process

/*****************************************************************************/
// clean up the packets before login
void qq_b4_packets_free(qq_data * qd)
{
	packet_before_login *b4_packet;
	g_return_if_fail(qd != NULL);
	// now clean up my own data structures
	if (qd->before_login_packets != NULL) {
		while (NULL != (b4_packet = g_queue_pop_tail(qd->before_login_packets))) {
			g_free(b4_packet->buf);
			g_free(b4_packet);
		}
		g_queue_free(qd->before_login_packets);
	}			// if 
}				// qq_b4_packets_free

/*****************************************************************************/
void qq_input_pending(gpointer data, gint source, GaimInputCondition cond)
{
	GaimConnection *gc;
	qq_data *qd;;
	guint8 *buf;
	gint len;

	gc = (GaimConnection *) data;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL && cond == GAIM_INPUT_READ);

	qd = (qq_data *) gc->proto_data;
	// according to glib manual memory allocated by g_newa could be 
	// automatically freed when the current stack frame is cleaned up
	buf = g_newa(guint8, MAX_PACKET_SIZE);

	// here we have UDP proxy suppport
	len = qq_proxy_read(qd, buf, MAX_PACKET_SIZE);
	if (len <= 0) {
		gaim_connection_error(gc, _("Unable to read from socket"));
		return;
	} else
		_qq_packet_process(buf, len, gc);
}				// qq_input_pending

/*****************************************************************************/
// END OF FILE
