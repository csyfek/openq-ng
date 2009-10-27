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
#include <string.h>		// g_memmove, memmove
#include "debug.h"		// gaim_debug

#include "utils.h"		// get_ip_str
#include "packet_parse.h"	// create_packet, read_packet
#include "buddy_list.h"
#include "buddy_status.h"	// qq_buddy_status
#include "buddy_opt.h"		// qq_add_buddy_by_recv_packet
#include "char_conv.h"		// qq_to_utf8
#include "crypt.h"		// qq_crypt
#include "header_info.h"	// cmd alias
#include "keep_alive.h"		// qq_refresh_all_buddy_status
#include "send_core.h"		// qq_send_cmd
#include "qq.h"			// qq_data

#define QQ_GET_ONLINE_BUDDY_02          0x02
#define QQ_GET_ONLINE_BUDDY_03          0x03	// unknown function

#define QQ_ONLINE_BUDDY_ENTRY_LEN       38

typedef struct _qq_friends_online_entry {
	qq_buddy_status *s;
	guint16 unknown1;
	guint8 flag1;
	guint8 comm_flag;
	guint16 unknown2;
	guint8 ending;		//0x00
} qq_friends_online_entry;

extern void			// defined in qq_buddy_status.c
 _qq_buddy_status_dump_unclear(qq_buddy_status * s);

extern gint			// defined in qq_buddy_status.c
 _qq_buddy_status_read(guint8 * data, guint8 ** cursor, gint len, qq_buddy_status * s);

/*****************************************************************************/
// get a list of online_buddies
void qq_send_packet_get_buddies_online(GaimConnection * gc, guint8 position)
{
	qq_data *qd;
	guint8 *raw_data, *cursor;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;
	raw_data = g_newa(guint8, 5);
	cursor = raw_data;

	// 000-000 get online friends cmd
	// only 0x02 and 0x03 returns info from server, other valuse all return 0xff
	// I can also only send the first byte (0x02, or 0x03)
	// and the result is the same
	create_packet_b(raw_data, &cursor, QQ_GET_ONLINE_BUDDY_02);
	// 001-001 seems it supports 255 online buddies at most
	create_packet_b(raw_data, &cursor, position);
	// 002-002
	create_packet_b(raw_data, &cursor, 0x00);
	// 003-004
	create_packet_w(raw_data, &cursor, 0x0000);

	qq_send_cmd(gc, QQ_CMD_GET_FRIENDS_ONLINE, TRUE, 0, TRUE, raw_data, 5);
	qd->last_get_online = time(NULL);

}				// qq_send_packet_get_buddies_online

/*****************************************************************************/
// position starts with 0x0000, 
// server may return a position tag if list is too long for one packet
void qq_send_packet_get_buddies_list(GaimConnection * gc, guint16 position)
{
	guint8 *raw_data, *cursor;
	gint data_len;

	g_return_if_fail(gc != NULL);

	data_len = 3;
	raw_data = g_newa(guint8, data_len);
	cursor = raw_data;
	// 000-001 starting position, can manually specify
	create_packet_w(raw_data, &cursor, position);
	// before Mar 18, 2004, any value can work, and we sent 00
	// I do not know what data QQ server is expecting, as QQ2003iii 0304 itself
	// even can sending packets 00 and get no response.
	// Now I tested that 00,00,00,00,00,01 work perfectly
	// March 22, fount the 00,00,00 starts to work as well
	create_packet_b(raw_data, &cursor, 0x00);

	qq_send_cmd(gc, QQ_CMD_GET_FRIENDS_LIST, TRUE, 0, TRUE, raw_data, data_len);

}				// qq_send_packet_get_buddies_list

/*****************************************************************************/
void _qq_buddies_online_reply_dump_unclear(qq_friends_online_entry * fe)
{
	GString *dump;

	g_return_if_fail(fe != NULL);

	_qq_buddy_status_dump_unclear(fe->s);

	dump = g_string_new("");
	g_string_append_printf(dump, "Unclear fields for [%d]:\n", fe->s->uid);
	g_string_append_printf(dump, "031-032: %04x (unknown)\n", fe->unknown1);
	g_string_append_printf(dump, "033:     %02x   (flag1)\n", fe->flag1);
	g_string_append_printf(dump, "034:     %02x   (comm_flag)\n", fe->comm_flag);
	g_string_append_printf(dump, "035-036: %04x (unknown)\n", fe->unknown2);

	gaim_debug(GAIM_DEBUG_INFO, "QQ", "Online buddy entry, %s", dump->str);
	g_string_free(dump, TRUE);
}				// _qq_buddies_online_reply_dump_unknown

/*****************************************************************************/
// process the reply packet for get_buddies_online packet
void qq_process_get_buddies_online_reply(guint8 * buf, gint buf_len, GaimConnection * gc) {

	qq_data *qd;
	gint len, bytes;
	guint8 *data, *cursor, position;
	GaimBuddy *b;
	qq_buddy *q_bud;
	qq_friends_online_entry *fe;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	g_return_if_fail(buf != NULL && buf_len != 0);

	qd = (qq_data *) gc->proto_data;
	len = buf_len;
	data = g_newa(guint8, len);
	cursor = data;

	if (qq_crypt(DECRYPT, buf, buf_len, qd->session_key, data, &len)) {

		read_packet_b(data, &cursor, len, &position);
		fe = g_newa(qq_friends_online_entry, 1);
		fe->s = g_newa(qq_buddy_status, 1);

		while (cursor < (data + len)) {
			// based on one online buddy entry
			bytes = 0;
			// 000-030 qq_buddy_status
			bytes += _qq_buddy_status_read(data, &cursor, len, fe->s);
			// 031-032: unknown4
			bytes += read_packet_w(data, &cursor, len, &fe->unknown1);
			// 033-033: flag1
			bytes += read_packet_b(data, &cursor, len, &fe->flag1);
			// 034-034: comm_flag
			bytes += read_packet_b(data, &cursor, len, &fe->comm_flag);
			// 035-036:
			bytes += read_packet_w(data, &cursor, len, &fe->unknown2);
			// 037-037:
			bytes += read_packet_b(data, &cursor, len, &fe->ending);	// 0x00

			if (fe->s->uid == 0 || bytes != QQ_ONLINE_BUDDY_ENTRY_LEN) {
				g_free(fe->s->ip);
				g_free(fe->s->unknown_key);
				continue;
			}	// check if it is a valid entry

			if (QQ_DEBUG)
				_qq_buddies_online_reply_dump_unclear(fe);

			// update buddy information
			b = gaim_find_buddy(gaim_connection_get_account(gc), uid_to_gaim_name(fe->s->uid));
			q_bud = (b == NULL) ? NULL : (qq_buddy *) b->proto_data;

			if (q_bud != NULL) {	// we find one and update qq_buddy
				g_memmove(q_bud->ip, fe->s->ip, 4);
				q_bud->port = fe->s->port;
				q_bud->status = fe->s->status;
				q_bud->flag1 = fe->flag1;
				q_bud->comm_flag = fe->comm_flag;
				qq_update_buddy_contact(gc, q_bud);
			}	// if q_bud

			g_free(fe->s->ip);
			g_free(fe->s->unknown_key);
		}		// while cursor

		if (position != QQ_FRIENDS_ONLINE_POSITION_END)
			qq_send_packet_get_buddies_online(gc, position);
		else
			qq_refresh_all_buddy_status(gc);

	} else
		gaim_debug(GAIM_DEBUG_ERROR, "QQ", "Error decrypt buddies online");

}				// qq_process_get_buddies_online_reply

/*****************************************************************************/
// process reply for get_buddies_list
void qq_process_get_buddies_list_reply(guint8 * buf, gint buf_len, GaimConnection * gc) {
	qq_data *qd;
	qq_buddy *q_bud;
	gint len, bytes, bytes_expected, i;
	guint16 position, unknown;
	guint8 *data, *cursor, bar, pascal_len;
	gchar *name;
	GaimBuddy *b;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	g_return_if_fail(buf != NULL && buf_len != 0);

	qd = (qq_data *) gc->proto_data;
	len = buf_len;
	data = g_newa(guint8, len);
	cursor = data;

	if (qq_crypt(DECRYPT, buf, buf_len, qd->session_key, data, &len)) {
		read_packet_w(data, &cursor, len, &position);
		// the following data is buddy list in this packet
		i = 0;
		while (cursor < (data + len)) {
			q_bud = g_new0(qq_buddy, 1);
			bytes = 0;
			// 000-003: uid
			bytes += read_packet_dw(data, &cursor, len, &q_bud->uid);
			// 004-004: 0xff if buddy is self, 0x00 otherwise
			bytes += read_packet_b(data, &cursor, len, &bar);
			// 005-005: icon index (1-255)
			bytes += read_packet_b(data, &cursor, len, &q_bud->icon);
			// 006-006: age
			bytes += read_packet_b(data, &cursor, len, &q_bud->age);
			// 007-007: gender
			bytes += read_packet_b(data, &cursor, len, &q_bud->gender);
			pascal_len = convert_as_pascal_string(cursor, &q_bud->nickname, QQ_CHARSET_DEFAULT);
			cursor += pascal_len;
			bytes += pascal_len;
			bytes += read_packet_w(data, &cursor, len, &unknown);
			/* flag1: (0-7)
			 *        bit1 => qq show
			 * comm_flag: (0-7)
			 *        bit1 => member
			 *        bit4 => TCP mode
			 *        bit5 => open mobile QQ
			 *        bit6 => bind to mobile
			 *        bit7 => whether having a video
			 */
			bytes += read_packet_b(data, &cursor, len, &q_bud->flag1);
			bytes += read_packet_b(data, &cursor, len, &q_bud->comm_flag);

			bytes_expected = 12 + pascal_len;

			if (q_bud->uid == 0 || bytes != bytes_expected) {
				gaim_debug(GAIM_DEBUG_INFO, "QQ",
					   "Buddy entry, expect %d bytes, read %d bytes\n", bytes_expected, bytes);
				g_free(q_bud->nickname);
				g_free(q_bud);
				continue;
			} else
				i++;

			if (QQ_DEBUG)
				gaim_debug(GAIM_DEBUG_INFO, "QQ",
					   "buddy [%09d]: flag1=0x%02x, comm_flag=0x%02x\n",
					   q_bud->uid, q_bud->flag1, q_bud->comm_flag);

			name = uid_to_gaim_name(q_bud->uid);
			b = gaim_find_buddy(gc->account, name);
			g_free(name);

			if (b == NULL)
				b = qq_add_buddy_by_recv_packet(gc, q_bud->uid, TRUE, FALSE);

			b->proto_data = q_bud;
			qd->buddies = g_list_append(qd->buddies, q_bud);
			qq_update_buddy_contact(gc, q_bud);
		}		// while cursor

		if (position == QQ_FRIENDS_LIST_POSITION_END) {
			gaim_debug(GAIM_DEBUG_INFO, "QQ", "Get friends list done, %d buddies\n", i);
			qq_send_packet_get_buddies_online(gc, QQ_FRIENDS_ONLINE_POSITION_START);
		} else
			qq_send_packet_get_buddies_list(gc, position);

	} else
		gaim_debug(GAIM_DEBUG_ERROR, "QQ", "Error decrypt buddies list");

}				// qq_process_get_buddies_list_reply

/*****************************************************************************/
// END OF FILE
