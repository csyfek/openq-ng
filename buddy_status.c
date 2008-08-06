/**
 * @file buddy_status.c
 *
 * purple
 *
 * Purple is the legal property ofr its developers, whose names are too numerous
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

#include <string.h>
#include "internal.h"
#include "debug.h"
#include "prefs.h"

#include "buddy_info.h"
#include "buddy_status.h"
#include "crypt.h"
#include "header_info.h"
#include "qq_base.h"
#include "packet_parse.h"
#include "utils.h"

#include "qq_network.h"

#define QQ_MISC_STATUS_HAVING_VIIDEO      0x00000001
#define QQ_CHANGE_ONLINE_STATUS_REPLY_OK 	0x30	/* ASCII value of "0" */

/* TODO: figure out what's going on with the IP region. Sometimes I get valid IP addresses, 
 * but the port number's weird, other times I get 0s. I get these simultaneously on the same buddy, 
 * using different accounts to get info. */

/* parse the data into qq_buddy_status */
gint qq_buddy_status_read(qq_buddy_status *bs, guint8 *data)
{
	gint bytes = 0;

	g_return_val_if_fail(data != NULL && bs != NULL, -1);

	/* 000-003: uid */
	bytes += qq_get32(&bs->uid, data + bytes);
	/* 004-004: 0x01 */
	bytes += qq_get8(&bs->unknown1, data + bytes);
	/* this is no longer the IP, it seems QQ (as of 2006) no longer sends
	 * the buddy's IP in this packet. all 0s */
	/* 005-008: ip */
	bytes += qq_get32((guint32 *)&(bs->ip), data + bytes);
	/* port info is no longer here either */
	/* 009-010: port */
	bytes += qq_get16(&bs->port, data + bytes);
	/* 011-011: 0x00 */
	bytes += qq_get8(&bs->unknown2, data + bytes);
	/* 012-012: status */
	bytes += qq_get8(&bs->status, data + bytes);
	/* 013-014: client_version */
	bytes += qq_get16(&bs->unknown3, data + bytes);
	/* 015-030: unknown key */
	bytes += qq_getdata(&(bs->unknown_key[0]), QQ_KEY_LENGTH, data + bytes);

	purple_debug(PURPLE_DEBUG_INFO, "QQ_STATUS", 
			"uid: %d, un1: %d, ip: %s:%d, un2:%d, status:%d, un3:%04X\n", 
			bs->uid, bs->unknown1, inet_ntoa(bs->ip), bs->port,
			bs->unknown2, bs->status, bs->unknown3);

	if (bs->uid == 0 || bytes != 31)
		return -1;

	return bytes;
}

/* check if status means online or offline */
gboolean is_online(guint8 status)
{
	switch(status) {
		case QQ_BUDDY_ONLINE_NORMAL:
		case QQ_BUDDY_ONLINE_AWAY:
		case QQ_BUDDY_ONLINE_INVISIBLE:
			return TRUE;
		case QQ_BUDDY_ONLINE_OFFLINE:
			return FALSE;
	}
	return FALSE;
}

/* Help calculate the correct icon index to tell the server. */
gint get_icon_offset(PurpleConnection *gc)
{ 
	PurpleAccount *account;
	PurplePresence *presence; 

	account = purple_connection_get_account(gc);
	presence = purple_account_get_presence(account);

	if (purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_INVISIBLE)) {
		return 2;
	} else if (purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_AWAY)
			|| purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_EXTENDED_AWAY)
			|| purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_UNAVAILABLE)) {
		return 1;
	} else {
		return 0;
	}
}

/* send a packet to change my online status */
void qq_send_packet_change_status(PurpleConnection *gc)
{
	qq_data *qd;
	guint8 raw_data[16] = {0};
	gint bytes = 0;
	guint8 away_cmd;
	guint32 misc_status;
	gboolean fake_video;
	PurpleAccount *account;
	PurplePresence *presence; 

	account = purple_connection_get_account(gc);
	presence = purple_account_get_presence(account);

	qd = (qq_data *) gc->proto_data;
	if (!qd->logged_in)
		return;

	if (purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_INVISIBLE)) {
		away_cmd = QQ_BUDDY_ONLINE_INVISIBLE;
	} else if (purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_AWAY)
			|| purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_EXTENDED_AWAY)
			|| purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_UNAVAILABLE)) {
		away_cmd = QQ_BUDDY_ONLINE_AWAY;
	} else {
		away_cmd = QQ_BUDDY_ONLINE_NORMAL;
	}

	misc_status = 0x00000000;
	fake_video = purple_prefs_get_bool("/plugins/prpl/qq/show_fake_video");
	if (fake_video)
		misc_status |= QQ_MISC_STATUS_HAVING_VIIDEO;

	bytes = 0;
	bytes += qq_put8(raw_data + bytes, away_cmd);
	bytes += qq_put32(raw_data + bytes, misc_status);

	qq_send_cmd(qd, QQ_CMD_CHANGE_ONLINE_STATUS, raw_data, bytes);
}

/* parse the reply packet for change_status */
void qq_process_change_status_reply(guint8 *buf, gint buf_len, PurpleConnection *gc)
{
	qq_data *qd;
	gint len, bytes;
	guint8 *data, reply;
	PurpleBuddy *b;
	qq_buddy *q_bud;
	gchar *name;

	g_return_if_fail(buf != NULL && buf_len != 0);

	qd = (qq_data *) gc->proto_data;
	len = buf_len;
	data = g_newa(guint8, len);

	if ( !qq_decrypt(buf, buf_len, qd->session_key, data, &len) ) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Error decrypt chg status reply\n");
		return;
	}

	bytes = 0;
	bytes = qq_get8(&reply, data + bytes);
	if (reply != QQ_CHANGE_ONLINE_STATUS_REPLY_OK) {
		purple_debug(PURPLE_DEBUG_WARNING, "QQ", "Change status fail\n");
	} else {
		purple_debug(PURPLE_DEBUG_INFO, "QQ", "Change status OK\n");
		name = uid_to_purple_name(qd->uid);
		b = purple_find_buddy(gc->account, name);
		g_free(name);
		q_bud = (b == NULL) ? NULL : (qq_buddy *) b->proto_data;
		if (q_bud != NULL) {
			qq_update_buddy_contact(gc, q_bud);
		}
	}
}

/* it is a server message indicating that one of my buddies has changed its status */
void qq_process_buddy_change_status(guint8 *buf, gint buf_len, PurpleConnection *gc) 
{
	qq_data *qd;
	gint len, bytes;
	guint32 my_uid;
	guint8 *data;
	PurpleBuddy *b;
	qq_buddy *q_bud;
	qq_buddy_status bs;
	gchar *name;

	g_return_if_fail(buf != NULL && buf_len != 0);

	qd = (qq_data *) gc->proto_data;
	len = buf_len;
	data = g_newa(guint8, len);

	if ( !qq_decrypt(buf, buf_len, qd->session_key, data, &len) ) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Error decrypt buddy status change packet\n");
		return;
	}

	memset(&bs, 0, sizeof(bs));
	bytes = 0;
	/* 000-030: qq_buddy_status */
	bytes += qq_buddy_status_read(&bs, data + bytes);
	/* 031-034:  Unknow, maybe my uid */ 
	/* This has a value of 0 when we've changed our status to 
	 * QQ_BUDDY_ONLINE_INVISIBLE */
	bytes += qq_get32(&my_uid, data + bytes);

	purple_debug(PURPLE_DEBUG_INFO, "QQ",
		"set new server to %s:%d\n", qd->real_hostname, qd->real_port);

	if (bytes != 35) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "bytes(%d) != 35\n", bytes);
		return;
	}

	name = uid_to_purple_name(bs.uid);
	b = purple_find_buddy(gc->account, name);
	g_free(name);
	q_bud = (b == NULL) ? NULL : (qq_buddy *) b->proto_data;
	if (q_bud) {
		purple_debug(PURPLE_DEBUG_INFO, "QQ", "status:.uid = %d, q_bud->uid = %d\n", bs.uid , q_bud->uid);
		if(bs.ip.s_addr != 0) { 
			g_memmove(&(q_bud->ip), &bs.ip, sizeof(q_bud->ip));
			q_bud->port = bs.port;
		}
		q_bud->status =bs.status;

		if (q_bud->status == QQ_BUDDY_ONLINE_NORMAL) {
			qq_send_packet_get_level(gc, q_bud->uid);
		}
		qq_update_buddy_contact(gc, q_bud);
	} else {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", 
				"got information of unknown buddy %d\n", bs.uid);
	}
}

/*TODO: maybe this should be qq_update_buddy_status() ?*/
void qq_update_buddy_contact(PurpleConnection *gc, qq_buddy *q_bud)
{
	gchar *name;
	PurpleBuddy *bud;
	gchar *status_id;
	
	g_return_if_fail(q_bud != NULL);

	name = uid_to_purple_name(q_bud->uid);
	bud = purple_find_buddy(gc->account, name);
	g_return_if_fail(bud != NULL);

	if (bud != NULL) {
		purple_blist_server_alias_buddy(bud, q_bud->nickname); /* server */
		q_bud->last_refresh = time(NULL);

		/* purple supports signon and idle time
		 * but it is not much use for QQ, I do not use them */
		/* serv_got_update(gc, name, online, 0, q_bud->signon, q_bud->idle, bud->uc); */
		status_id = "available";
		switch(q_bud->status) {
		case QQ_BUDDY_OFFLINE:
			status_id = "offline";
			break;
		case QQ_BUDDY_ONLINE_NORMAL:
			status_id = "available";
			break;
		case QQ_BUDDY_ONLINE_OFFLINE:
			status_id = "offline";
			break;
	        case QQ_BUDDY_ONLINE_AWAY:
			status_id = "away";
			break;
	       	case QQ_BUDDY_ONLINE_INVISIBLE:
			status_id = "invisible";
			break;
		default:
			status_id = "invisible";
			purple_debug(PURPLE_DEBUG_ERROR, "QQ", "unknown status: %x\n", q_bud->status);
			break;
		}
		purple_debug(PURPLE_DEBUG_INFO, "QQ", "set buddy %d to %s\n", q_bud->uid, status_id);
		purple_prpl_got_user_status(gc->account, name, status_id, NULL);

		if (q_bud->comm_flag & QQ_COMM_FLAG_BIND_MOBILE && q_bud->status != QQ_BUDDY_OFFLINE)
			purple_prpl_got_user_status(gc->account, name, "mobile", NULL);
		else
			purple_prpl_got_user_status_deactive(gc->account, name, "mobile");
	} else {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "unknown buddy: %d\n", q_bud->uid);
	}

	purple_debug(PURPLE_DEBUG_INFO, "QQ", "qq_update_buddy_contact, client=%04x\n", q_bud->client_version);
	g_free(name);
}

/* refresh all buddies online/offline,
 * after receiving reply for get_buddies_online packet */
void qq_refresh_all_buddy_status(PurpleConnection *gc)
{
	time_t now;
	GList *list;
	qq_data *qd;
	qq_buddy *q_bud;

	qd = (qq_data *) (gc->proto_data);
	now = time(NULL);
	list = qd->buddies;

	while (list != NULL) {
		q_bud = (qq_buddy *) list->data;
		if (q_bud != NULL && now > q_bud->last_refresh + QQ_UPDATE_ONLINE_INTERVAL
				&& q_bud->status != QQ_BUDDY_ONLINE_INVISIBLE) {
			q_bud->status = QQ_BUDDY_ONLINE_OFFLINE;
			qq_update_buddy_contact(gc, q_bud);
		}
		list = list->next;
	}
}
