/**
 * @file qq.c The QQ2003C protocol plugin
 *
 * gaim
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

#include "internal.h"

#ifdef _WIN32
#define random rand
#endif

#include "debug.h"
#include "notify.h"
#include "prefs.h"
#include "request.h"
#include "accountopt.h"
#include "prpl.h"
#include "gtkroomlist.h"
#include "gtklog.h"
#include "server.h"

#include "utils.h"
#include "buddy_info.h"
#include "buddy_opt.h"
#include "buddy_status.h"
#include "char_conv.h"
#include "group_find.h"		/* qq_group_find_member_by_channel_and_nickname */
#include "group_im.h"		/* qq_send_packet_group_im */
#include "group_info.h"		/* qq_send_cmd_group_get_group_info */
#include "group_join.h"		/* qq_group_join */
#include "group_opt.h"		/* qq_group_manage_members */
#include "group.h"		/* chat_info, etc */
#include "header_info.h"	/* qq_get_cmd_desc */
#include "im.h"
#include "infodlg.h"
#include "keep_alive.h"
#include "ip_location.h"	/* qq_ip_get_location */
#include "login_logout.h"
#include "qq_proxy.h"		/* qq_connect, qq_disconnect */
#include "send_core.h"
#include "qq.h"
#include "send_file.h"
#include "version.h"

#define OPENQ_VER               VERSION
#define OPENQ_AUTHOR            "Puzzlebird"
#define OPENQ_WEBSITE		"http://openq.linuxsir.org"
#define QQ_TCP_QUERY_PORT       "8000"
#define QQ_UDP_PORT             "8000"

const gchar *udp_server_list[] = {
	"sz.tencent.com",	// 61.144.238.145
	"sz2.tencent.com",	// 61.144.238.146
	"sz3.tencent.com",	// 202.104.129.251
	"sz4.tencent.com",	// 202.104.129.254
	"sz5.tencent.com",	// 61.141.194.203
	"sz6.tencent.com",	// 202.104.129.252
	"sz7.tencent.com",	// 202.104.129.253
	"202.96.170.64",
	"64.144.238.155",
	"202.104.129.254"
};
const gint udp_server_amount = (sizeof(udp_server_list) / sizeof(udp_server_list[0]));


const gchar *tcp_server_list[] = {
	"tcpconn.tencent.com",	// 218.17.209.23
	"tcpconn2.tencent.com",	// 218.18.95.153
	"tcpconn3.tencent.com",	// 218.17.209.23
	"tcpconn4.tencent.com",	// 218.18.95.153
};
const gint tcp_server_amount = (sizeof(tcp_server_list) / sizeof(tcp_server_list[0]));

void _qq_login(GaimAccount * account)
{
	const gchar *qq_server, *qq_port;
	qq_data *qd;
	GaimConnection *gc;
	gboolean login_hidden, use_tcp;

	g_return_if_fail(account != NULL);

	gc = gaim_account_get_connection(account);
	g_return_if_fail(gc != NULL);

	gc->flags |= GAIM_CONNECTION_HTML | GAIM_CONNECTION_NO_BGCOLOR | GAIM_CONNECTION_AUTO_RESP;

	qd = g_new0(qq_data, 1);
	gc->proto_data = qd;

	qq_server = gaim_account_get_string(account, "server", NULL);
	qq_port = gaim_account_get_string(account, "port", NULL);
	use_tcp = gaim_account_get_bool(account, "use_tcp", FALSE);
	login_hidden = gaim_account_get_bool(account, "hidden", FALSE);

	qd->use_tcp = use_tcp;

	if (login_hidden)
		qd->login_mode = QQ_LOGIN_MODE_HIDDEN;
	else
		qd->login_mode = QQ_LOGIN_MODE_NORMAL;

	if (qq_server == NULL || strlen(qq_server) == 0)
		qq_server = use_tcp ?
		    tcp_server_list[random() % tcp_server_amount] : udp_server_list[random() % udp_server_amount];

	if (qq_port == NULL || strtol(qq_port, NULL, 10) == 0)
		qq_port = use_tcp ? QQ_TCP_QUERY_PORT : QQ_UDP_PORT;

	gaim_connection_update_progress(gc, _("Connecting"), 0, QQ_CONNECT_STEPS);

	if (qq_connect(account, qq_server, strtol(qq_port, NULL, 10), use_tcp, FALSE) < 0)
		gaim_connection_error(gc, _("Unable to connect."));
}

/* directly goes for qq_disconnect */
void _qq_close(GaimConnection * gc)
{
	g_return_if_fail(gc != NULL);
	qq_disconnect(gc);
}

/* returns the icon name for a buddy or protocol */
const gchar *_qq_list_icon(GaimAccount * a, GaimBuddy * b)
{
	gchar *filename;
	qq_buddy *q_bud;
	gchar icon_suffix;

	/* do not use g_return_val_if_fail, as it is not assertion */
	if (b == NULL || b->proto_data == NULL)
		return "qq";

	q_bud = (qq_buddy *) b->proto_data;
	icon_suffix = get_suffix_from_status(q_bud->status);
	filename = get_icon_name(q_bud->icon / 3 + 1, icon_suffix);

	return filename;
}

/* a short status text beside buddy icon (only shown in large icon mode) */
gchar *_qq_status_text(GaimBuddy * b)
{
	qq_buddy *q_bud;
	gboolean show_info, having_video;
	GString *status;
	gchar *ret;

	g_return_val_if_fail(b != NULL, NULL);

	show_info = gaim_prefs_get_bool("/plugins/prpl/qq/show_status_by_icon");
	if (!show_info)
		return NULL;

	q_bud = (qq_buddy *) b->proto_data;
	if (q_bud == NULL)
		return NULL;

	status = g_string_new("");

	switch (q_bud->gender) {
	case QQ_BUDDY_GENDER_GG:
		g_string_append(status, " GG");
		break;
	case QQ_BUDDY_GENDER_MM:
		g_string_append(status, " MM");
		break;
	case QQ_BUDDY_GENDER_UNKNOWN:
		g_string_append(status, "^_*");
		break;
	default:
		g_string_append(status, "^_^");
	}			/* switch gender */

	g_string_append_printf(status, " Age: %d", q_bud->age);

	having_video = q_bud->comm_flag & QQ_COMM_FLAG_VIDEO;
	/* As the font is too small for Chinese characters,
	 * 	I do not use get_text here
	 */
	if (having_video)
		g_string_append(status, " (video)");

	ret = status->str;
	g_string_free(status, FALSE);

	return ret;
}

/* a floating text when mouse is on the icon, show connection status here */
gchar *_qq_tooltip_text(GaimBuddy * b)
{
	qq_buddy *q_bud;
	gchar *ret;
	gchar *country, *country_utf8, *city, *city_utf8;
	guint32 ip_value;
	GString *tooltip;

	g_return_val_if_fail(b != NULL, NULL);

	q_bud = (qq_buddy *) b->proto_data;
	if (q_bud == NULL)
		return NULL;

	if (is_online(q_bud->status)) {
		ip_value = ntohl(*(guint32 *) (q_bud->ip));
		tooltip = g_string_new("\n");	/* gaim 0.77-cvs needs a "\n" */
		if (qq_ip_get_location(ip_value, &country, &city)) {
			country_utf8 = qq_to_utf8(country, QQ_CHARSET_DEFAULT);
			city_utf8 = qq_to_utf8(city, QQ_CHARSET_DEFAULT);
			g_string_append_printf(tooltip, "%s, %s\n", country_utf8, city_utf8);
			g_free(country);
			g_free(city);
			g_free(country_utf8);
			g_free(city_utf8);
		}
		g_string_append(tooltip, "<span foreground=\"blue\" font_desc=\"Courier 10\">");
		g_string_append_printf(tooltip, "[%s] %s</span>", (q_bud->comm_flag & QQ_COMM_FLAG_TCP_MODE)
				       ? "TCP" : "UDP", gen_ip_str(q_bud->ip));
		ret = tooltip->str;
		g_string_free(tooltip, FALSE);
		return ret;
	}

	return NULL;
}

/* we can show tiny icons on the four corners of buddy icon, */
/* but it is quite ugly with QQ icon, so I do nothing here */
void _qq_list_emblems(GaimBuddy * b, char **se, char **sw, char **nw, char **ne) {
	// each char ** are refering to filename in pixmaps/gaim/status/default/*png
	return;
}

/* QQ away status (used to initiate QQ away packet) */
GList *_qq_away_states(GaimConnection * gc)
{
	GList *m;

	g_return_val_if_fail(gc != NULL, NULL);

	m = NULL;
	m = g_list_append(m, _("QQ: Available"));
	m = g_list_append(m, _("QQ: Away"));
	m = g_list_append(m, _("QQ: Invisible"));
	m = g_list_append(m, GAIM_AWAY_CUSTOM);

	return m;
}

/* initiate QQ away with proper change_status packet */
void _qq_set_away(GaimConnection * gc, const char *state, const char *msg)
{
	qq_data *qd;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;
	if (gc->away) {
		g_free(gc->away);
		gc->away = NULL;
	}

	if (msg) {
		qd->status = QQ_SELF_STATUS_CUSTOM;
		gc->away = g_strdup(msg);
	} else if (state) {
		gc->away = g_strdup("");
		if (g_ascii_strcasecmp(state, _("QQ: Available")) == 0)
			qd->status = QQ_SELF_STATUS_AVAILABLE;
		else if (g_ascii_strcasecmp(state, _("QQ: Away")) == 0)
			qd->status = QQ_SELF_STATUS_AWAY;
		else if (g_ascii_strcasecmp(state, _("QQ: Invisible")) == 0)
			qd->status = QQ_SELF_STATUS_INVISIBLE;
		else if (g_ascii_strcasecmp(state, GAIM_AWAY_CUSTOM) == 0) {
			if (gc->is_idle)
				qd->status = QQ_SELF_STATUS_IDLE;
			else
				qd->status = QQ_SELF_STATUS_AVAILABLE;
		}
	} else if (gc->is_idle)
		qd->status = QQ_SELF_STATUS_IDLE;
	else
		qd->status = QQ_SELF_STATUS_AVAILABLE;

	qq_send_packet_change_status(gc);
}

/* send an instance msg to a buddy */
gint _qq_send_im(GaimConnection * gc, const gchar * who, const gchar * message, GaimConvImFlags flags) {
	gint type, to_uid;
	gchar *msg, *msg_with_qq_smiley;
	qq_data *qd;

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL && who != NULL, -1);

	qd = (qq_data *) gc->proto_data;

	g_return_val_if_fail(strlen(message) <= QQ_MSG_IM_MAX, -E2BIG);

	type = (flags == GAIM_CONV_IM_AUTO_RESP ? QQ_IM_AUTO_REPLY : QQ_IM_TEXT);
	to_uid = gaim_name_to_uid(who);

	/* if msg is to myself, bypass the network */
	if (to_uid == qd->uid)
		serv_got_im(gc, who, message, flags, time(NULL));
	else {
		msg = utf8_to_qq(message, QQ_CHARSET_DEFAULT);
		msg_with_qq_smiley = gaim_smiley_to_qq(msg);
		qq_send_packet_im(gc, to_uid, msg_with_qq_smiley, type);
		g_free(msg);
		g_free(msg_with_qq_smiley);
	}

	return 1;
}

/* send a chat msg to a QQ Qun */
gint _qq_chat_send(GaimConnection * gc, gint channel, const gchar * message)
{
	gchar *msg, *msg_with_qq_smiley;
	qq_group *group;

	g_return_val_if_fail(gc != NULL && message != NULL, -1);
	g_return_val_if_fail(strlen(message) <= QQ_MSG_IM_MAX, -E2BIG);

	group = qq_group_find_by_channel(gc, channel);
	g_return_val_if_fail(group != NULL, -1);

	msg = utf8_to_qq(message, QQ_CHARSET_DEFAULT);
	msg_with_qq_smiley = gaim_smiley_to_qq(msg);
	qq_send_packet_group_im(gc, group, msg_with_qq_smiley);
	g_free(msg);
	g_free(msg_with_qq_smiley);

	return 1;
}

/* send packet to get who's detailed information */
void _qq_get_info(GaimConnection * gc, const gchar * who)
{
	guint32 uid;
	qq_data *qd;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = gc->proto_data;
	uid = gaim_name_to_uid(who);

	if (uid <= 0) {
		gaim_debug(GAIM_DEBUG_ERROR, "QQ", "Not valid QQid: %s\n", who);
		gaim_notify_error(gc, NULL, _("Invalid name, please input in qq-xxxxxxxx format"), NULL);
		return;
	}

	qq_send_packet_get_info(gc, uid, TRUE);	/* need to show up info window */
}

/* get my own information */
void _qq_menu_get_my_info(GaimPluginAction * action)
{
	GaimConnection *gc = (GaimConnection *) action->context;
	qq_data *qd;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;
	_qq_get_info(gc, uid_to_gaim_name(qd->uid));
}

/* remove a buddy from my list and remove myself from his list */
void _qq_menu_block_buddy(GaimBlistNode * node, gpointer param_who)
{
	guint32 uid;
	gc_and_uid *g;
	GaimBuddy *buddy;
	GaimConnection *gc;
	const gchar *who = param_who;

	g_return_if_fail(GAIM_BLIST_NODE_IS_BUDDY(node));

	buddy = (GaimBuddy *) node;
	gc = gaim_account_get_connection(buddy->account);
	g_return_if_fail(gc != NULL && who != NULL);

	uid = gaim_name_to_uid(who);
	g_return_if_fail(uid > 0);

	g = g_new0(gc_and_uid, 1);
	g->gc = gc;
	g->uid = uid;

	gaim_request_action(gc, _("Block Buddy"),
			    _("Are you sure to block this buddy?"), NULL,
			    1, g, 2,
			    _("Cancel"),
			    G_CALLBACK(qq_do_nothing_with_gc_and_uid),
			    _("Block"), G_CALLBACK(qq_block_buddy_with_gc_and_uid));
}

/* show a brief summary of what we get from login packet */
void _qq_menu_show_login_info(GaimPluginAction * action)
{
	GaimConnection *gc = (GaimConnection *) action->context;
	qq_data *qd;
	GString *info;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;
	info = g_string_new("<html><body>\n");

	g_string_append_printf(info, _("<b>Current Online</b>: %d<br>\n"), qd->all_online);
	g_string_append_printf(info, _("<b>Last Refresh</b>: %s<br>\n"), ctime(&qd->last_get_online));

	g_string_append(info, "<hr>\n");

	g_string_append_printf(info, _("<b>Connection Mode</b>: %s<br>\n"), qd->use_tcp ? "TCP" : "UDP");
	g_string_append_printf(info, _("<b>Server IP</b>: %s: %d<br>\n"), qd->server_ip, qd->server_port);
	g_string_append_printf(info, _("<b>My Public IP</b>: %s<br>\n"), qd->my_ip);

	g_string_append(info, "<hr>\n");
	g_string_append(info, "<i>Information below may not be accurate</i><br>\n");

	g_string_append_printf(info, _("<b>Login Time</b>: %s<br>\n"), ctime(&qd->login_time));
	g_string_append_printf(info, _("<b>Last Login IP</b>: %s<br>\n"), qd->last_login_ip);
	g_string_append_printf(info, _("<b>Last Login Time</b>: %s\n"), ctime(&qd->last_login_time));

	g_string_append(info, "</body></html>");

	gaim_notify_formatted(gc, NULL, _("Login Information"), NULL, info->str, NULL, NULL);

	g_string_free(info, TRUE);
}

/* show about page about QQ plugin */
void _qq_menu_show_about(GaimPluginAction * action)
{
	GaimConnection *gc = (GaimConnection *) action->context;
	qq_data *qd;
	GString *info;
	gchar *head;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);

	qd = (qq_data *) gc->proto_data;
	info = g_string_new("<html><body>\n");

	g_string_append_printf(info, _("<b>Author</b> : %s<br>\n"), OPENQ_AUTHOR);
	g_string_append(info, "Copyright (c) 2004.  All rights reserved.<br><br>\n");

	g_string_append(info, _("<p><b>Code Contributors</b><br>\n"));
	g_string_append(info, "henryouly : file transfer, udp sock5 proxy and qq_show<br>\n");
	g_string_append(info, "arfankai  : fixed bugs in char_conv.c<br>\n");
	g_string_append(info, "rakescar  : provided filter for HTML tag<br>\n");
	g_string_append(info, "yyw       : improved performance on PPC linux<br>\n");
	g_string_append(info, "lvxiang   : provided ip to location original code<br><br>\n");

	g_string_append(info, _("<p><b>Acknowledgement</b><br>\n"));
	g_string_append(info, "Shufeng Tan : http://sf.net/projects/perl-oicq<br>\n");
	g_string_append(info, "Jeff Ye : http://www.sinomac.com<br>\n");
	g_string_append(info, "Hu Zheng : http://forlinux.yeah.net<br><br>\n");

	g_string_append(info, "<p>And, my parents...\n");

	g_string_append(info, "</body></html>");

	head = g_strdup_printf("About QQ Plugin Ver %s", OPENQ_VER);
	gaim_notify_formatted(gc, NULL, head, NULL, info->str, NULL, NULL);

	g_free(head);
	g_string_free(info, TRUE);
}

/* callback of sending any command to QQ server */
void _qq_menu_any_cmd_send_cb(GaimConnection * gc, GaimRequestFields * fields)
{
	GList *groups, *flds;
	GaimRequestField *field;
	const gchar *id, *value;
	gchar *cmd_str, *data_str, **segments;
	guint16 cmd;
	guint8 *data;
	gint i, data_len;

	cmd_str = NULL;
	data_str = NULL;
	cmd = 0x00;
	data = NULL;
	data_len = 0;

	for (groups = gaim_request_fields_get_groups(fields); groups; groups = groups->next) {
		for (flds = gaim_request_field_group_get_fields(groups->data); flds; flds = flds->next) {
			field = flds->data;
			id = gaim_request_field_get_id(field);
			value = gaim_request_field_string_get_value(field);

			if (!g_ascii_strcasecmp(id, "cmd"))
				cmd_str = g_strdup(value);
			else if (!g_ascii_strcasecmp(id, "data"))
				data_str = g_strdup(value);
		}
	}

	if (cmd_str != NULL)
		cmd = (guint16) strtol(cmd_str, NULL, 16);

	if (data_str != NULL) {
		if (NULL == (segments = split_data(data_str, strlen(data_str), ",", 0))) {
			g_free(cmd_str);
			g_free(data_str);
			return;
		}
		for (data_len = 0; segments[data_len] != NULL; data_len++) {;
		}
		data = g_newa(guint8, data_len);
		for (i = 0; i < data_len; i++)
			data[i] = (guint8) strtol(segments[i], NULL, 16);
		g_strfreev(segments);
	}

	if (cmd && data_len > 0) {
		gaim_debug(GAIM_DEBUG_INFO, "QQ",
			   "Send Any cmd: %s, data dump\n%s", qq_get_cmd_desc(cmd), hex_dump_to_str(data, data_len));
		qq_send_cmd(gc, cmd, TRUE, 0, TRUE, data, data_len);
	}

	g_free(cmd_str);
	g_free(data_str);
}				

/* send any command with data to QQ server, for testing and debuggin only */
void _qq_menu_any_cmd(GaimPluginAction * action)
{
	GaimConnection *gc = (GaimConnection *) action->context;
	qq_data *qd;
	gchar *tips;
	GaimRequestField *field;
	GaimRequestFields *fields;
	GaimRequestFieldGroup *group;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	tips = _("Separate the value with \",\"\nAllow \"0x\" before each value");
	fields = gaim_request_fields_new();
	group = gaim_request_field_group_new(NULL);
	gaim_request_fields_add_group(fields, group);

	/* sample: 0x22 */
	field = gaim_request_field_string_new("cmd", _("CMD Code"), NULL, FALSE);
	gaim_request_field_group_add_field(group, field);
	/* sample: 0x00,0x15,0xAB */
	/*     or: 00,15,AB */
	/* the delimit is ",", allow 0x before the value */
	field = gaim_request_field_string_new("data", _("Raw Data"), NULL, FALSE);
	gaim_request_field_group_add_field(group, field);

	gaim_request_fields(gc, _("QQ Any Command"),
			    _("Send Arbitrary Command"), tips, fields,
			    _("Send"), G_CALLBACK(_qq_menu_any_cmd_send_cb), _("Cancel"), NULL, gc);
}


void _qq_menu_search_or_add_permanent_group(GaimPluginAction * action)
{
	gaim_gtk_roomlist_dialog_show();
}

void _qq_menu_create_permanent_group(GaimPluginAction * action)
{
	GaimConnection *gc = (GaimConnection *) action->context;
	g_return_if_fail(gc != NULL);
	gaim_request_input(gc, _("Create QQ Qun"),
			   _("Input Qun name here"),
			   _("Only QQ member can create permanent Qun"),
			   "OpenQ", FALSE, FALSE, NULL,
			   _("Create"), G_CALLBACK(qq_group_create_with_name), _("Cancel"), NULL, gc);
}

void _qq_menu_unsubscribe_group(GaimBlistNode * node, gpointer param_components)
{
	GaimBuddy *buddy;
	GaimConnection *gc;
	GHashTable *components = (GHashTable *) param_components;

	g_return_if_fail(GAIM_BLIST_NODE_IS_BUDDY(node));

	buddy = (GaimBuddy *) node;
	gc = gaim_account_get_connection(buddy->account);

	g_return_if_fail(gc != NULL && components != NULL);
	qq_group_exit(gc, components);
}

void _qq_menu_manage_group(GaimBlistNode * node, gpointer param_components)
{
	GaimBuddy *buddy;
	GaimConnection *gc;
	GHashTable *components = (GHashTable *) param_components;

	g_return_if_fail(GAIM_BLIST_NODE_IS_BUDDY(node));

	buddy = (GaimBuddy *) node;
	gc = gaim_account_get_connection(buddy->account);

	g_return_if_fail(gc != NULL && components != NULL);
	qq_group_manage_group(gc, components);
}

void _qq_menu_show_system_message(GaimPluginAction *action)
{
	GaimConnection *gc = (GaimConnection *) action->context;
	g_return_if_fail ( gc != NULL );
	gaim_gtk_log_show(GAIM_LOG_IM, "systemim", gaim_connection_get_account(gc));
}

void _qq_menu_send_file(GaimBlistNode * node, gpointer ignored)
{
	GaimBuddy *buddy;
	GaimConnection *gc;
	qq_buddy *q_bud;

	g_return_if_fail (GAIM_BLIST_NODE_IS_BUDDY (node));
	buddy = (GaimBuddy *) node;
	q_bud = (qq_buddy *) buddy->proto_data;
//	if (is_online (q_bud->status)) {
	gc = gaim_account_get_connection (buddy->account);
	g_return_if_fail (gc != NULL && gc->proto_data != NULL);
	qq_send_file(gc, buddy->name, NULL);
//	}
}

/* protocol related menus */
GList *_qq_actions(GaimPlugin * plugin, gpointer context)
{
	GList *m;
	GaimPluginAction *act;

	m = NULL;
	act = gaim_plugin_action_new(_("Modify My Information"), _qq_menu_get_my_info);
	m = g_list_append(m, act);

	act = gaim_plugin_action_new(_("Show Login Information"), _qq_menu_show_login_info);
	m = g_list_append(m, act);

	act = gaim_plugin_action_new(_("Show System Message"), _qq_menu_show_system_message);
	m = g_list_append(m, act);

	act = gaim_plugin_action_new(_("Any QQ Command"), _qq_menu_any_cmd);
	m = g_list_append(m, act);

	act = gaim_plugin_action_new(_("Qun: Search a permanent Qun"), _qq_menu_search_or_add_permanent_group);
	m = g_list_append(m, act);

	act = gaim_plugin_action_new(_("Qun: Create a permanent Qun"), _qq_menu_create_permanent_group);
	m = g_list_append(m, act);

	act = gaim_plugin_action_new(_("About QQ Plugin"), _qq_menu_show_about);
	m = g_list_append(m, act);

	return m;
}

/* buddy-related menu shown up with right-click */
GList *_qq_buddy_menu(GaimBlistNode * node)
{
	GList *m;
	GaimBlistNodeAction *act;

	m = NULL;
	act = gaim_blist_node_action_new(_("Block this buddy"), _qq_menu_block_buddy, NULL);
	m = g_list_append(m, act);
//	if (q_bud && is_online(q_bud->status)) {
		act = gaim_blist_node_action_new(_("Send File"), _qq_menu_send_file, NULL);
		m = g_list_append(m, act);
//	}

	return m;
}

/* chat-related (QQ Qun) menu shown up with right-click */
GList *_qq_chat_menu(GaimConnection * gc, GHashTable * components)
{
	GList *m;
	GaimBlistNodeAction *act;

	m = NULL;
	act = gaim_blist_node_action_new(_("Exit this QQ Qun"), _qq_menu_unsubscribe_group, NULL);
	m = g_list_append(m, act);

	act = gaim_blist_node_action_new(_("Show Details"), _qq_menu_manage_group, NULL);
	m = g_list_append(m, act);

	return m;
}

void _qq_keep_alive(GaimConnection * gc)
{
	qq_group *group;
	qq_data *qd;
	GList *list;

	g_return_if_fail(gc != NULL);
	if (NULL == (qd = (qq_data *) gc->proto_data))
		return;

	list = qd->groups;
	while (list != NULL) {
		group = (qq_group *) list->data;
		if (group->my_status == QQ_GROUP_MEMBER_STATUS_IS_MEMBER ||
		    group->my_status == QQ_GROUP_MEMBER_STATUS_IS_ADMIN)
			qq_send_cmd_group_get_group_info(gc, group);
		list = list->next;
	}

	qq_send_packet_keep_alive(gc);

}

/* convert chat nickname to qq-uid to get this buddy info */
/* who is the nickname of buddy in QQ chat-room (Qun) */
void _qq_get_chat_buddy_info(GaimConnection * gc, gint channel, const gchar * who)
{
	gchar *gaim_name;
	g_return_if_fail(gc != NULL && gc->proto_data != NULL && who != NULL);

	gaim_name = qq_group_find_member_by_channel_and_nickname(gc, channel, who);
	if (gaim_name != NULL)
		_qq_get_info(gc, gaim_name);

}

/* convert chat nickname to qq-uid to invite individual IM to buddy */
/* who is the nickname of buddy in QQ chat-room (Qun) */
gchar *_qq_get_chat_buddy_real_name(GaimConnection * gc, gint channel, const gchar * who) {

	g_return_val_if_fail(gc != NULL && gc->proto_data != NULL && who != NULL, NULL);
	return qq_group_find_member_by_channel_and_nickname(gc, channel, who);

}

void qq_function_not_implemented(GaimConnection * gc)
{
	gaim_notify_warning(gc, NULL, _("This function has not be implemented yet"), _("Please wait for new version"));
}

GaimPluginPrefFrame *get_plugin_pref_frame(GaimPlugin * plugin)
{
	GaimPluginPrefFrame *frame;
	GaimPluginPref *ppref;

	frame = gaim_plugin_pref_frame_new();

	ppref = gaim_plugin_pref_new_with_label(_("Convert IP to location"));
	gaim_plugin_pref_frame_add(frame, ppref);

	ppref = gaim_plugin_pref_new_with_name_and_label("/plugins/prpl/qq/ipfile", _("IP file"));
	gaim_plugin_pref_frame_add(frame, ppref);

	ppref = gaim_plugin_pref_new_with_label(_("Display Options"));
	gaim_plugin_pref_frame_add(frame, ppref);

	ppref = gaim_plugin_pref_new_with_name_and_label
	    ("/plugins/prpl/qq/show_status_by_icon", _("Show gender/age information beside buddy icons"));
	gaim_plugin_pref_frame_add(frame, ppref);

	ppref = gaim_plugin_pref_new_with_name_and_label
	    ("/plugins/prpl/qq/show_fake_video", _("Fake an video for GAIM QQ (re-login to activate)"));
	gaim_plugin_pref_frame_add(frame, ppref);

	ppref = gaim_plugin_pref_new_with_label(_("System Options"));
	gaim_plugin_pref_frame_add(frame, ppref);

	ppref = gaim_plugin_pref_new_with_name_and_label
	    ("/plugins/prpl/qq/prompt_for_missing_packet", _("Prompt user for actions if there are missing packets"));
	gaim_plugin_pref_frame_add(frame, ppref);

	ppref = gaim_plugin_pref_new_with_name_and_label
	    ("/plugins/prpl/qq/prompt_group_msg_on_recv", _("Pop up Qun chat window when receive Qun message"));
	gaim_plugin_pref_frame_add(frame, ppref);

	ppref = gaim_plugin_pref_new_with_name_and_label("/plugins/prpl/qq/datadir", _("OpenQ installed directory"));
	gaim_plugin_pref_frame_add(frame, ppref);

	return frame;

}

GaimPlugin *my_protocol = NULL;
static GaimPluginProtocolInfo prpl_info	= {
	OPT_PROTO_CHAT_TOPIC | OPT_PROTO_USE_POINTSIZE,
	NULL,				/* user_splits	*/
	NULL,				/* protocol_options */
	NO_BUDDY_ICONS,			/* icon_spec */
	_qq_list_icon,			/* list_icon */
	_qq_list_emblems,		/* list_emblems */
	_qq_status_text,		/* status_text	*/
	_qq_tooltip_text,		/* tooltip_text */
	_qq_away_states,		/* away_states	*/
	_qq_buddy_menu,			/* blist_node_menu */
	qq_chat_info,			/* chat_info */
	NULL,				/* chat_info_defaults */
	_qq_login,			/* login */
	_qq_close,			/* close */
	_qq_send_im,			/* send_im */
	NULL,				/* set_info */
	NULL,				/* send_typing	*/
	_qq_get_info,			/* get_info */
	_qq_set_away,			/* set_away */
	NULL,				/* set_idle */
	NULL,				/* change_passwd */
	qq_add_buddy,			/* add_buddy */
	NULL,				/* add_buddies	*/
	qq_remove_buddy,		/* remove_buddy */
	NULL,				/* remove_buddies */
	NULL,				/* add_permit */
	NULL,				/* add_deny */
	NULL,				/* rem_permit */
	NULL,				/* rem_deny */
	NULL,				/* set_permit_deny */
	NULL,				/* warn */
	qq_group_join,			/* join_chat */
	NULL,				/* reject chat	invite */
	NULL,				/* get_chat_name */
	NULL,				/* chat_invite	*/
	NULL,				/* chat_leave */
	NULL,				/* chat_whisper */
	_qq_chat_send,			/* chat_send */
	_qq_keep_alive,			/* keepalive */
	NULL,				/* register_user */
	_qq_get_chat_buddy_info,	/* get_cb_info	*/
	NULL,				/* get_cb_away	*/
	NULL,				/* alias_buddy	*/
	NULL,				/* group_buddy	*/
	NULL,				/* rename_group */
	NULL,				/* buddy_free */
	NULL,				/* convo_closed */
	NULL,				/* normalize */
	NULL,				/* set_buddy_icon */
	NULL,				/* remove_group */
	_qq_get_chat_buddy_real_name,	/* get_cb_real_name */
	NULL,				/* set_chat_topic */
	NULL,				/* find_blist_chat */
	qq_roomlist_get_list,		/* roomlist_get_list */
	qq_roomlist_cancel,		/* roomlist_cancel */
	NULL,				/* roomlist_expand_category */
	NULL,				/* can_receive_file */
	NULL				/* send_file */
};

static GaimPluginUiInfo prefs_info = {
	get_plugin_pref_frame
};

static GaimPluginInfo info = {
	GAIM_PLUGIN_MAGIC,
	GAIM_MAJOR_VERSION,
	GAIM_MINOR_VERSION,
	GAIM_PLUGIN_PROTOCOL,		/**< type		*/
	NULL,				/**< ui_requirement	*/
	0,				/**< flags		*/
	NULL,				/**< dependencies	*/
	GAIM_PRIORITY_DEFAULT,		/**< priority		*/

	"prpl-qq",			/**< id			*/
	"QQ",				/**< name		*/
	OPENQ_VER,			/**< version		*/
					/**  summary		*/
	N_("QQ Protocol	Plugin"),
					/**  description	*/
	N_("QQ Protocol	Plugin"),
	OPENQ_AUTHOR,			/**< author		*/
	OPENQ_WEBSITE,			/**< homepage		*/

	NULL,				/**< load		*/
	NULL,				/**< unload		*/
	NULL,				/**< destroy		*/

	NULL,				/**< ui_info		*/
	&prpl_info,			/**< extra_info		*/
	&prefs_info,			/**< prefs_info		*/
	_qq_actions
};


void init_plugin(GaimPlugin * plugin)
{
	GaimAccountOption *option;

	bindtextdomain(PACKAGE, LOCALEDIR);
	bind_textdomain_codeset(PACKAGE, "UTF-8");

	option = gaim_account_option_bool_new(_("Login in TCP"), "use_tcp", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = gaim_account_option_bool_new(_("Login Hidden"), "hidden", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = gaim_account_option_string_new(_("QQ Server"), "server", NULL);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = gaim_account_option_string_new(_("QQ Port"), "port", NULL);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	my_protocol = plugin;

	gaim_prefs_add_none("/plugins/prpl/qq");
	gaim_prefs_add_string("/plugins/prpl/qq/ipfile", NULL);
	gaim_prefs_add_bool("/plugins/prpl/qq/show_status_by_icon", TRUE);
	gaim_prefs_add_bool("/plugins/prpl/qq/show_fake_video", FALSE);
	gaim_prefs_add_string("/plugins/prpl/qq/datadir", DATADIR);
	gaim_prefs_add_bool("/plugins/prpl/qq/prompt_for_missing_packet", FALSE);
	gaim_prefs_add_bool("/plugins/prpl/qq/prompt_group_msg_on_recv", TRUE);
}

GAIM_INIT_PLUGIN(qq, init_plugin, info);
