/**
 * @file qq_network.h
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

#ifndef _QQ_PROXY_H
#define _QQ_PROXY_H

#include <glib.h>
#include "connection.h"

#include "qq.h"

#define QQ_CONNECT_STEPS    2	/* steps in connection */

gint qq_proxy_read(qq_data *qd, guint8 *data, gint len);
gint qq_proxy_write(qq_data *qd, guint8 *data, gint len);

gint qq_connect(PurpleAccount *account, const gchar *host, guint16 port, gboolean use_tcp);
void qq_disconnect(PurpleConnection *gc);

void qq_b4_packets_free(qq_data *qd);
void qq_input_pending(gpointer data, gint source, PurpleInputCondition cond);

gint qq_send_cmd(PurpleConnection *gc, guint16 cmd, gboolean is_auto_seq, guint16 seq, 
		gboolean need_ack, guint8 *data, gint len);
gint _qq_send_packet(PurpleConnection * gc, guint8 *buf, gint len, guint16 cmd);
gint _create_packet_head_seq(guint8 *buf, PurpleConnection *gc,
		guint16 cmd, gboolean is_auto_seq, guint16 *seq);
#endif
