/**
 * @file buddy_list.h
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

#ifndef _QQ_BUDDY_LIST_H_
#define _QQ_BUDDY_LIST_H_

#include <glib.h>
#include "connection.h"

void qq_send_packet_get_buddies_online(PurpleConnection *gc, guint8 position);
guint8 qq_process_get_buddies_online_reply(guint8 *buf, gint buf_len, PurpleConnection *gc);
void qq_send_packet_get_buddies_list(PurpleConnection *gc, guint16 position);
guint16 qq_process_get_buddies_list_reply(guint8 *buf, gint buf_len, PurpleConnection *gc);
void qq_send_packet_get_all_list_with_group(PurpleConnection *gc, guint32 position);
guint32 qq_process_get_all_list_with_group_reply(guint8 *buf, gint buf_len, PurpleConnection *gc);

void qq_refresh_all_buddy_status(PurpleConnection *gc);
#endif
