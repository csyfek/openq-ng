/**
 * @file sendqueue.h
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

#ifndef _QQ_SEND_QUEUE_H_
#define _QQ_SEND_QUEUE_H_

#include <glib.h>
#include "qq.h"

void qq_trans_append(qq_data *qd, guint8 *buf, gint len, guint16 cmd);
void qq_trans_remove(qq_data *qd, gpointer data);
gpointer qq_trans_find(qq_data *qd, guint16 send_seq);
void qq_trans_remove_all(qq_data *qd);

gint qq_trans_scan(qq_data *qd, gint *start, guint8 *buf, gint maxlen, guint16 *cmd, gint *retries);

#endif
