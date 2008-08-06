/**
 * @file sendqueue.c
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

#include "internal.h"

#include "connection.h"
#include "debug.h"
#include "notify.h"
#include "prefs.h"
#include "request.h"

#include "header_info.h"
#include "qq_network.h"
#include "sendqueue.h"

#define QQ_RESEND_MAX               8	/* max resend per packet */

typedef struct _transaction {
	gint fd;
	guint8 *buf;
	gint buf_len;

	guint16 cmd;
	guint16 send_seq;

	gint retries;
	time_t sendtime;
} transaction;

void qq_trans_append(qq_data *qd, guint8 *buf, gint buf_len, guint16 cmd)
{
	transaction *trans = NULL;
	trans = g_new0(transaction, 1);

	trans->fd = qd->fd;
	trans->cmd = cmd;
	trans->send_seq = qd->send_seq;
	trans->retries = QQ_RESEND_MAX;
	trans->sendtime = time(NULL);
	trans->buf = g_memdup(buf, buf_len);	/* don't use g_strdup, may have 0x00 */
	trans->buf_len = buf_len;

	purple_debug(PURPLE_DEBUG_ERROR, "QQ",
			"Add to transaction, send_seq = %d, buf = %lu, len = %d\n",
			trans->send_seq, trans->buf, trans->buf_len);
	qd->transactions = g_list_append(qd->transactions, trans);
}

/* Remove a packet with send_seq from sendqueue */
void qq_trans_remove(qq_data *qd, gpointer data) 
{
	transaction *trans = (transaction *)data;

	g_return_if_fail(qd != NULL && data != NULL);
	
	if (trans->buf)	g_free(trans->buf);
	qd->transactions = g_list_remove(qd->transactions, trans);
	g_free(trans);
}

gpointer qq_trans_find(qq_data *qd, guint16 send_seq)
{
	GList *curr;
	GList *next;
	transaction *trans;

	curr = qd->transactions;
	while(curr) {
		next = curr->next;
		trans = (transaction *) (curr->data);
		if(trans->send_seq == send_seq) {
			return trans;
		}
		curr = next;
	}

	return NULL;
}

/* clean up sendqueue and free all contents */
void qq_trans_remove_all(qq_data *qd)
{
	GList *curr;
	GList *next;
	transaction *trans;
	gint count = 0;

	curr = qd->transactions;
	while(curr) {
		next = curr->next;
		
		trans = (transaction *) (curr->data);
		/*
		purple_debug(PURPLE_DEBUG_ERROR, "QQ",
			"Remove to transaction, send_seq = %d, buf = %lu, len = %d\n",
			trans->send_seq, trans->buf, trans->len);
		*/
		qq_trans_remove(qd, trans);

		count++;
		curr = next;
	}
	g_list_free(qd->transactions);

	purple_debug(PURPLE_DEBUG_INFO, "QQ", "%d packets in sendqueue are freed!\n", count);
}

gint qq_trans_scan(qq_data *qd, gint *start,
	guint8 *buf, gint maxlen, guint16 *cmd, gint *retries)
{
	GList *curr;
	GList *next = NULL;
	transaction *trans;
	gint copylen;

	g_return_val_if_fail(qd != NULL && *start >= 0 && maxlen > 0, -1);
	
	//purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Scan from %d\n", *start);
	curr = g_list_nth(qd->transactions, *start);
	while(curr) {
		next = curr->next;
		*start = g_list_position(qd->transactions, next);
		
		trans = (transaction *) (curr->data);
		if (trans->buf == NULL || trans->buf_len <= 0) {
			qq_trans_remove(qd, trans);
			curr = next;
			continue;
		}

		if (trans->retries < 0) {
			purple_debug(PURPLE_DEBUG_ERROR, "QQ",
				"Remove transaction, seq %d, buf %lu, len %d, retries %d, next %d\n",
				trans->send_seq, trans->buf, trans->buf_len, trans->retries, *start);
			qq_trans_remove(qd, trans);
			curr = next;
			continue;
		}

		purple_debug(PURPLE_DEBUG_ERROR, "QQ",
				"Resend transaction, seq %d, buf %lu, len %d, retries %d, next %d\n",
				trans->send_seq, trans->buf, trans->buf_len, trans->retries, *start);
		copylen = MIN(trans->buf_len, maxlen);
		g_memmove(buf, trans->buf, copylen);

		*cmd = trans->cmd;
		*retries = trans->retries;
		trans->retries--;
		return copylen;
	}

	// purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Scan finished\n");
	return -1;
}
