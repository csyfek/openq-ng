/**
 * @file qq_base.c
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

#include "debug.h"
#include "internal.h"
#include "server.h"
#include "cipher.h"

#include "buddy_info.h"
#include "buddy_list.h"
#include "char_conv.h"
#include "crypt.h"
#include "group.h"
#include "header_info.h"
#include "qq_base.h"
#include "packet_parse.h"
#include "qq.h"
#include "qq_network.h"
#include "utils.h"

#define QQ_LOGIN_DATA_LENGTH		    416
#define QQ_LOGIN_REPLY_OK_PACKET_LEN        139
#define QQ_LOGIN_REPLY_REDIRECT_PACKET_LEN  11

/* for QQ 2003iii 0117, fixed value */
/* static const guint8 login_23_51[29] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xbf, 0x14, 0x11, 0x20,
	0x03, 0x9d, 0xb2, 0xe6, 0xb3, 0x11, 0xb7, 0x13,
	0x95, 0x67, 0xda, 0x2c, 0x01 
}; */

/* for QQ 2003iii 0304, fixed value */
/*
static const guint8 login_23_51[29] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x9a, 0x93, 0xfe, 0x85,
	0xd3, 0xd9, 0x2a, 0x41, 0xc8, 0x0d, 0xff, 0xb6,
	0x40, 0xb8, 0xac, 0x32, 0x01
};
*/

/* for QQ 2005? copy from lumaqq */
/* FIXME: change to guint8 */
static const guint8 login_23_51[29] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x86, 0xcc, 0x4c, 0x35,
	0x2c, 0xd3, 0x73, 0x6c, 0x14, 0xf6, 0xf6, 0xaf,
	0xc3, 0xfa, 0x33, 0xa4, 0x01
};

static const guint8 login_53_68[16] = {
 	0x8D, 0x8B, 0xFA, 0xEC, 0xD5, 0x52, 0x17, 0x4A,
 	0x86, 0xF9, 0xA7, 0x75, 0xE6, 0x32, 0xD1, 0x6D
};

static const guint8 login_100_bytes[100] = {
	0x40, 0x0B, 0x04, 0x02, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 0x09, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0xE9, 0x03, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xF3, 0x03,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xED,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0xEC, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x03, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0xEE, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0xEF, 0x03, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0xEB, 0x03, 0x00,
	0x00, 0x00, 0x00, 0x00
};


/* fixed value, not affected by version, or mac address */
/*
static const guint8 login_53_68[16] = {
	0x82, 0x2a, 0x91, 0xfd, 0xa5, 0xca, 0x67, 0x4c,
	0xac, 0x81, 0x1f, 0x6f, 0x52, 0x05, 0xa7, 0xbf
};
*/


typedef struct _qq_login_reply_ok qq_login_reply_ok_packet;
typedef struct _qq_login_reply_redirect qq_login_reply_redirect_packet;

struct _qq_login_reply_ok {
	guint8 result;
	guint8 *session_key;
	guint32 uid;
	guint8 client_ip[4];	/* those detected by server */
	guint16 client_port;
	guint8 server_ip[4];
	guint16 server_port;
	time_t login_time;
	guint8 unknown1[26];
	guint8 unknown_server1_ip[4];
	guint16 unknown_server1_port;
	guint8 unknown_server2_ip[4];
	guint16 unknown_server2_port;
	guint16 unknown2;	/* 0x0001 */
	guint16 unknown3;	/* 0x0000 */
	guint8 unknown4[32];
	guint8 unknown5[12];
	guint8 last_client_ip[4];
	time_t last_login_time;
	guint8 unknown6[8];
};

struct _qq_login_reply_redirect {
	guint8 result;
	guint32 uid;
	guint8 new_server_ip[4];
	guint16 new_server_port;
};

/* generate a md5 key using uid and session_key */
static guint8 *gen_session_md5(gint uid, guint8 *session_key)
{
	guint8 *src, md5_str[QQ_KEY_LENGTH];
	PurpleCipher *cipher;
	PurpleCipherContext *context;

	src = g_newa(guint8, 20);
	/* bug found by QuLogic */
	memcpy(src, &uid, sizeof(uid));
	memcpy(src + sizeof(uid), session_key, QQ_KEY_LENGTH);

	cipher = purple_ciphers_find_cipher("md5");
	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, src, 20);
	purple_cipher_context_digest(context, sizeof(md5_str), md5_str, NULL);
	purple_cipher_context_destroy(context);

	return g_memdup(md5_str, QQ_KEY_LENGTH);
}

/* process login reply which says OK */
static gint _qq_process_login_ok(PurpleConnection *gc, guint8 *data, gint len)
{
	gint bytes;
	qq_data *qd;
	qq_login_reply_ok_packet lrop;

	qd = (qq_data *) gc->proto_data;
	/* FIXME, check QQ_LOGIN_REPLY_OK_PACKET_LEN here */
	bytes = 0;

	/* 000-000: reply code */
	bytes += qq_get8(&lrop.result, data + bytes);
	/* 001-016: session key */
	lrop.session_key = g_memdup(data + bytes, QQ_KEY_LENGTH);
	bytes += QQ_KEY_LENGTH;
	purple_debug(PURPLE_DEBUG_INFO, "QQ", "Get session_key done\n");
	/* 017-020: login uid */
	bytes += qq_get32(&lrop.uid, data + bytes);
	/* 021-024: server detected user public IP */
	bytes += qq_getdata((guint8 *) &lrop.client_ip, 4, data + bytes);
	/* 025-026: server detected user port */
	bytes += qq_get16(&lrop.client_port, data + bytes);
	/* 027-030: server detected itself ip 127.0.0.1 ? */
	bytes += qq_getdata((guint8 *) &lrop.server_ip, 4, data + bytes);
	/* 031-032: server listening port */
	bytes += qq_get16(&lrop.server_port, data + bytes);
	/* 033-036: login time for current session */
	bytes += qq_getime(&lrop.login_time, data + bytes);
	/* 037-062: 26 bytes, unknown */
	bytes += qq_getdata((guint8 *) &lrop.unknown1, 26, data + bytes);
	/* 063-066: unknown server1 ip address */
	bytes += qq_getdata((guint8 *) &lrop.unknown_server1_ip, 4, data + bytes);
	/* 067-068: unknown server1 port */
	bytes += qq_get16(&lrop.unknown_server1_port, data + bytes);
	/* 069-072: unknown server2 ip address */
	bytes += qq_getdata((guint8 *) &lrop.unknown_server2_ip, 4, data + bytes);
	/* 073-074: unknown server2 port */
	bytes += qq_get16(&lrop.unknown_server2_port, data + bytes);
	/* 075-076: 2 bytes unknown */
	bytes += qq_get16(&lrop.unknown2, data + bytes);
	/* 077-078: 2 bytes unknown */
	bytes += qq_get16(&lrop.unknown3, data + bytes);
	/* 079-110: 32 bytes unknown */
	bytes += qq_getdata((guint8 *) &lrop.unknown4, 32, data + bytes);
	/* 111-122: 12 bytes unknown */
	bytes += qq_getdata((guint8 *) &lrop.unknown5, 12, data + bytes);
	/* 123-126: login IP of last session */
	bytes += qq_getdata((guint8 *) &lrop.last_client_ip, 4, data + bytes);
	/* 127-130: login time of last session */
	bytes += qq_getime(&lrop.last_login_time, data + bytes);
	/* 131-138: 8 bytes unknown */
	bytes += qq_getdata((guint8 *) &lrop.unknown6, 8, data + bytes);

	if (bytes != QQ_LOGIN_REPLY_OK_PACKET_LEN) {	/* fail parsing login info */
		purple_debug(PURPLE_DEBUG_WARNING, "QQ",
			   "Fail parsing login info, expect %d bytes, read %d bytes\n",
			   QQ_LOGIN_REPLY_OK_PACKET_LEN, bytes);
	}			/* but we still go on as login OK */

	g_return_val_if_fail(qd->session_key == NULL, QQ_LOGIN_REPLY_MISC_ERROR);
	qd->session_key = lrop.session_key;
	
	g_return_val_if_fail(qd->session_md5 == NULL, QQ_LOGIN_REPLY_MISC_ERROR);
	qd->session_md5 = gen_session_md5(qd->uid, qd->session_key);
	
	g_return_val_if_fail(qd->my_ip == NULL, QQ_LOGIN_REPLY_MISC_ERROR);
	qd->my_ip = gen_ip_str(lrop.client_ip);
	
	qd->my_port = lrop.client_port;
	qd->login_time = lrop.login_time;
	qd->last_login_time = lrop.last_login_time;
	qd->last_login_ip = gen_ip_str(lrop.last_client_ip);

	purple_connection_set_state(gc, PURPLE_CONNECTED);
	qd->logged_in = TRUE;	/* must be defined after sev_finish_login */

	/* now initiate QQ Qun, do it first as it may take longer to finish */
	qq_group_init(gc);

	/* Now goes on updating my icon/nickname, not showing info_window */
	qd->modifying_face = FALSE;

	qq_send_packet_get_info(gc, qd->uid, FALSE);
	/* grab my level */
	qq_send_packet_get_level(gc, qd->uid);

	qq_send_packet_change_status(gc);

	/* refresh buddies */
	qq_send_packet_get_buddies_list(gc, 0);

	/* refresh groups */
	qq_send_packet_get_all_list_with_group(gc, 0);

	return QQ_LOGIN_REPLY_OK;
}

/* process login reply packet which includes redirected new server address */
static gint _qq_process_login_redirect(PurpleConnection *gc, guint8 *data, gint len)
{
	gint bytes, ret;
	qq_data *qd;
	qq_login_reply_redirect_packet lrrp;

	qd = (qq_data *) gc->proto_data;
	bytes = 0;
	/* 000-000: reply code */
	bytes += qq_get8(&lrrp.result, data + bytes);
	/* 001-004: login uid */
	bytes += qq_get32(&lrrp.uid, data + bytes);
	/* 005-008: redirected new server IP */
	bytes += qq_getdata(lrrp.new_server_ip, 4, data + bytes);
	/* 009-010: redirected new server port */
	bytes += qq_get16(&lrrp.new_server_port, data + bytes);

	if (bytes != QQ_LOGIN_REPLY_REDIRECT_PACKET_LEN) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ",
			   "Fail parsing login redirect packet, expect %d bytes, read %d bytes\n",
			   QQ_LOGIN_REPLY_REDIRECT_PACKET_LEN, bytes);
		ret = QQ_LOGIN_REPLY_MISC_ERROR;
	} else {
		/* redirect to new server, do not disconnect or connect here
		 * those connect should be called at packet_process */
		if (qd->real_hostname) {
			purple_debug(PURPLE_DEBUG_INFO, "QQ", "free real_hostname\n");
			g_free(qd->real_hostname);
			qd->real_hostname = NULL;
		}
		qd->real_hostname = gen_ip_str(lrrp.new_server_ip);
		qd->real_port = lrrp.new_server_port;
		qd->is_redirect = TRUE;

		purple_debug(PURPLE_DEBUG_WARNING, "QQ",
			   "Redirected to new server: %s:%d\n", qd->real_hostname, qd->real_port);

		ret = QQ_LOGIN_REPLY_REDIRECT;
	}

	return ret;
}

/* process login reply which says wrong password */
static gint _qq_process_login_wrong_pwd(PurpleConnection *gc, guint8 *data, gint len)
{
	gchar *server_reply, *server_reply_utf8;
	server_reply = g_new0(gchar, len);
	g_memmove(server_reply, data + 1, len - 1);
	server_reply_utf8 = qq_to_utf8(server_reply, QQ_CHARSET_DEFAULT);
	purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Wrong password, server msg in UTF8: %s\n", server_reply_utf8);
	g_free(server_reply);
	g_free(server_reply_utf8);

	return QQ_LOGIN_REPLY_PWD_ERROR;
}

/* request before login */
void qq_send_packet_token(PurpleConnection *gc)
{
	qq_data *qd;
	guint8 buf[16] = {0};
	gint bytes = 0;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	bytes += qq_put8(buf + bytes, 0);
	
	qq_send_data(qd, QQ_CMD_TOKEN, buf, bytes);
}

/* send login packet to QQ server */
void qq_send_packet_login(PurpleConnection *gc)
{
	qq_data *qd;
	guint8 *buf, *raw_data;
	gint bytes;
	guint8 *encrypted_data;
	gint encrypted_len;

	g_return_if_fail(gc != NULL && gc->proto_data != NULL);
	qd = (qq_data *) gc->proto_data;

	g_return_if_fail(qd->token != NULL && qd->token_len > 0);

	raw_data = g_newa(guint8, QQ_LOGIN_DATA_LENGTH);
	memset(raw_data, 0, QQ_LOGIN_DATA_LENGTH);

	encrypted_data = g_newa(guint8, QQ_LOGIN_DATA_LENGTH + 16);	/* 16 bytes more */
	if (qd->inikey) {
		g_free(qd->inikey);
	}
	qd->inikey = (guint8 *) g_strnfill(QQ_KEY_LENGTH, 0x01);

	bytes = 0;
	/* now generate the encrypted data
	 * 000-015 use pwkey as key to encrypt empty string */
	qq_encrypt((guint8 *) "", 0, qd->pwkey, raw_data + bytes, &encrypted_len);
	bytes += 16;
	/* 016-016 */
	bytes += qq_put8(raw_data + bytes, 0x00);
	/* 017-020, used to be IP, now zero */
	bytes += qq_put32(raw_data + bytes, 0x00000000);
	/* 021-022, used to be port, now zero */
	bytes += qq_put16(raw_data + bytes, 0x0000);
	/* 023-051, fixed value, unknown */
	bytes += qq_putdata(raw_data + bytes, login_23_51, 29);
	/* 052-052, login mode */
	bytes += qq_put8(raw_data + bytes, qd->login_mode);
	/* 053-068, fixed value, maybe related to per machine */
	bytes += qq_putdata(raw_data + bytes, login_53_68, 16);
	/* 069, login token length */
	bytes += qq_put8(raw_data + bytes, qd->token_len);
	/* 070-093, login token, normally 24 bytes */
	bytes += qq_putdata(raw_data + bytes, qd->token, qd->token_len);
	/* 100 bytes unknown */
	bytes += qq_putdata(raw_data + bytes, login_100_bytes, 100);
	/* all zero left */

	qq_encrypt(raw_data, QQ_LOGIN_DATA_LENGTH, qd->inikey, encrypted_data, &encrypted_len);

	buf = g_newa(guint8, MAX_PACKET_SIZE);
	memset(buf, 0, MAX_PACKET_SIZE);
	bytes = 0;
	bytes += qq_putdata(buf + bytes, qd->inikey, QQ_KEY_LENGTH);
	bytes += qq_putdata(buf + bytes, encrypted_data, encrypted_len);

	qq_send_data(qd, QQ_CMD_LOGIN, buf, bytes);
}

guint8 qq_process_token_reply(PurpleConnection *gc, gchar *error_msg, guint8 *buf, gint buf_len)
{
	qq_data *qd;
	guint8 ret;
	int token_len;

	g_return_val_if_fail(buf != NULL && buf_len != 0, -1);

	g_return_val_if_fail(gc != NULL  && gc->proto_data != NULL, -1);
	qd = (qq_data *) gc->proto_data;

	ret = buf[0];
	
	if (ret != QQ_TOKEN_REPLY_OK) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Unknown request login token reply code : %d\n", buf[0]);
		qq_hex_dump(PURPLE_DEBUG_WARNING, "QQ",
				buf, buf_len,
				">>> [default] decrypt and dump");
		error_msg = try_dump_as_gbk(buf, buf_len);
		return ret;
	}
	
	token_len = buf_len-2;
	if (token_len <= 0) {
		error_msg = g_strdup_printf( _("Invalid token len, %d"), token_len);
		return -1;
	}
	
	if (buf[1] != token_len) {
		purple_debug(PURPLE_DEBUG_INFO, "QQ",
				"Invalid token len. Packet specifies length of %d, actual length is %d\n", buf[1], buf_len-2);
	}
	qq_hex_dump(PURPLE_DEBUG_INFO, "QQ",
			buf+2, token_len,
			"<<< got a token -> [default] decrypt and dump");
			
	qd->token = g_new0(guint8, token_len);
	qd->token_len = token_len;
	g_memmove(qd->token, buf + 2, qd->token_len);
	return ret;
}

/* send logout packets to QQ server */
void qq_send_packet_logout(PurpleConnection *gc)
{
	gint i;
	qq_data *qd;

	qd = (qq_data *) gc->proto_data;
	for (i = 0; i < 4; i++)
		qq_send_cmd_detail(qd, QQ_CMD_LOGOUT, 0xffff, FALSE, qd->pwkey, QQ_KEY_LENGTH);

	qd->logged_in = FALSE;	/* update login status AFTER sending logout packets */
}

/* process the login reply packet */
void qq_process_login_reply(guint8 *buf, gint buf_len, PurpleConnection *gc)
{
	gint len, ret, bytes;
	guint8 *data;
	qq_data *qd;
	gchar* error_msg;

	g_return_if_fail(buf != NULL && buf_len != 0);

	qd = (qq_data *) gc->proto_data;
	len = buf_len;
	data = g_newa(guint8, len);

	if (qq_decrypt(buf, buf_len, qd->pwkey, data, &len)) {
		/* should be able to decrypt with pwkey */
		purple_debug(PURPLE_DEBUG_INFO, "QQ", "Decrypt login reply packet with pwkey, %d bytes\n", len);
		if (data[0] == QQ_LOGIN_REPLY_OK) {
			ret = _qq_process_login_ok(gc, data, len);
		} else {
			purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Unknown login reply code : %d\n", data[0]);
			ret = QQ_LOGIN_REPLY_MISC_ERROR;
		}
	} else {		/* decrypt with pwkey error */
		len = buf_len;	/* reset len, decrypt will fail if len is too short */
		if (qq_decrypt(buf, buf_len, qd->inikey, data, &len)) {
			/* decrypt ok with inipwd, it might be password error */
			purple_debug(PURPLE_DEBUG_WARNING, "QQ", 
					"Decrypt login reply packet with inikey, %d bytes\n", len);
			bytes = 0;
			switch (data[0]) {
			case QQ_LOGIN_REPLY_REDIRECT:
				ret = _qq_process_login_redirect(gc, data, len);
				break;
			case QQ_LOGIN_REPLY_PWD_ERROR:
				ret = _qq_process_login_wrong_pwd(gc, data, len);
				break;
			default:
				purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Unknown reply code: %d\n", data[0]);
				qq_hex_dump(PURPLE_DEBUG_WARNING, "QQ",
						data, len,
						">>> [default] decrypt and dump");
				error_msg = try_dump_as_gbk(data, len);
				if (error_msg)	{
					purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, error_msg);
					g_free(error_msg);
				}
				ret = QQ_LOGIN_REPLY_MISC_ERROR;
			}
		} else {	/* no idea how to decrypt */
			purple_debug(PURPLE_DEBUG_ERROR, "QQ", "No idea how to decrypt login reply\n");
			ret = QQ_LOGIN_REPLY_MISC_ERROR;
		}
	}

	switch (ret) {
	case QQ_LOGIN_REPLY_PWD_ERROR:
		if (!purple_account_get_remember_password(gc->account))
			purple_account_set_password(gc->account, NULL);
		purple_connection_error_reason(gc,
			PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Incorrect password."));
		break;
	case QQ_LOGIN_REPLY_MISC_ERROR:
			if (purple_debug_is_enabled())
				purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Unable to login. Check debug log."));
			else
				purple_connection_error_reason(gc,
					PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Unable to login"));				
		break;
	case QQ_LOGIN_REPLY_OK:
		purple_debug(PURPLE_DEBUG_INFO, "QQ", "Login repliess OK; everything is fine\n");
		break;
	case QQ_LOGIN_REPLY_REDIRECT:
		/* the redirect has been done in _qq_process_login_reply */
		break;
	default:{;
		}
	}
}

/* send keep-alive packet to QQ server (it is a heart-beat) */
void qq_send_packet_keep_alive(PurpleConnection *gc)
{
	qq_data *qd;
	guint8 raw_data[16] = {0};
	gint bytes= 0;

	qd = (qq_data *) gc->proto_data;

	/* In fact, we can send whatever we like to server
	 * with this command, server return the same result including
	 * the amount of online QQ users, my ip and port */
	bytes += qq_put32(raw_data + bytes, qd->uid);

	qq_send_cmd(qd, QQ_CMD_KEEP_ALIVE, raw_data, 4);
}

/* parse the return of keep-alive packet, it includes some system information */
gboolean qq_process_keep_alive(guint8 *buf, gint buf_len, PurpleConnection *gc) 
{
	qq_data *qd;
	gint len;
	gchar **segments;
	guint8 *data;

	g_return_val_if_fail(buf != NULL && buf_len != 0, FALSE);

	qd = (qq_data *) gc->proto_data;
	len = buf_len;
	data = g_newa(guint8, len);

	if ( !qq_decrypt(buf, buf_len, qd->session_key, data, &len) ) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Error decrypt keep alive reply\n");
		return FALSE;
	}

	/* qq_show_packet("Keep alive reply packet", data, len); */

	/* the last one is 60, don't know what it is */
	if (NULL == (segments = split_data(data, len, "\x1f", 6)))
			return TRUE;
			
	/* segments[0] and segment[1] are all 0x30 ("0") */
	qd->total_online = strtol(segments[2], NULL, 10);
	if(0 == qd->total_online) {
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Keep alive error"));
	}
	g_free(qd->my_ip);
	qd->my_ip = g_strdup(segments[3]);
	qd->my_port = strtol(segments[4], NULL, 10);
	g_strfreev(segments);
	return TRUE;
}
