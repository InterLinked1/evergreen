/*
 * evergreen -- online only terminal mail user agent
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief SMTP protocol operations
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "evergreen.h"

#include <stdlib.h>
#include <string.h>

#include <libetpan/libetpan.h>

/* Forward declaration for libetpan, exported from src/data-types/base64.h */
char *encode_base64(const char * in, int len);

/* duplicated from rfc822.c, since clist is a typedef, so this cannot be in the header file */
static void free_string_clist(clist *c)
{
	clistiter *cur;
	for (cur = clist_begin(c); cur; cur = clist_next(cur)) {
		char *s = clist_content(cur);
		free(s);
	}
	clist_free(c);
}

static int add_recipients(struct message_constructor *msgc, struct mailsmtp *smtp, int esmtp, clist *recipients, int *restrict num_recipients, char *list)
{
	int res;
	/* Okay to consume msgc recipients now, we won't need them anymore afterwards */
	char *recipient;
	while ((recipient = addr_sep(&list))) {
		char *tmp, *dup;
		/* ltrim */
		while (*recipient == ' ') {
			recipient++;
		}
		if (!*recipient) {
			/* Empty recipient? */
			continue;
		}
		/* Just want the email address, not the name, if there is one */
		tmp = strchr(recipient, ' ');
		if (tmp) {
			/* ltrim */
			while (*tmp == ' ') {
				tmp++;
			}
			if (*tmp) {
				/* We trimmed spaces in the middle of the word, and there's still text,
				 * so the first part must have been the name */
				recipient = strchr(tmp, '<');
				if (!recipient) {
					client_debug(3, "Malformed recipient?");
					continue;
				}
			} else {
				/* The spaces we trimmed must have been at the end */
			}
		}
		client_debug(3, "Adding recipient to transaction: %s", recipient);
		dup = strdup(recipient);
		if (!dup) {
			SET_ERROR("Allocation failure");
			free_string_clist(recipients);
			return -1;
		}
		if (esmtp) {
			res = mailesmtp_rcpt(smtp, dup, MAILSMTP_DSN_NOTIFY_FAILURE | MAILSMTP_DSN_NOTIFY_DELAY, NULL);
		} else {
			res = mailsmtp_rcpt(smtp, dup);
		}
		if (res != MAILSMTP_NO_ERROR) {
			SET_ERROR("RCPT %s: '%s'", dup, mailsmtp_strerror(res));
			free_string_clist(recipients);
			free(dup);
			return -1;
		}
		*num_recipients += 1;
		clist_append(recipients, dup);
	}
	return 0;
}

int smtp_send(struct client *client, struct message_constructor *msgc, const char *body, size_t len)
{
	int esmtp = 1;
	int res;
	int num_recipients = 0;
	mailsmtp *smtp = NULL;
	clist *recipients;
	const char *hostname = client->config->smtp_hostname[0] ? client->config->smtp_hostname : client->config->imap_hostname;

	/* Quick sanity checks, server will probably reject the message otherwise anyways */
	if (strlen_zero(msgc->from)) {
		SET_ERROR("No From address");
		return -1;
	} else if (strlen_zero(msgc->to) && strlen_zero(msgc->cc) && strlen_zero(msgc->bcc)) {
		SET_ERROR("No recipients");
		return -1;
	}

	recipients = clist_new();
	if (!recipients) {
		SET_ERROR("Allocation failure");
		return -1;
	}

	smtp = mailsmtp_new(0, NULL);
	if (!smtp) {
		SET_ERROR("Allocation failure");
		goto cleanup;
	}

	if (client->config->smtp_security == SECURITY_TLS) {
		res = mailsmtp_ssl_connect(smtp, hostname, client->config->smtp_port);
	} else {
		res = mailsmtp_socket_connect(smtp, hostname, client->config->smtp_port);
	}

	if (res != MAILSMTP_NO_ERROR) {
		SET_ERROR("connect err: %s", mailsmtp_strerror(res));
		goto cleanup;
	}

	res = mailesmtp_ehlo(smtp);
	if (res == MAILSMTP_ERROR_NOT_IMPLEMENTED) {
		esmtp = 0;
		res = mailsmtp_helo(smtp);
	}

#define SMTP_ERROR(cmd) \
	client_debug(1, "SMTP %s: %s - %d - %s", cmd, mailsmtp_strerror(res), smtp->response_code, smtp->response); \
	SET_ERROR("%d %s", smtp->response_code, smtp->response);

	if (res != MAILSMTP_NO_ERROR) {
		SET_ERROR("%s err: %s", esmtp ? "EHLO" : "HELO", mailsmtp_strerror(res));
		goto cleanup;
	}

	if (client->config->smtp_security == SECURITY_STARTTLS) {
		if (!esmtp) {
			SET_ERROR("STARTTLS not supported");
			goto cleanup;
		}
		res = mailsmtp_socket_starttls(smtp);
		if (res != MAILSMTP_NO_ERROR) {
			SMTP_ERROR("STARTTLS");
			goto cleanup;
		}

		/* HELO/EHLO again */
		res = mailesmtp_ehlo(smtp);
		if (res == MAILSMTP_ERROR_NOT_IMPLEMENTED) {
			SMTP_ERROR("EHLO");
			goto cleanup;
		}
	}

	if (!strlen_zero(client->config->smtp_username)) {
		if (!esmtp) {
			SET_ERROR("AUTH not supported");
			goto cleanup;
		}
		/* Prefer PLAIN, if available, since it only requires a single roundtrip, rather than LOGIN, which requires 2 */
		if (smtp->auth & MAILSMTP_AUTH_PLAIN) {
			/* Builds of libetpan generally don't have USE_SASL defined, and,
			 * without this, mailesmtp_auth functions won't work at all,
			 * even for things like AUTH PLAIN and LOGIN.
			 *
			 * There is a mailsmtp_auth_login function in src/low-level/smtp/mailsmtp.c,
			 * but it's #if 0'd, so we're not allowed to use it!
			 *
			 * Finally, to add insult to injury, the library will NOT allow applications
			 * to authenticate themselves! There are mailsmtp_send_command and mailsmtp_send_command_private
			 * functions in mailsmtp.c, but they are NOT exported.
			 *
			 * So, there are 3 ways that we could've used the library as is,
			 * but clearly it's conspired against use of the library to authenticate,
			 * so we do unfortunately require a modified library to properly expose the authentication functionality.
			 * If a modified library is not present, this file will fail to compile.
			 *
			 * This is rather mindboggling, but we'll have to manually send the auth commands ourself,
			 * as this is the most portable way. */
			char *encoded;
			char buf[256];
			char fullcmd[256];
			int buflen = snprintf(buf, sizeof(buf), "%c%s%c%s", '\0', client->config->smtp_username, '\0', client->config->smtp_password[0] ? client->config->smtp_password : "");
			/* FYI, encode_base64 does not produce padded encodings. Some server implementations may take issue with that (but hopefully not) */
			encoded = encode_base64(buf, buflen);
			if (!encoded) {
				SET_ERROR("Encoding error");
				goto cleanup;
			}
			snprintf(fullcmd, sizeof(fullcmd), "AUTH PLAIN %s\r\n", encoded);
			explicit_bzero(encoded, strlen(encoded));
			free(encoded);
			res = mailsmtp_send_command(smtp, fullcmd);
			if (res != MAILSMTP_NO_ERROR) {
				SMTP_ERROR("AUTH PLAIN");
				goto cleanup;
			}
			explicit_bzero(fullcmd, sizeof(fullcmd));
			res = mailsmtp_read_response(smtp);
			if (res != MAILSMTP_NO_ERROR && smtp->response_code != 235) {
				SMTP_ERROR("AUTH");
				goto cleanup;
			}
		} else if (smtp->auth & MAILSMTP_AUTH_LOGIN) {
			res = mailsmtp_send_command(smtp, "AUTH LOGIN\r\n");
			if (res != MAILSMTP_NO_ERROR) {
				SMTP_ERROR("AUTH LOGIN");
				goto cleanup;
			}
			res = mailsmtp_read_response(smtp);
			/* libetpan will return error code unknown for this one, so check manually */
			if (smtp->response_code != 334) {
				SMTP_ERROR("AUTH");
				goto cleanup;
			}
			res = mailsmtp_auth_login(smtp, client->config->smtp_username, client->config->smtp_password[0] ? client->config->smtp_password : "");
			if (res != MAILSMTP_NO_ERROR) {
				SMTP_ERROR("AUTH");
				goto cleanup;
			}
		} else {
			SET_ERROR("No supported AUTH methods");
			goto cleanup;
		}
	}

	if (esmtp) {
		res = mailesmtp_mail_size(smtp, client->config->fromaddr[0] ? client->config->fromaddr : "User", 1, EVERGREEN_PROGNAME, len);
	} else {
		res = mailsmtp_mail(smtp, client->config->fromaddr[0] ? client->config->fromaddr : "User");
	}

	if (res != MAILSMTP_NO_ERROR) {
		SMTP_ERROR("MAIL");
		goto cleanup;
	}

	if (!strlen_zero(msgc->to) && add_recipients(msgc, smtp, esmtp, recipients, &num_recipients, msgc->to)) {
		goto cleanup;
	}
	if (!strlen_zero(msgc->cc) && add_recipients(msgc, smtp, esmtp, recipients, &num_recipients, msgc->cc)) {
		goto cleanup;
	}
	if (!strlen_zero(msgc->bcc) && add_recipients(msgc, smtp, esmtp, recipients, &num_recipients, msgc->bcc)) {
		goto cleanup;
	}

	if (!num_recipients) {
		SET_ERROR("No recipients");
		goto cleanup;
	}

	res = mailsmtp_data(smtp);
	if (res != MAILSMTP_NO_ERROR) {
		SMTP_ERROR("DATA");
		goto cleanup;
	}

	res = mailsmtp_data_message(smtp, body, len);
	if (res != MAILSMTP_NO_ERROR) {
		SMTP_ERROR("DATA");
		goto cleanup;
	}

	mailsmtp_quit(smtp);

	free_string_clist(recipients);
	mailsmtp_free(smtp);
	return 0;

cleanup:
	free_string_clist(recipients);
	mailsmtp_free(smtp);
	return -1;
}
