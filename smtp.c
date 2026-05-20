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
				/* mailesmtp_rcpt does not want <> surrounding the address, strip em here */
				*recipient++ = '\0';
				tmp = strchr(recipient, '>');
				if (!tmp) {
					client_debug(3, "Malformed recipient?");
					continue;
				}
				*tmp = '\0';
			} else {
				/* The spaces we trimmed must have been at the end */
			}
		} else {
			recipient = strchr(recipient, '<');
			if (!recipient) {
				client_debug(3, "Malformed recipient?");
				continue;
			}
			/* mailesmtp_rcpt does not want <> surrounding the address, strip em here */
			*recipient++ = '\0';
			tmp = strchr(recipient, '>');
			if (!tmp) {
				client_debug(3, "Malformed recipient?");
				continue;
			}
			*tmp = '\0';
		}
		client_debug(3, "Adding recipient to transaction: %s", recipient);
		dup = strdup(recipient);
		if (!dup) {
			SET_ERROR("Allocation failure");
			return -1;
		}
		if (esmtp) {
			res = mailesmtp_rcpt(smtp, dup, MAILSMTP_DSN_NOTIFY_FAILURE | MAILSMTP_DSN_NOTIFY_DELAY, NULL);
		} else {
			res = mailsmtp_rcpt(smtp, dup);
		}
		if (res != MAILSMTP_NO_ERROR) {
			SET_ERROR("RCPT %s: '%s'", dup, mailsmtp_strerror(res));
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
		/* CRAM-MD5 -> PLAIN -> LOGIN */
		if (smtp->auth & (MAILSMTP_AUTH_PLAIN | MAILSMTP_AUTH_LOGIN)) {
			res = mailsmtp_auth(smtp, client->config->smtp_username, client->config->smtp_password[0] ? client->config->smtp_password : "");
			if (res != MAILSMTP_NO_ERROR) {
				SMTP_ERROR("AUTH");
				goto cleanup;
			}
		} else {
			SET_ERROR("No supported AUTH methods");
			goto cleanup;
		}
	} else {
		client_debug(3, "No SMTP username... assuming AUTH is not required");
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
