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
 * \brief RFC822 message formatting
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "evergreen.h"

#include <string.h>
#include <stdlib.h>

#include <libetpan/libetpan.h>

char *addr_sep(char **restrict addr)
{
	char *s, *start = *addr;
	s = start;

	if (!s) {
		return NULL;
	}

	while (*s) {
		if (*s == ';' || *s == ',') {
			*s = '\0';
			*addr = s + 1;
			return start;
		}
		s++;
	}
	*addr = NULL;
	return start;
}

static int parse_address_list(struct message_constructor *msgc, struct mailimf_address_list *list, const char *hdr, const char *addrs_orig)
{
	char *addr, *addrs, *dup = strdup(addrs_orig);
	if (!dup) {
		SET_ERROR("Allocation failure");
		return -1;
	}
	addrs = dup;
	while ((addr = addr_sep(&addrs))) {
		int res;
		while (*addr == ' ') {
			addr++;
		}
		if (!*addr) {
			continue;
		}
		client_debug(6, "Parsing address '%s'", addr);
		res = mailimf_address_list_add_parse(list, addr);
		if (res != MAILIMF_NO_ERROR) {
			SET_ERROR("Failed to parse %s address '%s'", hdr, addr);
			free(dup);
			return -1;
		}
	}
	free(dup);
	return 0;
}

static void free_string_clist(clist *c)
{
	clistiter *cur;
	for (cur = clist_begin(c); cur; cur = clist_next(cur)) {
		char *s = clist_content(cur);
		free(s);
	}
	clist_free(c);
}

static clist *parse_clist_strings(char *val)
{
	char *s;
	clist *clist = clist_new();
	if (!clist) {
		return NULL;
	}

	while ((s = strsep(&val, ","))) {
		char *dup = strdup(s);
		if (!dup) {
			free_string_clist(clist);
			return NULL;
		}
		clist_append(clist, dup);
	}
	return clist;
}

static char *get_message_id(void)
{
	char *s;
	int res;
	time_t now;
	long value;

	now = time(NULL);
	value = random();

	res = asprintf(&s, EVERGREEN_PROGNAME ".%lx.%lx.%x", (long) now, value, getpid());
	if (res < 0) {
		return NULL;
	}
	return s;
}

static struct mailimf_fields *build_fields(struct message_constructor *msgc)
{
	struct mailimf_mailbox_list *from = NULL;
	struct mailimf_address_list *to = NULL, *cc = NULL, *bcc = NULL, *replyto = NULL;
	char *subject = NULL;
	int res;
	struct mailimf_date_time *date = NULL;
	char *messageid = NULL;
	clist *inreplyto = NULL, *references = NULL;
	struct mailimf_fields *new_fields;
	struct mailimf_field *useragentfield;

	/* Subject */
	if (msgc->subject) {
		subject = strdup(msgc->subject);
		if (!subject) {
			SET_ERROR("Allocation failure");
			return NULL;
		}
	}

	/* From */
	if (msgc->from) {
		from = mailimf_mailbox_list_new_empty();
		if (!from) {
			SET_ERROR("Allocation failure");
			goto fail;
		}
		res = mailimf_mailbox_list_add_parse(from, msgc->from);
		if (res != MAILIMF_NO_ERROR) {
			SET_ERROR("Failed to parse From address");
			goto fail;
		}
	}

#define PARSE_HEADER(field, name) \
	if (!strlen_zero(msgc->field)) { \
		field = mailimf_address_list_new_empty(); \
		if (parse_address_list(msgc, field, name, msgc->field)) { \
			goto fail; \
		} \
	}

	PARSE_HEADER(to, "To");
	PARSE_HEADER(cc, "Cc");
	PARSE_HEADER(bcc, "Bcc");
	PARSE_HEADER(replyto, "Reply-To");
#undef PARSE_HEADER

	if (msgc->inreplyto) {
		char *s = strdup(msgc->inreplyto);
		inreplyto = parse_clist_strings(s);
		free(s);
		if (!inreplyto) {
			SET_ERROR("Allocation failure");
			goto fail;
		}
	}
	if (msgc->references) {
		references = parse_clist_strings(msgc->references);
		if (!references) {
			SET_ERROR("Allocation failure");
			goto fail;
		}
	}

	date = mailimf_get_current_date();
	if (!date) {
		SET_ERROR("Allocation failure");
		goto fail;
	}
	messageid = get_message_id();
	if (!messageid) {
		SET_ERROR("Allocation failure");
		goto fail;
	}

	new_fields = mailimf_fields_new_with_data_all(date, from,
		NULL, /* Sender */
		replyto, to, cc, bcc, messageid, inreplyto, references, subject);

	if (!new_fields) {
		SET_ERROR("Message field creation");
		goto fail;
	}

	useragentfield = mailimf_field_new_custom(strdup("User-Agent"), strdup(USER_AGENT));
	if (!useragentfield) {
		SET_ERROR("Allocation failure");
		mailimf_fields_free(new_fields);
		goto fail;
	}

	mailimf_fields_add(new_fields, useragentfield);
	return new_fields;

fail:
	free_if(messageid);
	if (date) {
		mailimf_date_time_free(date);
	}
	if (references) {
		free_string_clist(references);
	}
	if (inreplyto) {
		free_string_clist(inreplyto);
	}
	if (replyto) {
		mailimf_address_list_free(replyto);
	}
	if (bcc) {
		mailimf_address_list_free(bcc);
	}
	if (cc) {
		mailimf_address_list_free(cc);
	}
	if (to) {
		mailimf_address_list_free(to);
	}
	if (from) {
		mailimf_mailbox_list_free(from);
	}
	free_if(subject);
	return NULL;
}

static struct mailmime *build_body_text(char *restrict text, size_t len)
{
	struct mailmime_fields *mime_fields;
	struct mailmime *mime_sub;
	struct mailmime_content *content;
	struct mailmime_parameter *param;
	int res;

	mime_fields = mailmime_fields_new_encoding(MAILMIME_MECHANISM_7BIT);
	if (!mime_fields) {
		goto err;
	}

	content = mailmime_content_new_with_str("text/plain");
	if (!content) {
		goto free_fields;
	}

	/* charset param */
	param = mailmime_param_new_with_data("charset", DEST_CHARSET);
	if (!param) {
		goto free_content;
	}
	res = clist_append(content->ct_parameters, param);
	if (res < 0) {
		mailmime_parameter_free(param);
		goto free_content;
	}

	/* format=flowed */
	param = mailmime_param_new_with_data("format", "flowed");
	if (!param) {
		goto free_content;
	}
	res = clist_append(content->ct_parameters, param);
	if (res < 0) {
		mailmime_parameter_free(param);
		goto free_content;
	}

	mime_sub = mailmime_new_empty(content, mime_fields);
	if (!mime_sub) {
		goto free_content;
	}

	res = mailmime_set_body_text(mime_sub, text, len);
	if (res != MAILIMF_NO_ERROR) {
		goto free_mime;
	}

	return mime_sub;

free_mime:
	mailmime_free(mime_sub);
	goto err;
free_content:
	mailmime_content_free(content);
free_fields:
	mailmime_fields_free(mime_fields);
err:
	return NULL;
}

char *create_email_message(struct message_constructor *msgc, size_t *restrict len)
{
	struct mailimf_fields *fields;
	struct mailmime *message;
	struct mailmime *text_part = NULL;
	int res;
	int col;
	char *s;
	MMAPString *str;

	/* Email headers */
	fields = build_fields(msgc);
	if (!fields) {
		goto err;
	}

	/* Create empty message */
	message = mailmime_new_message_data(NULL);
	if (!message) {
		goto free_fields;
	}
	mailmime_set_imf_fields(message, fields);

	/* Build body text */
	if (msgc->body) {
		/* The text that gets passed here is added to the body quite literally,
		 * so all line wrapping already needs to be done by this point. */
		text_part = build_body_text(msgc->body, msgc->bodylen);
		if (!text_part) {
			SET_ERROR("Failed to build body text");
			goto free_message;
		}
		res = mailmime_smart_add_part(message, text_part);
		if (res != MAILIMF_NO_ERROR) {
			SET_ERROR("Failed to add body text");
			goto free_text;
		}
	} else {
		client_debug(4, "Message has empty body?");
	}

	str = mmap_string_new("");
	if (!str) {
		goto free_text;
	}
	col = 0;
	res = mailmime_write_mem(str, &col, message);
	if (res != MAILIMF_NO_ERROR) {
		SET_ERROR("Message write failed");
		goto free_message;
	}
	s = strndup(str->str, str->len);
	if (!s) {
		SET_ERROR("Allocation failure");
	} else {
		*len = str->len;
		mailmime_free(message);
		mmap_string_free(str);
		return s;
	}

	mmap_string_free(str);

free_text:
	if (text_part) {
		mailmime_free(text_part);
	}
free_message:
	mailmime_free(message);
	goto err;
free_fields:
	mailimf_fields_free(fields);
err:
	return NULL;
}
