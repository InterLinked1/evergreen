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
 * \brief IMAP protocol operations
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "evergreen.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <poll.h>
#include <search.h>

#include <libetpan/libetpan.h>

static inline void free_mailbox_keywords(struct mailbox *mbox)
{
	int i;
	for (i = 0; i < mbox->num_keywords && mbox->keywords[i]; i++) {
		free(mbox->keywords[i]);
		mbox->keywords[i] = NULL;
	}
}

void client_destroy(struct client *client)
{
	if (client->idling) {
		/* If we're still idling at exit time, stop */
		client_idle_stop(client);
	}
	mailimap_logout(client->imap);
	mailimap_free(client->imap);

	/* Free mailbox structures */
	if (client->mailboxes) {
		int i;
		for (i = 0; i < client->num_mailboxes; i++) {
			free_mailbox_keywords(&client->mailboxes[i]);
			free_if(client->mailboxes[i].name);
		}
		free(client->mailboxes);
	}
}

static int client_load_capabilities(struct client *client)
{
	struct mailimap_capability_data *capdata;
	int res = mailimap_capability(client->imap, &capdata);

	if (MAILIMAP_ERROR(res)) {
		return -1;
	}

	/* Now that we've called mailimap_capability, libetpan is aware of what capabilities are available. */
	mailimap_capability_data_free(capdata);

	/* Be nice, and identify ourselves, if possible */
	if (mailimap_has_id(client->imap)) {
		res = mailimap_custom_command(client->imap, "ID (\"name\" \"evergreen (libetpan)\" \"version\" \"" EVERGREEN_VERSION "\")");
	}

#define SET_CAPABILITY(flag, res) if ((res)) { client->capabilities |= flag; }
	SET_CAPABILITY(IMAP_CAPABILITY_IDLE, mailimap_has_idle(client->imap));
	SET_CAPABILITY(IMAP_CAPABILITY_MOVE, mailimap_has_extension(client->imap, "MOVE"));
	SET_CAPABILITY(IMAP_CAPABILITY_SORT, mailimap_has_sort(client->imap));
	SET_CAPABILITY(IMAP_CAPABILITY_THREAD_REFERENCES, mailimap_has_extension(client->imap, "THREAD=REFERENCES"));
	SET_CAPABILITY(IMAP_CAPABILITY_STATUS_SIZE, mailimap_has_extension(client->imap, "STATUS=SIZE"));
	SET_CAPABILITY(IMAP_CAPABILITY_LIST_STATUS, mailimap_has_extension(client->imap, "LIST-STATUS"));
	SET_CAPABILITY(IMAP_CAPABILITY_NOTIFY, mailimap_has_extension(client->imap, "NOTIFY"));
	SET_CAPABILITY(IMAP_CAPABILITY_UNSELECT, mailimap_has_extension(client->imap, "UNSELECT"));
	SET_CAPABILITY(IMAP_CAPABILITY_QUOTA, mailimap_has_quota(client->imap));
#undef SET_CAPABILITY

	return res;
}

int client_connect(struct client *client, struct config *config)
{
	int res;
	struct mailimap *imap = mailimap_new(0, NULL);
	if (!imap) {
		client_error("Failed to create IMAP session");
		return -1;
	}

	client->imap = imap;

	client_status("Connecting to %s:%d", config->imap_hostname, config->imap_port);

	mailimap_set_timeout(imap, 15); /* If the IMAP server hasn't responded by now, I doubt it ever will */
	if (config->imap_security == SECURITY_TLS) {
		res = mailimap_ssl_connect(imap, config->imap_hostname, config->imap_port);
	} else {
		res = mailimap_socket_connect(imap, config->imap_hostname, config->imap_port);
	}
	if (MAILIMAP_ERROR(res)) {
		client_error("Failed to establish IMAP session to %s:%d (%s)", config->imap_hostname, config->imap_port, maildriver_strerror(res));
		mailimap_free(client->imap);
		return -1;
	}

	/* Timeout needs to be sufficiently large... e.g. FETCH 1:* (SIZE) can take quite a few seconds on large mailboxes. */
	mailimap_set_timeout(imap, 60); /* If the IMAP server hasn't responded by now, I doubt it ever will */

	if (client_load_capabilities(client)) {
		mailimap_free(client->imap);
		return -1;
	}
	return 0;
}

int client_login(struct client *client, struct config *config)
{
	int res;

	client_status("Authenticating to IMAP server");

	/* Authenticate using LOGIN */
	res = mailimap_login(client->imap, config->imap_username, config->imap_password);
	explicit_bzero(config->imap_password, sizeof(config->imap_password)); /* Zero the password out from memory */

	if (res) {
		client_error("IMAP login failed: %s", config->imap_username);
		return -1;
	}

	/* Save the file descriptor, for IDLE */
	client->imapfd = mailimap_idle_get_fd(client->imap);

	/* Some servers only advertise certain capabilities after authenticated, so load again. */
	return client_load_capabilities(client);
}

static inline char *find_mailbox_response_line(char *restrict s, const char *cmd, const char *mb, int *skiplenptr)
{
	char *tmp;
	int skiplen;
	char findbuf[64];
	skiplen = snprintf(findbuf, sizeof(findbuf), "* %s \"%s\" (", cmd, mb);
	tmp = strstr(s, findbuf);
	if (!tmp && !strchr(mb, ' ')) { /* If not found, try the unquoted version */
		skiplen = snprintf(findbuf, sizeof(findbuf), "* %s %s (", cmd, mb);
		tmp = strstr(s, findbuf);
	}
	*skiplenptr = skiplen;
	return tmp;
}

/*!
 * \brief Parse a STATUS line
 * \param client
 * \param mbox
 * \param tmp Line to parse
 * \param expect_full Whether we expect a full STATUS response line or not (1 for LIST-STATUS, 0 for STATUS during IDLE)
 */
static void parse_status(struct client *client, struct mailbox *mbox, char *restrict tmp, int expect_full)
{
	char *str;

	if (strlen_zero(tmp)) {
		client_warning("Malformed STATUS response");
		return;
	}

	str = strstr(tmp, "MESSAGES ");
	if (str) {
		str += STRLEN("MESSAGES ");
		if (!strlen_zero(str)) {
			mbox->total = (uint32_t) atol(str);
		}
	} else if (expect_full) {
		client_warning("Failed to parse MESSAGES");
	}
	str = strstr(tmp, "RECENT ");
	if (str) {
		str += STRLEN("RECENT ");
		if (!strlen_zero(str)) {
			mbox->recent = (uint32_t) atol(str);
		}
	} else if (expect_full) {
		client_warning("Failed to parse RECENT");
	}
	str = strstr(tmp, "UNSEEN ");
	if (str) {
		str += STRLEN("UNSEEN ");
		if (!strlen_zero(str)) {
			mbox->unseen = (uint32_t) atol(str);
		}
	} else if (expect_full) {
		client_warning("Failed to parse UNSEEN");
	}
	if (IMAP_HAS_CAPABILITY(client, IMAP_CAPABILITY_STATUS_SIZE)) {
		str = strstr(tmp, "SIZE ");
		if (str) {
			str += STRLEN("SIZE ");
			if (!strlen_zero(str)) {
				mbox->size = (size_t) atol(str);
			}
		} else if (expect_full) {
			client_warning("Failed to parse SIZE");
		}
	}
}

int client_status_command(struct client *client, struct mailbox *mbox, char *restrict list_status_resp)
{
	int res = 0;
	struct mailimap_status_att_list *att_list;
	struct mailimap_mailbox_data_status *status;
	clistiter *cur;

	/* If LIST-STATUS is supported, we might not need to make a STATUS request at all */
	if (list_status_resp) {
		char *tmp;
		int skiplen;
		/* See if we can get what we want from the log message. */
		tmp = find_mailbox_response_line(list_status_resp, "STATUS", mbox->name, &skiplen);
		if (!tmp) {
			client_warning("No STATUS response for mailbox '%s'", mbox->name);
			/* Manually ask for it now, as usual */
		} else {
			/* Parse what we want from the STATUS response.
			 * Normally not a great idea, but STATUS responses are easy to parse. */
			tmp += skiplen;
			parse_status(client, mbox, tmp, 1);
			/* Look at all the time we saved! Profit and return */
			return 0;
		}
	}

	att_list = mailimap_status_att_list_new_empty();
	if (!att_list) {
		return -1;
	}

	res |= mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_UNSEEN);
	res |= mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_MESSAGES);
	res |= mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_RECENT);

	if (client->capabilities & IMAP_CAPABILITY_STATUS_SIZE) {
		/* If the server does not support STATUS=SIZE, then
		 * the size statistics for a mailbox will gradually drift from what
		 * the actual size is. We could manually compute the size like
		 * we do in client_list, but this would be very expensive and slow
		 * for large mailboxes to do frequently, so we just live with this.
		 *
		 * The only special logic is if a mailbox becomes empty, then obviously
		 * the size is 0. */
		res |= mailimap_status_att_list_add(att_list, MAILIMAP_STATUS_ATT_SIZE);
	}

	if (res) {
		client_error("Failed to construct STATUS: %s", maildriver_strerror(res));
		goto cleanup;
	}
	res = mailimap_status(client->imap, mbox->name, att_list, &status);

	if (res != MAILIMAP_NO_ERROR) {
		client_error("STATUS failed: %s", maildriver_strerror(res));
		goto cleanup;
	}
	res = 0;

	client_debug(6, "Issued STATUS command for %s", mbox->name);
	for (cur = clist_begin(status->st_info_list); cur; cur = clist_next(cur)) {
		struct mailimap_status_info *status_info = clist_content(cur);
		switch (status_info->st_att) {
			case MAILIMAP_STATUS_ATT_UNSEEN:
				client->mailboxes[0].unseen -= mbox->unseen; /* Autocorrect aggregate stats as needed */
				mbox->unseen = status_info->st_value;
				client->mailboxes[0].unseen += mbox->unseen;
				break;
			case MAILIMAP_STATUS_ATT_MESSAGES:
				client->mailboxes[0].total -= mbox->total;
				mbox->total = status_info->st_value;
				client->mailboxes[0].total += mbox->total;
				break;
			case MAILIMAP_STATUS_ATT_RECENT:
				client->mailboxes[0].recent -= mbox->recent;
				mbox->recent = status_info->st_value;
				client->mailboxes[0].recent += mbox->recent;
				break;
			case MAILIMAP_STATUS_ATT_SIZE:
				client->mailboxes[0].size -= mbox->size;
				mbox->size = status_info->st_value;
				client->mailboxes[0].size += mbox->size;
				break;
			default:
				break;
		}
	}
	mailimap_mailbox_data_status_free(status);

	if (!(client->capabilities & IMAP_CAPABILITY_STATUS_SIZE) && !mbox->total && mbox->size) {
		client_debug(5, "Deducing that mailbox size is now 0, since it has no messages");
		client->mailboxes[0].size -= mbox->size;
		mbox->size = 0;
	}

cleanup:
	mailimap_status_att_list_free(att_list);
	return res;
}

static inline uint32_t fetch_size(struct mailimap_msg_att *msg_att)
{
	clistiter *cur;

	for (cur = clist_begin(msg_att->att_list); cur; cur = clist_next(cur)) {
		struct mailimap_msg_att_item *item = clist_content(cur);
		if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC && item->att_data.att_static->att_type == MAILIMAP_MSG_ATT_RFC822_SIZE) {
			return item->att_data.att_static->att_data.att_rfc822_size;
		}
	}
	return 0;
}

struct list_status_cb {
	struct client *client;
	char *buf;
	size_t len;
};

static void list_status_logger(mailstream *imap_stream, int log_type, const char *str, size_t size, void *context)
{
	int len;

	/* This is a hack due to the limitations of libetpan.
	 * It is very tricky to be able to send an arbitrary command and be able to read the raw response from it.
	 * Ideally, libetpan would populate a list of STATUS, but it only does this for one mailbox,
	 * so with LIST-STATUS, the status returned would just be that of the last mailbox for which an untagged STATUS
	 * was received. This doesn't help us at all.
	 *
	 * Instead, we use this logger callback as a callback to be able to receive the raw data received.
	 * We'll analyze any STATUS lines that appear here, store the info we want from it,
	 * and then use that later.
	 * The LIST response is still parsed as usual in mailimap_list_status.
	 * We still let libetpan handle parsing the LIST responses and we only manually parse the STATUS responses.
	 */

	struct list_status_cb *cb = context;
	struct client *client = cb->client;

	(void) imap_stream;

	if (!size || log_type != MAILSTREAM_LOG_TYPE_DATA_RECEIVED) {
		return;
	} else if (unlikely(!cb->len)) {
		return;
	}

	/* Can be broken up across multiple log callback calls, so append to a dynstr */
	client_debug(6, "Log callback of %lu bytes for LIST-STATUS", size);
	/* Since this can take quite a bit of time, send an update here */
	/* Look for "* STATUS " */
	if (size > 8 && !strncmp(str, "* STATUS ", STRLEN("* STATUS "))) {
		const char *mb = str + STRLEN("* STATUS ");
		size_t maxlen = size - STRLEN("* STATUS ");
		if (maxlen > 1) {
			const char *end = memchr(mb + 1, *mb == '"' ? '"' : ' ', maxlen);
			size_t mblen = end ? (size_t) (end - mb) : maxlen;
			if (*mb == '"') {
				mb++;
				mblen--;
			}
			client_status("Queried status of %.*s", (int) mblen, mb);
		}
	}

	len = snprintf(cb->buf, cb->len, "%.*s", (int) size, str);
	cb->buf += len;
	cb->len -= len;
}

/*! \brief Basically mailimap_list, but sending a custom command */
static int mailimap_list_status(mailimap *session, clist **list_result)
{
	struct mailimap_response *response;
	int r;
	int error_code;

#define LIST_STATUS_CMD "LIST \"\" \"*\" RETURN (STATUS (MESSAGES RECENT UNSEEN SIZE))\r\n"
/* RFC 5258 Sec 4: Technically, if the server supports LIST-EXTENDED and we don't ask for CHILDREN explicitly,
 * it's not obligated to return these attributes */
#define LIST_STATUS_CHILDREN_CMD "LIST \"\" \"*\" RETURN (CHILDREN STATUS (MESSAGES RECENT UNSEEN SIZE))\r\n"

	if ((session->imap_state != MAILIMAP_STATE_AUTHENTICATED) && (session->imap_state != MAILIMAP_STATE_SELECTED)) {
		return MAILIMAP_ERROR_BAD_STATE;
	}
	r = mailimap_send_current_tag(session);
	if (r != MAILIMAP_NO_ERROR) {
		return r;
	}

	/* XXX mailimap_send_crlf and mailimap_send_custom_command aren't public */
	if (mailimap_has_extension(session, "LIST-EXTENDED")) {
		r = (int) mailstream_write(session->imap_stream, LIST_STATUS_CHILDREN_CMD, STRLEN(LIST_STATUS_CHILDREN_CMD));
		if (r != STRLEN(LIST_STATUS_CHILDREN_CMD)) {
			return MAILIMAP_ERROR_STREAM;
		}
	} else {
		r = (int) mailstream_write(session->imap_stream, LIST_STATUS_CMD, STRLEN(LIST_STATUS_CMD));
		if (r != STRLEN(LIST_STATUS_CMD)) {
			return MAILIMAP_ERROR_STREAM;
		}
	}

	if (mailstream_flush(session->imap_stream) == -1) {
		return MAILIMAP_ERROR_STREAM;
	}
	if (mailimap_read_line(session) == NULL) {
		return MAILIMAP_ERROR_STREAM;
	}
	r = mailimap_parse_response(session, &response);
	if (r != MAILIMAP_NO_ERROR) {
		return r;
	}

	*list_result = session->imap_response_info->rsp_mailbox_list;
	session->imap_response_info->rsp_mailbox_list = NULL;

	/* session->imap_response only contains the last line (e.g. LIST completed) */
	error_code = response->rsp_resp_done->rsp_data.rsp_tagged->rsp_cond_state->rsp_type;
	mailimap_response_free(response);

	switch (error_code) {
		case MAILIMAP_RESP_COND_STATE_OK:
			return MAILIMAP_NO_ERROR;
		default:
			return MAILIMAP_ERROR_LIST;
	}
}

static int mailbox_attr_from_string(const char *s)
{
	if (!strcasecmp(s, "NonExistent") || !strcasecmp(s, "NoSelect")) {
		return IMAP_MAILBOX_NOSELECT;
	} else if (!strcasecmp(s, "HasNoChildren")) {
		return IMAP_MAILBOX_NOCHILDREN;
	} else if (!strcasecmp(s, "HasChildren")) {
		return IMAP_MAILBOX_HASCHILDREN;
	} else if (!strcasecmp(s, "Drafts")) {
		return IMAP_MAILBOX_DRAFTS;
	} else if (!strcasecmp(s, "Junk")) {
		return IMAP_MAILBOX_JUNK;
	} else if (!strcasecmp(s, "Sent")) {
		return IMAP_MAILBOX_SENT;
	} else if (!strcasecmp(s, "Trash")) {
		return IMAP_MAILBOX_TRASH;
	} else {
		client_debug(1, "Ignoring unknown mailbox attribute: %s", s);
		return 0;
	}
}

struct mailbox_ref {
	const char *name;
	struct mailimap_mailbox_list *mb_list;
	int flags;
	char data[];
};

#define STR_STARTS_WITH_CASE(s, str) !strncasecmp(s, str, STRLEN(str))
#define STR_ENDS_WITH_CASE(s, str) !strcasecmp(s + strlen(s) - STRLEN(str), str)

static int mailbox_name_score(struct mailbox_ref *r)
{
	/* Done this way so that the smaller the value, the earlier it sorts */
	if (!strcasecmp(r->name, "INBOX")) {
		return -10 + 1;
	}
	/* It can end with INBOX too, the mailbox might not be named that exactly */
	if (STR_ENDS_WITH_CASE(r->name, "INBOX")) {
		return -10 + 1;
	}

	if (r->flags & IMAP_MAILBOX_DRAFTS) {
		return -10 + 2;
	} else if (r->flags & IMAP_MAILBOX_SENT) {
		return -10 + 3;
	/* Archives */
	} else if (r->flags & IMAP_MAILBOX_JUNK) {
		return -10 + 5;
	} else if (r->flags & IMAP_MAILBOX_TRASH) {
		return -10 + 6;
	}

	return 0;
}

static int namespace_score(struct mailbox_ref *r)
{
	/* Other namespaces sort last */
	/* XXX Should use LIST to determine what the other/shared namespace prefixes actually are */
	if (STR_STARTS_WITH_CASE(r->name, "Other Users")) {
		return 1;
	} else if (STR_STARTS_WITH_CASE(r->name, "Shared Folders")) {
		return 2;
	} else {
		return 0;
	}
}

static int mkparent(struct client *client, char *restrict buf, size_t len, const char *child)
{
	char *tmp;
	safe_strncpy(buf, child, len);
	tmp = strrchr(buf, client->delimiter);
	if (tmp) {
		*tmp = '\0';
		return 1;
	}
	return 0;
}

static inline int mbox_name_cmp(const char *a, const char *b)
{
	/*! \todo Make [ sort before alphabetic characters, for things like [Gmail] where that makes sense */
	return strcmp(a, b);
}

static int __mailbox_name_cmp(struct client *client, struct mailbox_ref *a, struct mailbox_ref *b, int cmp_attrs)
{
	int res = 0;
	int ns_a, ns_b;
	int score_a, score_b;
	int has_parent_a, has_parent_b;
	char parent_a[512], parent_b[512];

	ns_a = namespace_score(a);
	ns_b = namespace_score(b);
	if (ns_a < ns_b) {
		res = -1;
	} else if (ns_b < ns_a) {
		res = 1;
	}

	/* If one folder is a prefix of the other,
	 * then it is its parent */
	if (!strncmp(a->name, b->name, strlen(a->name))) {
		/* b starts with a */
		res = -1;
	} else if (!strncmp(a->name, b->name, strlen(b->name))) {
		/* a starts with b */
		res = 1;
	}

	has_parent_a = mkparent(client, parent_a, sizeof(parent_a), a->name);
	has_parent_b = mkparent(client, parent_b, sizeof(parent_b), b->name);

	/* Only compare attributes if the folders are siblings */
	if (has_parent_a == has_parent_b && (!has_parent_a || !strcmp(parent_a, parent_b))) {
		score_a = mailbox_name_score(a);
		score_b = mailbox_name_score(b);
		if (!res && cmp_attrs) {
			if (score_a < score_b) {
				res = -1;
			} else if (score_b < score_a) {
				res = 1;
			}
		}
	}

	if (!res) {
		res = mbox_name_cmp(a->name, b->name);
	}

	return res;
}

static int mailbox_name_cmp(const void *arg1, const void *arg2, void *varg)
{
	struct mailbox_ref *const *ap = arg1;
	struct mailbox_ref *const *bp = arg2;
	struct mailbox_ref *a = *ap, *b = *bp;
	struct client *client = varg;

	return __mailbox_name_cmp(client, a, b, 1);
}

static inline int mailbox_has_direct_parent(struct mailbox_ref **restrict mb_names, const char *restrict mb, int num_mailboxes, char delim, char *restrict parent, size_t parentlen)
{
	int i;
	char *end;

	safe_strncpy(parent, mb, parentlen);
	end = strrchr(parent, delim);
	if (!end) {
		/* This mailbox is at the top level (doesn't have a parent).
		 * For the purposes of what we care about, pretend it has
		 * a parent already since it's good to go */
		return 1;
	}

	*end = '\0';

	for (i = 0; i < num_mailboxes; i++) {
		if (!strcmp(mb_names[i]->name, parent)) {
			return 1;
		}
	}

	/* Not at top-level and doesn't have a direct ancestor */
	return 0;
}

/*! \brief Create a list of all mailboxes, properly sorted, with flags */
static struct mailbox_ref **populate_mailboxes(struct client *client, clist *imap_list)
{
	int i;
	clistiter *cur;
	struct mailbox_ref **mb_names;

	/* While we could just iterate over the list and add these to client->mailboxes
	 * in the order the mailboxes were listed by the server, this is a bad idea.
	 * The mailboxes could be provided in any order; there is no guarantee as to ordering.
	 * To present folders in a sane order, we first sort all of the folders,
	 * then adjust based on SPECIAL-USE mailboxes, and then use that order. */
	mb_names = malloc(sizeof(struct mailbox_ref*) * clist_count(imap_list));
	if (!mb_names) {
		mailimap_list_result_free(imap_list);
		return NULL;
	}
	client->num_mailboxes = 0;
	for (i = 0, cur = clist_begin(imap_list); cur; i++, cur = clist_next(cur)) {
		struct mailimap_mailbox_list *mb_list = clist_content(cur);
		const char *name = mb_list->mb_name;
		struct mailimap_mbx_list_flags *flags = mb_list->mb_flag;

		mb_names[i] = malloc(sizeof(struct mailbox_ref) + strlen(name) + 1);
		if (!mb_names[i]) {
			mailimap_list_result_free(imap_list);
			/* Leaks mb_names and its individual strings, but we're exiting anyways */
			return NULL;
		}
		strcpy(mb_names[i]->data, name); /* Safe */
		mb_names[i]->name = mb_names[i]->data;
		mb_names[i]->mb_list = mb_list;
		mb_names[i]->flags = 0;
		client->num_mailboxes++;
		/* Determine the hierarchy delimiter (should be same for all). */
		client->delimiter = mb_list->mb_delimiter;
		if (flags) {
			clistiter *cur2;
			if (flags->mbf_type == MAILIMAP_MBX_LIST_FLAGS_SFLAG) {
				switch (flags->mbf_sflag) {
					case MAILIMAP_MBX_LIST_SFLAG_MARKED:
						mb_names[i]->flags |= IMAP_MAILBOX_MARKED;
						break;
					case MAILIMAP_MBX_LIST_SFLAG_UNMARKED:
						break;
					case MAILIMAP_MBX_LIST_SFLAG_NOSELECT:
						mb_names[i]->flags |= IMAP_MAILBOX_NOSELECT;
						break;
				}
			}
			for (cur2 = clist_begin(flags->mbf_oflags); cur2; cur2 = clist_next(cur2)) {
				struct mailimap_mbx_list_oflag *oflag = clist_content(cur2);
				switch (oflag->of_type) {
					case MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS:
						break;
					case MAILIMAP_MBX_LIST_OFLAG_FLAG_EXT:
						/* These don't include any backslashes, so don't in the other ones above either: */
						mb_names[i]->flags |= mailbox_attr_from_string(oflag->of_flag_ext);
						break;
				}
			}
		}
	}

	/* The RFC does not state servers must include \NonExistent mailboxes
	 * for folders with no ancestors, so autocreate dummy mailboxes if needed.
	 * Use client->num_mailboxes as loop invariant since we need to also
	 * check anything we add during the loop. */
	for (i = 0; i < client->num_mailboxes; i++) {
		char parent[1024]; /* No mailbox name is going to be longer than this... */
		struct mailbox_ref **new_mb_names;
		if (mailbox_has_direct_parent(mb_names, mb_names[i]->name, client->num_mailboxes, client->delimiter, parent, sizeof(parent))) {
			continue;
		}
		client_debug(3, "Mailbox '%s' does not have a direct parent, autocreating '%s'", mb_names[i]->name, parent);
		new_mb_names = realloc(mb_names, sizeof(struct mailbox_ref *) * (client->num_mailboxes + 1));
		if (!new_mb_names) {
			client_error("realloc failed");
			return NULL;
		}
		mb_names = new_mb_names;
		mb_names[client->num_mailboxes] = malloc(sizeof(struct mailbox_ref) + strlen(parent) + 1);
		if (!mb_names[client->num_mailboxes]) {
			return NULL;
		}
		strcpy(mb_names[client->num_mailboxes]->data, parent); /* Safe */
		mb_names[client->num_mailboxes]->name = mb_names[client->num_mailboxes]->data;
		mb_names[client->num_mailboxes]->mb_list = NULL;
		mb_names[client->num_mailboxes]->flags = IMAP_MAILBOX_NONEXISTENT;
		client->num_mailboxes++;
	}

	qsort_r(mb_names, client->num_mailboxes, sizeof(struct mailbox_ref *), mailbox_name_cmp, client);

	/* mb_names is now sorted */
	return mb_names;
}

static int __client_list(struct client *client)
{
	clist *imap_list;
	int res, i;
	int needunselect = 0;
	/* This is a single-threaded application, so there is no concurrency risk to making this static/global,
	 * and it's probably better to put such a large buffer in the global segment rather than on the stack. */
	static char list_status_buf[32768]; /* Hopefully big enough to fit the entire LIST-STATUS response */

	client_status("Querying mailbox list");

	if (IMAP_HAS_CAPABILITY(client, IMAP_CAPABILITY_LIST_STATUS) && IMAP_HAS_CAPABILITY(client, IMAP_CAPABILITY_STATUS_SIZE)) {
		struct list_status_cb cb = {
			.buf = list_status_buf,
			.len = sizeof(list_status_buf),
			.client = client,
		};
		list_status_buf[0] = '\0';
		/* Fundamentally, libetpan does not support LIST-STATUS.
		 * It did not support STATUS=SIZE either, but it was easy to patch it support that
		 * (and mod_webmail requires such a patched version of libetpan).
		 * Rather than trying to kludge libetpan to support LIST-STATUS,
		 * it's easier to just send it the command we want and parse it ourselves. */
		mailstream_set_logger(client->imap->imap_stream, list_status_logger, &cb);
		res = mailimap_list_status(client->imap, &imap_list);
		mailstream_set_logger(client->imap->imap_stream, NULL, NULL);
	} else {
		res = mailimap_list(client->imap, "", "*", &imap_list);
	}

	if (res != MAILIMAP_NO_ERROR) {
		client_error("%s", maildriver_strerror(res));
		return -1;
	}
	if (!clist_begin(imap_list)) {
		client_error("List is empty?");
		mailimap_list_result_free(imap_list);
		return -1;
	}

	if (!client->mailboxes) {
		struct mailbox_ref **mb_names = populate_mailboxes(client, imap_list);
		if (!mb_names) {
			return -1;
		}

		/* This does mean we won't see new mailboxes created at runtime */
		client->num_mailboxes++; /* Plus one for aggregate stats */
		client->mailboxes = calloc(client->num_mailboxes, sizeof(struct mailbox));
		if (!client->mailboxes) {
			mailimap_list_result_free(imap_list);
			return -1;
		}

		i = 0;
		client->mailboxes[i].name = strdup("ALL");
		client->mailboxes[i].flags |= IMAP_MAILBOX_NOSELECT; /* Not a real mailbox! */

		/* Now, add items in the order they appear in mb_names */
		for (i = 1; i < client->num_mailboxes; i++) {
			const char *name;
			/* Use i-1 for indexing mb_names but i for indexing client->mailboxes */
			struct mailimap_mailbox_list *mb_list = mb_names[i - 1]->mb_list;

			client->mailboxes[i].flags = mb_names[i - 1]->flags;
			if (!mb_list) {
				/* If we can't find it, it's a \NonExistent mailbox we just created. */
				client->mailboxes[i].name = strdup(mb_names[i - 1]->name);
				if (!client->mailboxes[i].name) {
					return -1; /* Leaks but exiting */
				}
				continue;
			}

			name = mb_list->mb_name;
			client->delimiter = mb_list->mb_delimiter;
			client->mailboxes[i].name = strdup(name);

			if (client->mailboxes[i].flags & IMAP_MAILBOX_NOSELECT) {
				continue;
			}

			/* STATUS: ideally we could get all the details we want from a single STATUS command. */
			if (!client_status_command(client, &client->mailboxes[i], list_status_buf)) {
				if (!IMAP_HAS_CAPABILITY(client, IMAP_CAPABILITY_STATUS_SIZE)) { /* Lacks RFC 8438 support */
					uint32_t size = 0;
					if (client->mailboxes[i].total > 0) {
						/* Do it the manual way. */
						struct mailimap_fetch_type *fetch_type;
						struct mailimap_fetch_att *fetch_att;
						clist *fetch_result;
						struct mailimap_set *set = mailimap_set_new_interval(1, 0); /* fetch in interval 1:* */

						client_status("Calculating size of %s", name);
						/* Must EXAMINE mailbox */
						res = mailimap_examine(client->imap, name);
						if (res != MAILIMAP_NO_ERROR) {
							client_error("Failed to EXAMINE mailbox '%s'", name);
						} else {
							fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
							fetch_att = mailimap_fetch_att_new_rfc822_size();
							mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);
							res = mailimap_fetch(client->imap, set, fetch_type, &fetch_result);
							if (res != MAILIMAP_NO_ERROR) {
								client_error("Failed to calculate size of mailbox %s: %s", name, maildriver_strerror(res));
							} else {
								clistiter *cur2;
								/* Iterate over each message size */
								for (cur2 = clist_begin(fetch_result); cur2; cur2 = clist_next(cur2)) {
									struct mailimap_msg_att *msg_att = clist_content(cur2);
									size += fetch_size(msg_att);
								}
								mailimap_fetch_list_free(fetch_result);
								mailimap_fetch_type_free(fetch_type);
							}
							/* UNSELECT the mailbox, since we weren't supposed to do this.
							 * XXX If a mailbox was previously selected, after we're done with all this,
							 * reselect that one. */
							needunselect = 1;
						}
						mailimap_set_free(set);
					}
					client->mailboxes[i].size = size;
					client->mailboxes[i].uidvalidity = client->imap->imap_selection_info->sel_uidvalidity;
					client->mailboxes[i].uidnext = client->imap->imap_selection_info->sel_uidnext;
				}
			}
			/* Update aggregate stats for all mailboxes */
			client->mailboxes[0].total += client->mailboxes[i].total;
			client->mailboxes[0].unseen += client->mailboxes[i].unseen;
			client->mailboxes[0].recent += client->mailboxes[i].recent;
			client->mailboxes[0].size += client->mailboxes[i].size;
		}

		/* Free list of mailboxes used for sorting */
		for (i = 0; i < client->num_mailboxes - 1; i++) {
			free(mb_names[i]);
		}
		free(mb_names);
	}

	if (needunselect) {
		/* UNSELECT itself is an extension. Only do if supported. */
		if (IMAP_HAS_CAPABILITY(client, IMAP_CAPABILITY_UNSELECT)) {
			res = mailimap_custom_command(client->imap, "UNSELECT");
			if (MAILIMAP_ERROR(res)) {
				client_error("UNSELECT failed");
			}
		} else {
			client_debug(4, "No way to unselect mailbox...");
			/* It's fine, the current mailbox won't be used until some mailbox is selected anyways... */
		}
	}

	mailimap_list_result_free(imap_list);
	return 0;
}

int client_list(struct client *client)
{
	return __client_list(client);
}

static int load_quota(struct client *client, struct mailbox *mbox)
{
	int res;
	clistiter *cur;
	struct mailimap_quota_complete_data *quotaroot_complete = NULL;

	res = mailimap_quota_getquotaroot(client->imap, mbox->name, &quotaroot_complete);
	if (MAILIMAP_ERROR(res)) {
		return -1;
	}
	for (cur = clist_begin(quotaroot_complete->quota_list); cur; cur = clist_next(cur)) {
		struct mailimap_quota_quota_data *qd = clist_content(cur);
		clistiter *cur2;
		for (cur2 = clist_begin(qd->quota_list); cur2; cur2 = clist_next(cur2)) {
			struct mailimap_quota_quota_resource *qr = clist_content(cur2);
			client_debug(2, "Mailbox '%s', usage %u, limit %u", quotaroot_complete->quotaroot_data->mailbox, qr->usage, qr->limit);
			client->quota_limit = qr->limit;
			client->quota_used = qr->usage;
		}
	}
	mailimap_quota_complete_data_free(quotaroot_complete);
	return 0;
}

static inline int mailbox_presentation_has_changed(struct client *client, struct mailbox *mbox)
{
	/* If anything about this mailbox has changed, that we display in the folder pane,
	 * we may need to regenerate its presentation in the folder pane. */
	if (client->imap->imap_selection_info->sel_uidnext != mbox->uidnext) {
		return 1;
	}
	if (client->imap->imap_selection_info->sel_exists != mbox->total) {
		return 1;
	}
	if (client->imap->imap_selection_info->sel_recent != mbox->recent) {
		return 1;
	}
	return 0;
}

static int num_common_prefix_chars(const char *s1, const char *s2)
{
	int i = 0;
	while (*s1 && *s2) {
		if (*s1 != *s2) {
			return i;
		}
		s1++;
		s2++;
	}
	return i;
}

static int ends_with(const char *s, const char *sub)
{
	size_t slen, sublen, diff;

	slen = strlen(s);
	sublen = strlen(sub);
	if (slen < sublen) {
		return 0;
	}

	diff = slen - sublen;
	s += diff;
	return !strncasecmp(s, sub, sublen);
}

static struct mailbox *find_specialuse_mailbox(struct client *client, int flag, const char *suffix)
{
	int i;
	char parent[512], parent2[512];
	int has_parent_a, has_parent_b;
	size_t parentlen;
	struct mailbox *best = NULL;
	int max_common = 0, common;
	int found_specialuse = 0;

	/* Find the correct trash mailbox for the current mailbox.
	 * In simple environments, there should only be one, probably called "Trash",
	 * but if there are multiple namespaces available to use, we may have
	 * several Trash mailboxes, and we need to select the right one. */

	has_parent_a = mkparent(client, parent, sizeof(parent), client->sel_mbox->name);
	parentlen = strlen(parent);

	for (i = 0; i < client->num_mailboxes; i++) {
		if (!(client->mailboxes[i].flags & flag)) {
			continue;
		}
		/* We know this IMAP server supports SPECIAL-USE flags,
		 * so we expect the correct mailbox must have the flag we seek. */
		found_specialuse = 1;
		/* Try to find the best match.
		 * For example, if the current mailbox is:
		 * Other Users.jsmith.Sub.Folder
		 * Other Users.jsmith.Trash is likely the correct trash mailbox,
		 * not Trash, or anything else. */
		has_parent_b = mkparent(client, parent2, sizeof(parent2), client->mailboxes[i].name);
		if (has_parent_a != has_parent_b) {
			continue;
		} else if (has_parent_a) {
			/* One parent must at least start with the other,
			 * for example, Gmail's special use folders are in
			 * subfolders of [Gmail]. */
			if (strncmp(parent, parent2, parentlen) && strncmp(parent, parent2, strlen(parent2))) {
				continue;
			}
		}
		common = num_common_prefix_chars(client->sel_mbox->name, client->mailboxes[i].name);
		if (common >= max_common) { /* >=, so even if 0 common prefix chars, Trash should override */
			best = &client->mailboxes[i];
			max_common = common;
		}
	}

	if (!found_specialuse) {
		/* Not ideal, but since SPECIAL-USE attributes couldn't answer the question,
		 * try to find it simply by parsing mailbox names for the closest match. */
		client_debug(1, "IMAP server does not appear to support SPECIAL-USE attributes for %s", suffix);
		max_common = 0;
		for (i = 0; i < client->num_mailboxes; i++) {
			if (!ends_with(client->mailboxes[i].name, suffix)) {
				continue;
			}
			common = num_common_prefix_chars(client->sel_mbox->name, client->mailboxes[i].name);
			if (common > max_common) {
				best = &client->mailboxes[i];
				max_common = common;
			}
		}
	} /* else, whether it's NULL or not, return what we have now. */
	if (!best) {
		client_warning("Unable to determine SPECIAL-USE %s mailbox for %s (SPECIAL-USE: %d)", suffix, client->sel_mbox->name, found_specialuse);
	} else {
		client_debug(3, "Auto-determined %s mailbox for %s: %s", suffix, client->sel_mbox->name, best->name);
	}
	return best;
}

int client_select(struct client *client, struct mailbox *mbox)
{
	int res;
	int need_redraw = 0;

	/* For some reason, the SELECT response can't give you the number of unread messages.
	 * We need to explicitly ask for the STATUS to get that.
	 * Do so and send it along because that will help the frontend.
	 * What could pose a problem is that with IMAP, you are not SUPPOSED to
	 * issue a STATUS for the currently selected mailbox.
	 * Personally, I think this is stupid, since there's no other way to get this information,
	 * and so what if you want that for the currently selected mailbox?
	 * We therefore ask for the STATUS before doing the SELECT, to maximize compatibility with
	 * servers that may adhere to such a dumb limitation, but that won't help if this mailbox
	 * was already selected anyways, and we're merely reselecting it.
	 */
	res = client_status_command(client, mbox, NULL);
	if (res != MAILIMAP_NO_ERROR) {
		client_error("STATUS '%s' failed: %s", mbox->name, maildriver_strerror(res));
		return -1;
	}

	/* Actually SELECT it */
	res = mailimap_select(client->imap, mbox->name);
	if (res != MAILIMAP_NO_ERROR) {
		client_error("SELECT '%s' failed: %s", mbox->name, maildriver_strerror(res));
		return -1;
	}

	/* XXX Since we call client_status_command right beforehand, won't this always be false? */
	need_redraw = mailbox_presentation_has_changed(client, mbox); /* Need to check before we overwrite any of the mailbox data */
	if (need_redraw) {
		client_debug(2, "Mailbox %s has changed since last select", mbox->name);
	}

	mbox->uidnext = client->imap->imap_selection_info->sel_uidnext;
	mbox->uidvalidity = client->imap->imap_selection_info->sel_uidvalidity;
	if (client->imap->imap_selection_info->sel_perm == MAILIMAP_MAILBOX_READONLY) {
		mbox->flags |= IMAP_MAILBOX_READONLY;
	} else {
		mbox->flags &= ~IMAP_MAILBOX_READONLY;
	}
	mbox->total = client->imap->imap_selection_info->sel_exists;
	mbox->recent = client->imap->imap_selection_info->sel_recent;

	/* Save permanent flags */
	if (!mbox->num_keywords) { /* Only do this the first time we select a mailbox (this does mean we won't see new ones during execution) */
		clistiter *cur;
		for (cur = clist_begin(client->imap->imap_selection_info->sel_perm_flags); cur; cur = clist_next(cur)) {
			struct mailimap_flag_perm *perm_flag = clist_content(cur);
			switch (perm_flag->fl_type) {
				case MAILIMAP_FLAG_PERM_FLAG:
					switch (perm_flag->fl_flag->fl_type) {
						case MAILIMAP_FLAG_ANSWERED:
						case MAILIMAP_FLAG_FLAGGED:
						case MAILIMAP_FLAG_DELETED:
						case MAILIMAP_FLAG_SEEN:
						case MAILIMAP_FLAG_DRAFT:
							break;
						case MAILIMAP_FLAG_KEYWORD:
							/* Store up to the first 64 keywords per mailbox */
							if (mbox->num_keywords < MAX_KEYWORDS) {
								mbox->keywords[mbox->num_keywords++] = strdup(perm_flag->fl_flag->fl_data.fl_keyword);
							}
							break;
						case MAILIMAP_FLAG_EXTENSION:
							break;
					}
					break;
				case MAILIMAP_FLAG_PERM_ALL:
					/* \All is not a flag, this means "all"... */
					mbox->keywords_allowed = 1;
					break;
			}
		}
		need_redraw = 1; /* First time */
	}

	/* Save current quota usage. */
	if (IMAP_HAS_CAPABILITY(client, IMAP_CAPABILITY_QUOTA)) {
		load_quota(client, mbox);
	}

	/* If we selected a mailbox that was marked, it is no longer marked */
	if (mbox->flags & IMAP_MAILBOX_MARKED) {
		mbox->flags &= ~IMAP_MAILBOX_MARKED;
		need_redraw = 1;
	}

	if (need_redraw) {
		redraw_folder_pane(client);
	}

	client_status("Selected '%s'", mbox->name);
	client->sel_mbox = mbox;
	client->trash_mbox = find_specialuse_mailbox(client, IMAP_MAILBOX_TRASH, "Trash");
	client->junk_mbox = find_specialuse_mailbox(client, IMAP_MAILBOX_JUNK, "Junk");
	client->sent_mbox = find_specialuse_mailbox(client, IMAP_MAILBOX_SENT, "Sent");
	client->draft_mbox = find_specialuse_mailbox(client, IMAP_MAILBOX_DRAFTS, "Drafts");
	return 0;
}

/* Note: We must deal with unsigned char for this func, which is why -funsigned-char is included in the build flags */
static char *mime_header_decode(const char *s)
{
	size_t cur_token;
	int encoded = 0;
	char *decoded = NULL;

	/* Decode header per RFC 2047 */
	/* See also: https://github.com/dinhvh/libetpan/issues/24 */

	if (strlen_zero(s)) {
		return NULL;
	}
	if (strstr(s, "=?")) {
		encoded = strcasestr(s, "?Q?") || strcasestr(s, "?B?");
	}
	if (!encoded) {
		/* XXX Interpret as UTF-8 */
		return NULL;
	}
	cur_token = 0;
	/* Decode any RFC 2047 encoded words */

	mailmime_encoded_phrase_parse("iso-8859-1", s, strlen(s), &cur_token, "utf-8", &decoded);
	if (!decoded) {
		client_debug(1, "Failed to decode MIME header");
		return NULL;
	}

	return decoded;
}

/*!
 * \brief Convert a datetime in an arbitrary timezone to local time
 * \param[out] dst Local time
 * \param[in] src Original time
 */
static inline void convert_to_localtime(struct tm *restrict dst, struct tm *restrict src)
{
	time_t epoch;
	long int offset;

	offset = src->tm_gmtoff;
	epoch = timegm(src) - offset;
#ifdef EXTRA_DEBUG_MODE
	client_debug(5, "Parsed datetime -> epoch %ld (had offset %ld)", epoch, offset);
	if (epoch < 0) { /* It should never be negative... */
		client_debug(1, "Date parsed to %ld? (%ld/%ld)", epoch, offset, timegm(src));
		return;
	}
#endif
	localtime_r(&epoch, dst);
}

static inline void append_internaldate(struct message *msg, struct mailimap_date_time *dt)
{
	char buf[40];
	struct tm tm;

	snprintf(buf, sizeof(buf), "%4d-%02d-%02d %02d:%02d:%02d %c%04d",
		dt->dt_year, dt->dt_month, dt->dt_day, dt->dt_hour, dt->dt_min, dt->dt_sec,
	dt->dt_zone < 0 ? '-' : '+', dt->dt_zone < 0 ? -dt->dt_zone : dt->dt_zone); /* -/+ followed by abs value for formatting */

	memset(&msg->intdate, 0, sizeof(struct tm)); /* so that fields not set by strptime are still zeroed */

	if (!strptime(buf, "%Y-%m-%d %H:%M:%S %z", &tm)) {
		client_debug(1, "Failed to parse INTERNALDATE %s?", buf);
	} else {
		convert_to_localtime(&msg->intdate, &tm);
	}
}

static int parse_rfc822_date(const char *s, struct tm *tm)
{
	char *t;

	/* Multiple possible date formats:
	 * 15 Oct 2002 23:57:35 +0300
	 * Tues, 15 Oct 2002 23:57:35 +0300
	 *  Mon, 3 Jul 2023 22:01:33 GMT */
	if ((t = strptime(s, "%a, %d %b %Y %H:%M:%S %z", tm)) || (t = strptime(s, "%d %b %Y %H:%M:%S %z", tm))) {
		return 0;
	}

	/* I've encountered some emails where the date is something like this:
	 * Mon, 3 Jul 2023 22:01:33 GMT
	 * Note that instead of an offset, you just have a TZ abbreviation.
	 * Valid according to RFC 822 5.1, but not according to RFC 2822 3.3, and not very common. */
	if ((t = strptime(s, "%a, %d %b %Y %H:%M:%S %Z", tm))) {
		client_debug(1, "Non-RFC2822 compliant date: %s (%s)", s, t);
		return 0;
	}

	client_debug(1, "Failed to parse as date: '%s'", s);
	return -1;
}

static inline void process_header_data(struct message *msg, const char *hdrname, const char *hdrval)
{
	if (!strcasecmp(hdrname, "X-Priority")) {
		msg->importance = atoi(hdrval); /* It'll stop where it should, this just works! */
	} else if (!strcasecmp(hdrname, "Importance") || !strcasecmp(hdrname, "X-MSMail-Priority")) {
		if (!strcasecmp(hdrval, "high")) {
			msg->importance = 1;
		} else if (!strcasecmp(hdrval, "low")) {
			msg->importance = 5;
		} else {
			msg->importance = 3;
		}
	} else if (!strcasecmp(hdrname, "Priority")) {
		if (!strcasecmp(hdrval, "Urgent")) {
			msg->importance = 1;
		} else if (!strcasecmp(hdrval, "Non-Urgent")) {
			msg->importance = 5;
		} else {
			msg->importance = 3;
		}
	} else if (!strcasecmp(hdrname, "Date")) {
		struct tm tm;
		memset(&tm, 0, sizeof(tm));
		parse_rfc822_date(hdrval, &tm);
		convert_to_localtime(&msg->date, &tm);
	} else {
		char *decoded = mime_header_decode(hdrval);
		if (decoded) {
			client_debug(5, "Decoded %s: %s => %s", hdrname, hdrval, decoded);
			hdrval = decoded;
		}
		if (!strcasecmp(hdrname, "From")) {
			REPLACE(msg->from, hdrval);
		} else if (!strcasecmp(hdrname, "Subject")) {
			REPLACE(msg->subject, hdrval);
		} else { /* else, there shouldn't be anything unaccounted for, since we only fetched specific headers of interest */
			client_debug(1, "Unanticipated header: %s", hdrname);
		}
		free_if(decoded);
	}
}

static inline void process_headers_data(struct message *msg, char *headers)
{
	char *header, *tmp;

	/* This function only parses the first line of headers, if they are multi-line,
	 * since we won't be able to display more than that in the message pane anyways.
	 * When a message is actually selected, that's different. */

	while ((header = strsep(&headers, "\n"))) {
		char *hdrname, *hdrval = header;
		if (strlen_zero(header)) {
			break; /* End of headers */
		}
		if (isspace(header[0])) {
			continue; /* Skip continuations of multiline headers */
		}
		hdrname = strsep(&hdrval, ":");
		while (hdrval && *hdrval == ' ') {
			hdrval++; /* Skip leading whitespace */
		}
		/* Strip CR */
		tmp = strchr(hdrval, '\r');
		if (tmp) {
			*tmp = '\0';
		}
		process_header_data(msg, hdrname, hdrval);
	}
}

static void mailbox_add_keyword(struct mailbox *mbox, const char *keyword)
{
	int i;
	for (i = 0; i < mbox->num_keywords; i++) {
		if (!strcmp(mbox->keywords[i], keyword)) {
			client_debug(1, "Keyword '%s' already exists", keyword);
			return;
		}
	}
	if (mbox->num_keywords < MAX_KEYWORDS) {
		client_debug(1, "Adding keyword '%s' to mailbox %s", keyword, mbox->name);
		mbox->keywords[mbox->num_keywords] = strdup(keyword);
		mbox->num_keywords++;
	} else {
		client_debug(1, "Can't add keyword, already at max keywords");
	}
}

void message_add_keyword(struct mailbox *mbox, struct message *msg, const char *keyword)
{
	int i;
	for (i = 0; i < mbox->num_keywords; i++) {
		if (!strcmp(mbox->keywords[i], keyword)) {
			msg->keywords |= (1 << i);
			return;
		}
	}
	/* The message has a keyword that wasn't returned in the mailbox's PERMANENTFLAGS response.
	 * It's likely a new keyword that just got created, and maybe we missed an untagged PERMANENTFLAGS announcing this. */
	client_debug(1, "Keyword '%s' not yet a known PERMANENTFLAG in %s? Adding it...", keyword, mbox->name);
	if (mbox->num_keywords < MAX_KEYWORDS) {
		mbox->keywords[mbox->num_keywords] = strdup(keyword);
		msg->keywords |= (1 << mbox->num_keywords);
		mbox->num_keywords++;
	} else {
		client_debug(1, "Can't add keyword, already at max keywords");
	}
}

static int fetchlist_single(struct mailimap_msg_att *msg_att, struct mailbox *mbox, struct message *msg, int process_full)
{
	clistiter *cur2;

	for (cur2 = clist_begin(msg_att->att_list); cur2; cur2 = clist_next(cur2)) {
		struct mailimap_msg_att_item *item = clist_content(cur2);
		if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC) {
			if (process_full) {
				struct mailimap_msg_att_body_section *msg_att_body_section;
				char headersbuf[8192]; /* Should be large enough for most email headers */
				switch (item->att_data.att_static->att_type) {
					case MAILIMAP_MSG_ATT_UID:
						msg->uid = item->att_data.att_static->att_data.att_uid;
						break;
					case MAILIMAP_MSG_ATT_INTERNALDATE:
						append_internaldate(msg, item->att_data.att_static->att_data.att_internal_date);
						break;
					case MAILIMAP_MSG_ATT_RFC822_SIZE:
						msg->size = item->att_data.att_static->att_data.att_rfc822_size;
						break;
					case MAILIMAP_MSG_ATT_BODY_SECTION:
						msg_att_body_section = item->att_data.att_static->att_data.att_body_section;
						/* Manual hacky workaround */
						/* Seems calling mailmime_parse and fetch_mime_recurse here is pointless
						 * since we still have to do append_header_meta on those fields anyways,
						 * or they don't show up. Can't just parse headers into mailmime_parse. */
						safe_strncpy(headersbuf, msg_att_body_section->sec_body_part, sizeof(headersbuf));
						process_headers_data(msg, headersbuf);
						break;
					case MAILIMAP_MSG_ATT_BODYSTRUCTURE:
						break;
					case MAILIMAP_MSG_ATT_RFC822_HEADER:
					case MAILIMAP_MSG_ATT_ENVELOPE:
					case MAILIMAP_MSG_ATT_RFC822_TEXT:
					case MAILIMAP_MSG_ATT_BODY:
					default:
						client_debug(1, "Unhandled FETCH response item");
						break;
				}
			}
		} else { /* MAILIMAP_MSG_ATT_ITEM_DYNAMIC */
			struct mailimap_msg_att_dynamic *dynamic = item->att_data.att_dyn;
			clistiter *dcur;
			if (dynamic && dynamic->att_list) {
				for (dcur = clist_begin(dynamic->att_list); dcur; dcur = clist_next(dcur)) {
					struct mailimap_flag_fetch *flag = clist_content(dcur);
					switch (flag->fl_type) {
						case MAILIMAP_FLAG_FETCH_RECENT:
							msg->flags |= IMAP_MESSAGE_FLAG_RECENT;
							break;
						case MAILIMAP_FLAG_FETCH_OTHER:
							switch (flag->fl_flag->fl_type) {
								case MAILIMAP_FLAG_ANSWERED:
									msg->flags |= IMAP_MESSAGE_FLAG_ANSWERED;
									break;
								case MAILIMAP_FLAG_FLAGGED:
									msg->flags |= IMAP_MESSAGE_FLAG_FLAGGED;
									break;
								case MAILIMAP_FLAG_DELETED:
									msg->flags |= IMAP_MESSAGE_FLAG_DELETED;
									break;
								case MAILIMAP_FLAG_SEEN:
									msg->flags |= IMAP_MESSAGE_FLAG_SEEN;
									break;
								case MAILIMAP_FLAG_DRAFT:
									msg->flags |= IMAP_MESSAGE_FLAG_DRAFT;
									break;
								case MAILIMAP_FLAG_KEYWORD:
									message_add_keyword(mbox, msg, flag->fl_flag->fl_data.fl_keyword);
									break;
								case MAILIMAP_FLAG_EXTENSION:
									break;
							}
							break;
					}
				}
			}
		}
	}

	return 0;
}

static int __fetchlist(struct client *client, int start, int end)
{
	struct mailimap_set *set = NULL;
	struct mailimap_fetch_type *fetch_type = NULL;
	struct mailimap_fetch_att *fetch_att = NULL;
	clist *fetch_result = NULL;
	clistiter *cur;
	clist *hdrlist;
	char *headername = NULL;
	struct mailimap_header_list *imap_hdrlist;
	struct mailimap_section *section;
	int res, i, seqno;

	set = mailimap_set_new_interval((uint32_t) start, (uint32_t) end);

	fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();

	/* UID */
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_uid());
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_flags()); /* Flags */
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_internaldate()); /* INTERNALDATE */
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_rfc822_size()); /* Size */
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_bodystructure()); /* BODYSTRUCTURE (for attachments) */

	/* Headers */
	hdrlist = clist_new();
	if (!hdrlist) {
		mailimap_set_free(set);
		mailimap_fetch_att_free(fetch_att);
		return -1;
	}

#define FETCH_HEADER(name) \
	headername = strdup(name); \
	res = clist_append(hdrlist, headername); \
	if (!hdrlist) { \
		goto cleanup; \
	}

	FETCH_HEADER("Date");
	FETCH_HEADER("Subject");
	FETCH_HEADER("From");
	FETCH_HEADER("X-Priority");
	FETCH_HEADER("Importance");
	FETCH_HEADER("X-MSMail-Priority");
	FETCH_HEADER("Priority");

	imap_hdrlist = mailimap_header_list_new(hdrlist);
	section = mailimap_section_new_header_fields(imap_hdrlist);
	if (!section) {
		goto cleanup2;
	}
	fetch_att = mailimap_fetch_att_new_body_peek_section(section);
	if (!fetch_att) {
		goto cleanup2;
	}
	res = mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);
	if (MAILIMAP_ERROR(res)) {
		goto cleanup;
	}
	fetch_att = NULL;

	/* Fetch! By sequence number, not UID. */
	res = mailimap_fetch(client->imap, set, fetch_type, &fetch_result);
	mailimap_fetch_type_free(fetch_type);
	/* Don't go to cleanup past this point, so no need to set fetch_type/set to NULL */
	if (MAILIMAP_ERROR(res)) {
		client_error("FETCH failed: %s", maildriver_strerror(res));
		/* fetch_result and everything that went into it is already freed */
		mailimap_set_free(set);
		return -1;
	}

	/* Populate cache of saved messages */
	free_cached_messages(client);
	if (init_messages(client, clist_count(fetch_result))) {
		mailimap_fetch_list_free(fetch_result);
		mailimap_set_free(set);
		return -1;
	}
	for (seqno = start, i = 0, cur = clist_begin(fetch_result); cur; seqno++, i++, cur = clist_next(cur)) {
		struct mailimap_msg_att *msg_att = clist_content(cur);
		struct message *msg = new_message(client, i, seqno);
		if (!msg) {
			mailimap_fetch_list_free(fetch_result);
			mailimap_set_free(set);
			return -1;
		}
		fetchlist_single(msg_att, client->sel_mbox, msg, 1);
	}

	client_status("Fetched headers %d:%d", start, end);
	mailimap_fetch_list_free(fetch_result);
	mailimap_set_free(set);
	return 0;

cleanup:
	mailimap_set_free(set);
	free_if(headername);
	/* Doesn't compile: clist_foreach(hdrlist, (clist_func) free, NULL); */
	for (cur = clist_begin(hdrlist); cur; cur = clist_next(cur)) {
		headername = clist_content(cur);
		free(headername);
	}
	clist_free(hdrlist);

	if (fetch_att) {
		mailimap_fetch_att_free(fetch_att);
	}
	if (fetch_type) {
		mailimap_fetch_type_free(fetch_type);
	}
	return -1;

cleanup2:
	mailimap_set_free(set);
	mailimap_header_list_free(imap_hdrlist);
	if (fetch_att) {
		mailimap_fetch_att_free(fetch_att);
	}
	if (fetch_type) {
		mailimap_fetch_type_free(fetch_type);
	}
	return -1;
}

int client_fetchlist(struct client *client)
{
	if (!client->sel_mbox->total) {
		/* Mailbox is empty */
		client_status("Mailbox '%s' is empty", client->sel_mbox->name);
		return 0;
	}

	return __fetchlist(client, client->start_seqno, client->end_seqno);
}

/*! \brief Issue FETCH command to get info about new messages during IDLE */
/*! \note Similar to __fetchlist, but we populate with individual messages, rather than a range */
static int client_fetch_postidle(struct client *client, int mbox_resync_flags)
{
	struct mailimap_set *set = NULL;
	struct mailimap_fetch_type *fetch_type = NULL;
	struct mailimap_fetch_att *fetch_att = NULL;
	clist *fetch_result = NULL;
	clistiter *cur;
	clist *hdrlist;
	char *headername = NULL;
	struct mailimap_header_list *imap_hdrlist;
	struct mailimap_section *section;
	int res, i, num_msgs;
	struct message *msg;
	int added = 0, processed = 0;

	assert(!client->idling);

	set = mailimap_set_new_empty();
	if (!set) {
		return -1;
	}

	num_msgs = num_messages(client);
	if (!num_msgs) {
		return -1;
	}
	msg = get_msg(client, 0);
	for (i = 0; i < num_msgs; i++, msg = msg->next) {
		if (msg->fetchflags & (MSG_FETCH_FLAGS | MSG_FETCH_ALL)) {
			mailimap_set_add_single(set, msg->seqno);
			added++;
		}
	}

	assert(added > 0);

	fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type,  mailimap_fetch_att_new_uid()); /* UID */
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_flags()); /* Flags */
	if (mbox_resync_flags & MBOX_NEED_FETCH_ALL) {
		mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_internaldate()); /* INTERNALDATE */
		mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_rfc822_size()); /* Size */
		mailimap_fetch_type_new_fetch_att_list_add(fetch_type, mailimap_fetch_att_new_bodystructure()); /* BODYSTRUCTURE (for attachments) */
		/* Headers */
		hdrlist = clist_new();
		if (!hdrlist) {
			mailimap_set_free(set);
			mailimap_fetch_att_free(fetch_att);
			return -1;
		}

		FETCH_HEADER("Date");
		FETCH_HEADER("Subject");
		FETCH_HEADER("From");
		FETCH_HEADER("X-Priority");
		FETCH_HEADER("Importance");
		FETCH_HEADER("X-MSMail-Priority");
		FETCH_HEADER("Priority");

		imap_hdrlist = mailimap_header_list_new(hdrlist);
		section = mailimap_section_new_header_fields(imap_hdrlist);
		if (!section) {
			goto cleanup2;
		}
		fetch_att = mailimap_fetch_att_new_body_peek_section(section);
		if (!fetch_att) {
			goto cleanup2;
		}
		res = mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);
		if (MAILIMAP_ERROR(res)) {
			goto cleanup;
		}
		fetch_att = NULL;
	}

	/* Fetch! By sequence number, not UID. */
	res = mailimap_fetch(client->imap, set, fetch_type, &fetch_result);
	mailimap_fetch_type_free(fetch_type);
	/* Don't go to cleanup past this point, so no need to set fetch_type/set to NULL */
	if (MAILIMAP_ERROR(res)) {
		client_error("FETCH failed: %s", maildriver_strerror(res));
		/* fetch_result and everything that went into it is already freed */
		mailimap_set_free(set);
		return -1;
	}

/*! \brief Is the message with this sequence number currently loaded in the message menu? */
#define MSG_SEQNO_IN_MENU_RANGE(client, s) (s >= client->start_seqno && s <= client->start_seqno + client->message_list.n - 1)

	/* Update existing messages or add new ones, based on results */
	for (i = 0, msg = get_msg(client, 0), cur = clist_begin(fetch_result); cur && i < num_msgs; i++, msg = msg->next) {
		struct mailimap_msg_att *msg_att;
		int was_seen;

		if (!(msg->fetchflags & (MSG_FETCH_FLAGS | MSG_FETCH_ALL))) {
			continue;
		}

		/* Process all messages received,
		 * assume they are in increasing sequence number order. */
		msg_att = clist_content(cur);
		msg->flags = 0; /* Reset flags before fetching again, e.g. so we reflect if a flag was removed */
		msg->keywords = 0;
		was_seen = msg->flags & IMAP_MESSAGE_FLAG_SEEN;
		if (msg->fetchflags & MSG_FETCH_ALL) {
			assert(mbox_resync_flags & MBOX_NEED_FETCH_ALL);
			client_debug(5, "Fetching entire message %d", msg->seqno);
			fetchlist_single(msg_att, client->sel_mbox, msg, 1);
		} else { /* MSG_FETCH_FLAGS */
			client_debug(5, "Fetching only flags for message %d", msg->seqno);
			/* Just check for flag changes, nothing else. */
			fetchlist_single(msg_att, client->sel_mbox, msg, 0);
		}
		if (was_seen && !(msg->flags & IMAP_MESSAGE_FLAG_SEEN)) {
			/* Message was previously seen, and now is no longer.
			 * This is an edge case, for FORCE_REFETCH_FLAGS, since when we initially process the FETCH
			 * during IDLE, we set REFRESH_MESSAGE_PANE if it's within view,
			 * so that will ensure the message pane updates.
			 * However, the folder pane also needs to be updated. */
			client->refreshflags |= REFRESH_FOLDERS;
		}
		processed++;
		msg->fetchflags &= ~(MSG_FETCH_FLAGS | MSG_FETCH_ALL);
		cur = clist_next(cur);
	}

	if (processed != added) {
		client_error("Wanted to process %d messages but only processed %d?", added, processed);
	}

	mailimap_fetch_list_free(fetch_result);
	mailimap_set_free(set);
	return 0;

cleanup:
	mailimap_set_free(set);
	if (mbox_resync_flags & MBOX_NEED_FETCH_ALL) {
		free_if(headername);
		for (cur = clist_begin(hdrlist); cur; cur = clist_next(cur)) {
			headername = clist_content(cur);
			free(headername);
		}
		clist_free(hdrlist);
	}

	if (fetch_att) {
		mailimap_fetch_att_free(fetch_att);
	}
	if (fetch_type) {
		mailimap_fetch_type_free(fetch_type);
	}
	return -1;

cleanup2:
	mailimap_set_free(set);
	if (mbox_resync_flags & MBOX_NEED_FETCH_ALL) {
		mailimap_header_list_free(imap_hdrlist);
	}
	if (fetch_att) {
		mailimap_fetch_att_free(fetch_att);
	}
	if (fetch_type) {
		mailimap_fetch_type_free(fetch_type);
	}
	return -1;
}

int client_fetch(struct client *client, struct message *msg, struct message_data *restrict mdata)
{
	int res;
	struct mailimap_set *set;
	struct mailimap_fetch_type *fetch_type;
	struct mailimap_fetch_att *fetch_att;
	clist *fetch_result = NULL;
	clistiter *cur;
	struct mailimap_section *section;
	struct mailimap_msg_att *msg_att;

	set = mailimap_set_new_single(msg->uid);
	fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
	section = mailimap_section_new(NULL);
#ifdef AUTO_MARK_SEEN
	fetch_att = mailimap_fetch_att_new_body_section(section);
#else
	fetch_att = mailimap_fetch_att_new_body_peek_section(section);
#endif
	mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

	/* Fetch by UID */
	res = mailimap_uid_fetch(client->imap, set, fetch_type, &fetch_result);
	if (MAILIMAP_ERROR(res)) {
		client_warning("FETCH failed: %s", maildriver_strerror(res));
		goto cleanup;
	}

	/* There's only one message, no need to have a for loop: */
	cur = clist_begin(fetch_result);
	msg_att = clist_content(cur);
	if (!msg_att) {
		goto cleanup;
	}
	for (cur = clist_begin(msg_att->att_list); cur ; cur = clist_next(cur)) {
		struct mailimap_msg_att_item *item = clist_content(cur);
		if (item->att_type == MAILIMAP_MSG_ATT_ITEM_STATIC) {
			switch (item->att_data.att_static->att_type) {
				case MAILIMAP_MSG_ATT_BODY_SECTION:
					mdata->msg_size = item->att_data.att_static->att_data.att_body_section->sec_length;
					mdata->msg_body = malloc(mdata->msg_size + 1);
					if (!mdata->msg_body) {
						goto cleanup;
					}
					memcpy(mdata->msg_body, item->att_data.att_static->att_data.att_body_section->sec_body_part, mdata->msg_size);
					mdata->msg_body[mdata->msg_size] = '\0'; /* If it wasn't null terminated to begin with, it is now */
					break;
				case MAILIMAP_MSG_ATT_UID:
					/* Already have this */
					/* Fall through */
				default:
					/* In case the server sends more than what we asked for, don't throw any warning about unexpected responses */
					break;
			}
		}
	}

	mailimap_set_free(set);
	mailimap_fetch_type_free(fetch_type);
	mailimap_fetch_list_free(fetch_result);

	if (!mdata->msg_body) {
		return -1;
	}

	return 0;

cleanup:
	mailimap_set_free(set);
	mailimap_fetch_type_free(fetch_type);
	if (fetch_result) {
		mailimap_fetch_list_free(fetch_result);
	}
	return -1;
}

static void fetch_mime_recurse_single(const char **body, size_t *len, struct mailmime_data *data)
{
	switch (data->dt_type) {
		case MAILMIME_DATA_TEXT:
			*body = data->dt_data.dt_text.dt_data;
			*len = data->dt_data.dt_text.dt_length;
			break;
		case MAILMIME_DATA_FILE:
			break;
	}
}

static void append_recipients(char **restrict s, struct mailimf_address_list *addr_list)
{
	clistiter *cur;
	int len;

	for (cur = clist_begin(addr_list->ad_list); cur; cur = clist_next(cur)) {
		struct mailimf_mailbox *mb;
		char addrbuf[256];
		char *decoded;
		const char *name;
		struct mailimf_address *addr = clist_content(cur);
		switch (addr->ad_type) {
			case MAILIMF_ADDRESS_GROUP:
				break;
			case MAILIMF_ADDRESS_MAILBOX:
				mb = addr->ad_data.ad_mailbox;
				decoded = mb->mb_display_name ? mime_header_decode(mb->mb_display_name) : NULL;
				name = decoded ? decoded : mb->mb_display_name;
				len = snprintf(addrbuf, sizeof(addrbuf), "%s%s%s<%s>", *s ? ", " : "", name ? name : "", !strlen_zero(name) ? " " : "", mb->mb_addr_spec);
				if (len < (int) sizeof(addrbuf)) {
					APPEND_STR(*s, addrbuf, len);
				} /* else, truncation occured */
				free_if(decoded);
				break;
		}
	}
}

static void append_messageid(char **restrict s, clist *list)
{
	clistiter *cur;

	if (!list) {
		return;
	}

	for (cur = clist_begin(list); cur; cur = clist_next(cur)) {
		char buf[512];
		int len;
		char *addr = clist_content(cur);
		if (!addr) {
			continue;
		}
		len = snprintf(buf, sizeof(buf), "%s%s", *s ? ", " : "", addr);
		if (len < (int) sizeof(buf)) {
			APPEND_STR(*s, buf, len);
		} /* else, truncation occured */
	}
}

static void link_attachment(struct message_data *mdata, struct attachment *attachment)
{
	if (!mdata->attachments) {
		mdata->attachments = attachment;
		insque(mdata->attachments, NULL);
	} else {
		struct attachment *last = mdata->attachments;
		while (last->next) {
			last = last->next;
		}
		/* Add to linked list, insert at end */
		insque(attachment, last);
	}
	mdata->num_attachments++;
}

static void cleanup_attachments(struct message_data *restrict mdata)
{
	struct attachment *first = mdata->attachments;
	while (first) {
		struct attachment *cur = first;
		first = cur->next;
		remque(cur);
		free(cur);
	}
	mdata->attachments = NULL;
	mdata->num_attachments = 0;
}

static int fetch_mime_recurse(struct message_data *mdata, struct mailmime *mime, int level, int *bodyencoding, const char **body, size_t *len, int parse_headers, int html)
{
	struct mailmime_fields *fields;
	struct mailmime_content *content_type;
	int text_plain = 0, text_html = 0;
	int is_attachment = 0;
	int encoding;
	clistiter *cur;
	clist *parameters;

	level++;

#ifdef DEBUG_MODE
	switch (mime->mm_type) {
		case MAILMIME_SINGLE:
			client_debug(3, "Single part");
			break;
		case MAILMIME_MULTIPLE:
			client_debug(3, "Multipart");
			break;
		case MAILMIME_MESSAGE:
			client_debug(3, "Message");
			break;
	}
#endif

	fields = mime->mm_mime_fields;

	/* https://sourceforge.net/p/libetpan/mailman/libetpan-users/thread/etPan.442f9a32.136d1751.1f41%40utopia/
	 * To get the HTML body from MIME structure:
	 * - display multipart/mixed in the given order
	 * - display multipart/parallel in any order
	 * - display one sub-part of the multipart/alternative (for example, if there is an HTML part, display it)
	 */

	content_type = mime->mm_content_type;
	/* We care about the encoding, mainly for quoted-printable Content-Transfer-Encoding.
	 * format=flowed is in the Content-Type, and we don't deal with that here, the frontend does. */
	encoding = fields ? mailmime_transfer_encoding_get(fields) : MAILMIME_MECHANISM_8BIT;
	parameters = content_type->ct_parameters;
	switch (content_type->ct_type->tp_type) {
		case MAILMIME_TYPE_DISCRETE_TYPE:
#ifdef DEBUG_MODE
			switch (content_type->ct_type->tp_data.tp_discrete_type->dt_type) {
				case MAILMIME_DISCRETE_TYPE_TEXT:
					client_debug(7, "[%d] text/%s", level, content_type->ct_subtype);
					break;
				case MAILMIME_DISCRETE_TYPE_IMAGE:
					client_debug(7, "[%d] image/%s", level, content_type->ct_subtype);
					break;
				case MAILMIME_DISCRETE_TYPE_AUDIO:
					client_debug(7, "[%d] audio/%s", level, content_type->ct_subtype);
					break;
				case MAILMIME_DISCRETE_TYPE_VIDEO:
					client_debug(7, "[%d] video/%s", level, content_type->ct_subtype);
					break;
				case MAILMIME_DISCRETE_TYPE_APPLICATION:
					client_debug(7, "[%d] application/%s", level, content_type->ct_subtype);
					break;
				case MAILMIME_DISCRETE_TYPE_EXTENSION:
					client_debug(7, "[%d] %s/%s", level, content_type->ct_type->tp_data.tp_discrete_type->dt_extension, content_type->ct_subtype);
					break;
			}
#endif
			switch (content_type->ct_type->tp_data.tp_discrete_type->dt_type) {
				case MAILMIME_DISCRETE_TYPE_TEXT:
					if (!strcasecmp(content_type->ct_subtype, "plain")) {
						text_plain = 1;
					} else if (!strcasecmp(content_type->ct_subtype, "html")) {
						text_html = 1;
					}
					break;
				case MAILMIME_DISCRETE_TYPE_APPLICATION:
					if (!strcmp(content_type->ct_subtype, "octet-stream")) {
						is_attachment = 1;
					}
					break;
				default:
					break;
			}
			break;
		case MAILMIME_TYPE_COMPOSITE_TYPE:
#ifdef DEBUG_MODE
			switch (content_type->ct_type->tp_data.tp_composite_type->ct_type) {
				case MAILMIME_COMPOSITE_TYPE_MESSAGE:
					client_debug(7, "[%d] message/%s", level, content_type->ct_subtype);
					break;
				case MAILMIME_COMPOSITE_TYPE_MULTIPART:
					client_debug(7, "[%d] multipart/%s", level, content_type->ct_subtype);
					if (!strcasecmp(content_type->ct_subtype, "alternative")) {
						text_html = 1;
					}
					break;
				case MAILMIME_COMPOSITE_TYPE_EXTENSION:
					client_debug(7, "[%d] %s/%s", level, content_type->ct_type->tp_data.tp_composite_type->ct_token, content_type->ct_subtype);
					break;
			}
#endif
			switch (content_type->ct_type->tp_data.tp_composite_type->ct_type) {
				case MAILMIME_COMPOSITE_TYPE_MULTIPART:
					if (!strcasecmp(content_type->ct_subtype, "alternative")) {
						text_html = 1;
					}
					break;
				default:
					break;
			}
	}

	for (cur = clist_begin(parameters); cur; cur = clist_next(cur)) {
		struct mailmime_parameter *param = clist_content(cur);
		client_debug(7, ";%s=%s", param->pa_name, param->pa_value);
		if (text_plain && !strcmp(param->pa_name, "format")) {
			if (!strcmp(param->pa_value, "flowed")) {
				mdata->pt_flowed = 1;
			}
		} else if (!strcmp(param->pa_name, "name")) {
			is_attachment = 1;
			/* If it's an attachment, add the name (and size) to the list */
			if (1) {
				const char *body2;
				struct attachment *attachment = calloc(1, sizeof(struct attachment) + strlen(param->pa_value) + 1);
				if (attachment) {
					strcpy(attachment->data, param->pa_value); /* Safe */
					attachment->name = attachment->data;
					if (mime->mm_type == MAILMIME_SINGLE) {
						/* Get the size of the attachment by reusing fetch_mime_recurse_single for that purpose. */
						fetch_mime_recurse_single(&body2, &attachment->size, mime->mm_data.mm_single);
					}
					link_attachment(mdata, attachment);
				}
			}
		}
	}

	switch (mime->mm_type) {
		case MAILMIME_SINGLE:
			/* The goal here is to not show attachments in an email,
			 * e.g.:
			 * - message/rfc822
			 * |- multipart/mixed
			 *   |- text/plain (body)
			 *   |- text/plain (attachment)
			 *
			 * We can't just stop when we find the message body,
			 * because we also need to process attachments to list them.
			 * But we need to be aware that anything after the body must be an attachment, not the body. */
			if (!is_attachment) { /* Haven't yet found the message body */
				if (html && text_html) {
					fetch_mime_recurse_single(body, len, mime->mm_data.mm_single);
					if (body && len) {
						client_debug(7, "Using text/html part");
					}
					*bodyencoding = encoding;
				} else if (!*bodyencoding && text_plain) {
					fetch_mime_recurse_single(body, len, mime->mm_data.mm_single);
					if (body && len) {
						client_debug(7, "Using text/plain part");
					}
					*bodyencoding = encoding;
				}
			}
			break;
		case MAILMIME_MULTIPLE:
			for (cur = clist_begin(mime->mm_data.mm_multipart.mm_mp_list); cur; cur = clist_next(cur)) {
				fetch_mime_recurse(mdata, clist_content(cur), level, bodyencoding, body, len, parse_headers, html);
			}
			break;
		case MAILMIME_MESSAGE:
			/* A message could have multiple Subject, etc. headers if it contains an RFC 822 message
			 * as an attachment, e.g. a non-delivery report. In that case, the first one we encounter
			 * is the real one, and everything else afterwards should be ignored. */
			if (mime->mm_data.mm_message.mm_fields) {
				/* Use the MIME decoded headers to both handle decoding and so we don't have to parse headers ourselves */
				if (parse_headers && clist_begin(mime->mm_data.mm_message.mm_fields->fld_list)) {
					struct mailimf_fields *mffields = mime->mm_data.mm_message.mm_fields;
					for (cur = clist_begin(mffields->fld_list); cur; cur = clist_next(cur)) {
						struct mailimf_subject *subject;
						char *decoded;
						const char *name;
						struct mailimf_field *f = clist_content(cur);
						switch (f->fld_type) {
							case MAILIMF_FIELD_ORIG_DATE:
							case MAILIMF_FIELD_FROM:
								/* Already have these */
								break;
							case MAILIMF_FIELD_REPLY_TO:
								append_recipients(&mdata->replyto, f->fld_data.fld_reply_to->rt_addr_list);
								break;
							case MAILIMF_FIELD_TO:
								append_recipients(&mdata->to, f->fld_data.fld_to->to_addr_list);
								break;
							case MAILIMF_FIELD_CC:
								append_recipients(&mdata->cc, f->fld_data.fld_cc->cc_addr_list);
								break;
							case MAILIMF_FIELD_BCC: /* For parsing draft messages, mainly */
								append_recipients(&mdata->bcc, f->fld_data.fld_bcc->bcc_addr_list);
								break;
							case MAILIMF_FIELD_SUBJECT:
								subject = f->fld_data.fld_subject;
								decoded = subject ? mime_header_decode(subject->sbj_value) : NULL;
								name = decoded ? decoded : subject ? subject->sbj_value : NULL;
								REPLACE(mdata->subject, name);
								free_if(decoded);
								break;
							case MAILIMF_FIELD_MESSAGE_ID:
								REPLACE(mdata->messageid, f->fld_data.fld_message_id->mid_value);
								break;
							case MAILIMF_FIELD_IN_REPLY_TO:
								append_messageid(&mdata->inreplyto, f->fld_data.fld_in_reply_to->mid_list);
								break;
							case MAILIMF_FIELD_REFERENCES:
								append_messageid(&mdata->references, f->fld_data.fld_references->mid_list);
								break;
							default:
								/* Ignore others */
								break;
						}
					}
				}
				if (mime->mm_data.mm_message.mm_msg_mime) {
					fetch_mime_recurse(mdata, mime->mm_data.mm_message.mm_msg_mime, level, bodyencoding, body, len, parse_headers, html);
				}
			}
			break;
	}

	return 0;
}

static int quoted_printable_decode(char *restrict s, size_t *restrict len, int printonly)
{
	char *d = s;
	size_t index = 0;
	*len = 0;
	while (*s) {
		if (*s == '=') {
			unsigned int hex;
			s++;
			index++;
			if (!*s) {
				client_debug(1, "Invalid quoted-printable sequence (abruptly terminated)");
				return -1;
			}
			if (*s == '\r') {
				/* Soft line break (since we must wrap by pos 76) */
				s++;
				index++;
				if (*s != '\n') {
					client_debug(1, "Invalid quoted-printable sequence (CR not followed by LF)");
					return -1;
				}
			} else {
				char hexcode[3];
				hexcode[0] = *s;
				s++;
				index++;
				if (!*s) {
					client_debug(1, "Invalid quoted-printable sequence (abruptly terminated)");
					return -1;
				}
				hexcode[1] = *s;
				hexcode[2] = '\0';
				if (sscanf(hexcode, "%x", &hex) != 1) {
					client_debug(1, "Failed to decode %s", hexcode);
				}
				if (!printonly || isprint((char) hex)) { /* XXX isprint check only works for single-byte UTF-8 characters */
					*d++ = (char) hex;
					*len += 1;
				} else {
					/* Don't add invalid UTF-8 characters in the first place */
					client_debug(1, "Invalid quoted printable[%lu] %s -> %d (%c)", index, hexcode, hex, hex);
				}
			}
			s++;
			index++;
		} else {
			if (*s <= 32 && !isspace(*s)) {
				client_debug(1, "Illegal quoted-printable character: %d", *s);
				return -1;
			}
			*d++ = *s++;
			index++;
			*len += 1;
		}
	}
	*d = '\0';
	return 0;
}

int client_fetch_mime(struct message_data *restrict mdata, int parse_headers, int html)
{
	int res;
	size_t current_index = 0; /* This must be initialized */
	struct mailmime *mime;
	const char *body = NULL;
	size_t len = 0;
	int encoding = 0;

	/* If we already parsed the desired component, don't reparse it unnecessarily */
	if (!html && mdata->pt_body) {
		return 0;
	}
	if (html && mdata->html_body) {
		return 0;
	}

	res = mailmime_parse(mdata->msg_body, mdata->msg_size, &current_index, &mime);
	if (res != MAILIMF_NO_ERROR) {
		return -1;
	}

	fetch_mime_recurse(mdata, mime, 0, &encoding, &body, &len, parse_headers, html);
	client_debug(7, "FETCH result: want HTML=%d, bodylen=%lu", html, len);
	if (!body || !len) {
		client_debug(1, "Failed to determine a suitable body for message?");
		mailmime_free(mime);
		return -1;
	} else {
		size_t idx = 0;
		char *result, *decoded = NULL;
		size_t resultlen, qlen = 0;
		res = mailmime_part_parse(body, len, &idx, encoding, &result, &resultlen);
		if (MAILIMAP_ERROR(res)) {
			mailmime_free(mime);
			return -1;
		}
		/* 7-bit and 8-bit don't need any special handling.
		 * Quoted printable needs to be decoded appropriately (below).
		 * Base64 is (in practice) only used for attachments, not the actual message content.
		 * Similar for binary, if that's even used at all. */
		switch (encoding) {
		case MAILMIME_MECHANISM_QUOTED_PRINTABLE:
			decoded = strndup(body, len);
			if (decoded && !quoted_printable_decode(decoded, &qlen, 0)) { /* Need to operate on original body, mailmime_part_parse removes quoted printable stuff */
				client_debug(3, "Translated quoted-printable body of length %lu to body of length %lu", resultlen, qlen);
				if (html) {
					mdata->html_body = decoded;
					mdata->html_size = len;
				} else {
					mdata->pt_body = decoded;
					mdata->pt_size = len;
				}
			} else {
				client_debug(1, "Could not decode quoted printable body?");
				free_if(decoded);
				res = -1;
			}
			break;
		case MAILMIME_MECHANISM_7BIT:
		case MAILMIME_MECHANISM_8BIT:
			if (html) {
				mdata->html_body = malloc(resultlen + 1);
				if (mdata->html_body) {
					mdata->html_size = resultlen;
					memcpy(mdata->html_body, result, mdata->html_size);
					mdata->html_body[mdata->html_size] = '\0';
				}
			} else {
				mdata->pt_body = malloc(resultlen + 1);
				if (mdata->pt_body) {
					mdata->pt_size = resultlen;
					memcpy(mdata->pt_body, result, mdata->pt_size);
					mdata->pt_body[mdata->pt_size] = '\0';
				}
			}
			break;
		case MAILMIME_MECHANISM_BASE64:
		case MAILMIME_MECHANISM_BINARY:
			res = -1;
			break;
		}
		mailmime_decoded_part_free(result);
	}
	mailmime_free(mime);
	return res;
}

void client_cleanup_message(struct message_data *restrict mdata)
{
	cleanup_attachments(mdata);
	free_if(mdata->messageid);
	free_if(mdata->references);
	free_if(mdata->inreplyto);
	free_if(mdata->msg_body);
	free_if(mdata->pt_body);
	free_if(mdata->html_body);
	free_if(mdata->subject);
	free_if(mdata->to);
	free_if(mdata->cc);
	free_if(mdata->bcc);
	free_if(mdata->replyto);
	free_if(mdata->headersfmt);
}

static int client_flush_pending_output(struct client *client)
{
	const char *line;
	struct pollfd pfd;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = client->imapfd;
	pfd.events = POLLIN;

	do {
		pfd.revents = 0;
		if ((client->imap->imap_stream && client->imap->imap_stream->read_buffer_len) || poll(&pfd, 1, 50) > 0) {
			line = mailimap_read_line(client->imap);
			/* Read and discard */
			client_debug(1, "Flushing output '%s'", line);
			if (strlen_zero(line)) {
				/* Avoid infinite loop if we keep reading nothing */
				break;
			}
		} else {
			break;
		}
	} while (line);
	return 0;
}

int client_idle_start(struct client *client)
{
	if (!IMAP_HAS_CAPABILITY(client, IMAP_CAPABILITY_IDLE)) {
		return -1;
	}
	if (!client->sel_mbox) {
		client_error("Client IDLE without mailbox");
		return -1;
	}
	if (!client->idling) {
		int res;
		client_debug(2, "Starting IDLE...");
		assert(client->imap->imap_selection_info != NULL);

		/* Flush any pending input before sending the IDLE command,
		 * or lack of synchronization could be possible which will confuse libetpan.
		 * For example, if we issue a MOVE command, we'll get an untagged EXPUNGE,
		 * and if that hasn't been read, then that may still be in the buffer.
		 *
		 * XXX This will cause us to lose updates delivered in that small amount of time
		 * between when we stop idling and start idling again, which is not ideal.
		 * In the MOVE case, we already reflect the deletion on our end,
		 * so we also don't want to handle that twice. */
		if (client_flush_pending_output(client) == -1) {
			return MAILIMAP_ERROR_STREAM;
		}

		res = mailimap_idle(client->imap);
		if (res != MAILIMAP_NO_ERROR) {
			client_warning("Failed to start IDLE: %s", maildriver_strerror(res));
			return -1;
		}
		client->idlestart = time(NULL);
		client->idling = 1;
	}
	return 0;
}

int client_idle_stop(struct client *client)
{
	if (client->idling) {
		int res;
		client_debug(2, "Stopping IDLE...");
		res = mailimap_idle_done(client->imap);
		if (res != MAILIMAP_NO_ERROR) {
			client_warning("Failed to stop IDLE: %s", maildriver_strerror(res));
			return -1;
		}
		client->idling = 0;
	}
	return 0;
}

static struct mailbox *find_mailbox_by_name(struct client *client, const char *name)
{
	int i;
	for (i = 0; i < client->num_mailboxes; i++) {
		if (!strcmp(client->mailboxes[i].name, name)) {
			return &client->mailboxes[i];
		}
	}
	return NULL;
}

static char *quotesep(char **restrict str)
{
	char *ret, *s = *str;

	if (strlen_zero(s)) {
		return NULL;
	}

	if (*s != '"' && *s == ' ') {
		s++;
	}

	if (*s != '"') {
		return strsep(str, " "); /* If not in quotes, then just return the next word as usual */
	}
	if (!*(s + 1)) {
		client_debug(1, "Malformed string (quotes not terminated)");
		return NULL;
	}
	ret = s + 1;
	s = strchr(s + 1, '"');
	if (!s) {
		client_debug(1, "Unterminated quotes");
		return NULL;
	}

	*s++ = '\0';
	*str = s;
	return ret;
}

static void __resequence_messages(struct message *msg, int shift_indices)
{
	if (!msg || msg->seqno == 0) {
		/* If msg is the last message in a mailbox, and we pass msg->next in here,
		 * then we'll have wrapped around, and we don't actually need to do anything
		 * in that case. */
		return;
	}
	client_debug(1, "Resequencing messages starting at %u", msg->seqno);
	if (shift_indices) {
		do {
			msg->seqno--;
			msg->index--;
			msg = next_message(msg);
		} while (msg);
	} else {
		do {
			msg->seqno--;
			msg = next_message(msg);
		} while (msg);
	}
}

/* We only shift indices if we start at index 0 and shift all messages down */
#define resequence_messages_indices(msg) __resequence_messages(msg, 1)

void resequence_messages(struct message *msg)
{
	return __resequence_messages(msg, 0);
}

static int fetch_flag_to_enum(const char *f)
{
	if (!strcmp(f, "\\Recent")) {
		return IMAP_MESSAGE_FLAG_RECENT;
	} else if (!strcmp(f, "\\Answered")) {
		return IMAP_MESSAGE_FLAG_ANSWERED;
	} else if (!strcmp(f, "\\Flagged")) {
		return IMAP_MESSAGE_FLAG_FLAGGED;
	} else if (!strcmp(f, "\\Deleted")) {
		return IMAP_MESSAGE_FLAG_DELETED;
	} else if (!strcmp(f, "\\Seen")) {
		return IMAP_MESSAGE_FLAG_SEEN;
	} else if (!strcmp(f, "\\Draft")) {
		return IMAP_MESSAGE_FLAG_DRAFT;
	}
	/* Not a flag, must be a keyword */
	return 0;
}

static void process_idle_fetch(struct client *client, struct message *msg, char *tmp)
{
	char *f, *s;
	int oldflags;
	uint64_t oldkeywords;

	s = strstr(tmp, "FLAGS");
	if (!tmp) {
		return;
	}
	s += STRLEN("FLAGS");
	if (strlen_zero(s)) {
		return;
	}
	/* Strip parens around flags */
	if (!strncmp(s, " (", 2)) {
		char *end = strchr(s, ')');
		if (end) {
			*end = '\0';
		}
		s += 2;
		if (strlen_zero(s)) {
			return;
		}
	}

	/* Reset flags to start with */
	oldflags = msg->flags;
	oldkeywords = msg->keywords;
	msg->flags = 0;
	msg->keywords = 0;

	/* Process each flag */
	while ((f = strsep(&s, " "))) {
		int flag;
		if (strlen_zero(f)) {
			continue;
		}
		flag = fetch_flag_to_enum(f);
		if (flag) {
			/* Flag */
			msg->flags |= flag;
		} else {
			/* Keyword */
			message_add_keyword(client->sel_mbox, msg, f);
		}
	}

	/* Something must have changed with this message, or we wouldn't have gotten a FETCH... */
	if (oldflags == msg->flags && oldkeywords == msg->keywords) {
		client_debug(1, "Strange, none of the flags for message %d changed?", msg->uid);
	} else {
		client->refreshflags |= REFRESH_MESSAGE_PANE;
		/* If unread count has changed, folder pane needs to be updated. */
		if (oldflags & IMAP_MESSAGE_FLAG_SEEN) {
			if (!(msg->flags & IMAP_MESSAGE_FLAG_SEEN)) {
				/* Was previously read and is now unread.
				 * We need to use mark_message_unseen to update the folder stats, too,
				 * but this is not idempotent on messages (in fact, will ignore already seen),
				 * so set the \Seen bit so it will do its thing correctly. */
				msg->flags |= IMAP_MESSAGE_FLAG_SEEN;
				mark_message_unseen(client->sel_mbox, msg);
				client->refreshflags |= REFRESH_FOLDERS;
			}
		} else {
			if (msg->flags & IMAP_MESSAGE_FLAG_SEEN) {
				/* Was previously unread and is now read */
				msg->flags &= ~IMAP_MESSAGE_FLAG_SEEN;
				mark_message_seen(client->sel_mbox, msg);
				client->refreshflags |= REFRESH_FOLDERS;
			}
		}
	}
}

static int process_idle_line(struct client *client, char *restrict s, int *restrict mbox_resync_flags)
{
	char *tmp;
	uint32_t seqno;
	struct mailbox *mbox;

	/* Remove line ending */
	tmp = strchr(s, '\r');
	if (tmp) {
		*tmp = '\0';
	}
	tmp = strchr(s, '\n');
	if (tmp) {
		*tmp = '\0';
	}

	client_debug(5, "IDLE data: %s", s);

	if (strncmp(s, "* ", 2)) {
		/* Maybe it's a tagged response terminating the IDLE command? */
		const char *next = strchr(s, ' ');
		/* Skip the tag, assuming that's what it is */
		if (!next) {
			return -1;
		}
		next++;
		if (!*next) {
			return -1;
		}
		if (!strncmp(next, "NO ", 3) || !strncmp(next, "OK ", 3)) { /* Done this way instead of strsep to leave original message intact */
			next += 3;
			if (!strlen_zero(next)) {
				/* Maybe it's an [ALERT] or something like that.
				 * Should display to the user. */
				client_debug(2, "Interesting IDLE response... '%s'", next);
				client_status("%s", next);
				/* Resume idling */
				return 0;
			}
		}
		client_warning("Unexpected IDLE response (not untagged): %s", s);
		return -1;
	}
	tmp = s + 2;
	if (strlen_zero(tmp)) {
		client_warning("Partial IDLE response: %s", s);
		return -1;
	}

	/* Based on the IDLE response, in place update any changed mailboxes. */

	if (!strncmp(tmp, "OK Still here", STRLEN("OK Still here"))) {
		/* Ignore, continue idling */
		return 0;
	} else if (!strncmp(tmp, "STATUS", STRLEN("STATUS"))) {
		char *mbname;
		uint32_t oldtotal;
		tmp += STRLEN("STATUS");
		if (strlen_zero(tmp)) {
			client_warning("Incomplete STATUS response");
			return -1;
		}

		while (*tmp == ' ') {
			tmp++;
		}
		if (strlen_zero(tmp)) {
			return -1;
		}
		mbname = quotesep(&tmp); /* Get the mailbox name where the update occured. */

		if (!mbname) {
			return -1;
		}
		mbox = find_mailbox_by_name(client, mbname);
		if (!mbox) {
			client_warning("'%s' not a known mailbox", mbname);
			return -1;
		}
		/* Update our view of this mailbox with the new STATUS line */
		oldtotal = mbox->total;
		parse_status(client, mbox, tmp, 0);
		client->refreshflags |= REFRESH_FOLDERS; /* STATUS is only used for non-selected mailboxes, so no need to update message pane */
		if (mbox->total > oldtotal) {
			/* New messages appeared in some other folder. */
			client->refreshtypes |= IDLE_STATUS_EXISTS;
		}
	} else if (strstr(tmp, "UIDVALIDITY")) {
		tmp += STRLEN("UIDVALIDITY");
		while (*tmp == ' ') {
			tmp++;
		}
		client_warning("Mailbox UIDVALIDITY changed to %s?", tmp);
		/* Disconnect since this is a pretty serious thing. */
		return -1;
	} else if (strstr(tmp, "PERMANENTFLAGS")) {
		tmp += STRLEN("PERMANENTFLAGS");
		while (*tmp == ' ') {
			tmp++;
		}
		/* Mailbox has a new keyword, add it */
		if (!strlen_zero(tmp)) {
			mailbox_add_keyword(client->sel_mbox, tmp);
		}
	} else {
		struct message *msg;

		seqno = atoi(tmp); /* It'll stop where it needs to */
		tmp = strchr(tmp, ' '); /* Skip the sequence number */
		if (!strlen_zero(tmp)) {
			tmp++;
		}
		if (strlen_zero(tmp)) {
			client_warning("Invalid IDLE data: %s", s);
			return -1;
		}

		/* What we do next depends on what the untagged response is */
		if (!strncmp(tmp, "EXISTS", STRLEN("EXISTS"))) {
			client->sel_mbox->total = seqno; /* Update number of messages in this mailbox. Could increment by 1, but just set it to EXISTS, should be more accurate. */
			client->sel_mbox->uidnext++;
			client->refreshtypes |= IDLE_EXISTS;
			client->refreshflags |= REFRESH_FOLDERS;
			if (MSG_SEQNO_IN_MENU_RANGE(client, seqno) || seqno == client->end_seqno + 1) {
				client->refreshflags |= REFRESH_MESSAGE_PANE;
				msg = new_message(client, num_messages(client), seqno);
				if (!msg) {
					return -1;
				}
				/* Add the message, but don't actually FETCH the data to populate
				 * the message structure until after we finish processing IDLE lines,
				 * in handle_idle.
				 *
				 * Once we FETCH, we will also know if it's seen or not, so we can
				 * update the mailbox stats appropriately, without doing a STATUS. */
				msg->fetchflags |= MSG_FETCH_ALL;
				*mbox_resync_flags |= MBOX_NEED_FETCH_ALL;
				if (seqno == client->end_seqno + 1) {
					client->end_seqno++;
				}
				/*! \todo if NOTIFY will automatically gives us, then we don't need to set these */
			} else {
				/* New message that's out of range.
				 * However, we still need to fetch certain message properties to recompute
				 * the mailbox stats properly, e.g. UNSEEN, SIZE.
				 *
				 * However, (even though IMAP clients are not supposed to do this), it may
				 * be more efficient just to issue a single STATUS command. */
				*mbox_resync_flags |= MBOX_NEED_STATUS;
			}
		} else if (!strncmp(tmp, "RECENT", STRLEN("RECENT"))) {
			/* RECENT is basically always accompanied by EXISTS,
			 * but update the refresh flags just in case. */
			client->sel_mbox->recent++;
			client->refreshflags |= REFRESH_FOLDERS;
			client->refreshtypes |= IDLE_RECENT;
			client->sel_mbox->flags |= IMAP_MAILBOX_MARKED; /* Mark the mailbox as marked, since it has recent messages */
		} else if (!strncmp(tmp, "EXPUNGE", STRLEN("EXPUNGE"))) {
			if (client->sel_mbox->total) {
				client->refreshtypes |= IDLE_EXPUNGE;
				if (MSG_SEQNO_IN_MENU_RANGE(client, seqno)) {
					struct message *next;
					client->refreshflags |= REFRESH_MESSAGE_PANE;
					/* We need to purge this message immediately,
					 * since we need to resequence messages so that we can successfully
					 * process future EXPUNGEs. */
					msg = get_msg_by_seqno(client, seqno);
					next = msg->next;
					client_debug(3, "Expunging message %u", msg->seqno);
					delete_message(client, msg);
					resequence_messages_indices(next); /* Renumber all higher sequenced numbers */
				} else {
					/* Messages not even in the current menu disappeared.
					 *
					 * A proper offline IMAP client would be able to subtract the correct number
					 * of messages, since it would know how many messages had the \\Deleted flag set.
					 * However, we don't necessarily know the flags of all the messages, since we only
					 * load a subset into memory at any given time.
					 *
					 * The only way to know what the current mailbox status is now
					 * is to issue a STATUS. */
					*mbox_resync_flags |= MBOX_NEED_STATUS;
					if (seqno < client->start_seqno) {
						/* We still need to decrement all our sequence numbers,
						 * even though the expunged message isn't visible. */
						resequence_messages(get_msg(client, 0));
					}
				}
			} else {
				client_warning("EXPUNGE on empty mailbox?");
				return -1;
			}
		} else if (!strncmp(tmp, "FETCH", STRLEN("FETCH"))) {
			/* This is most likely an update in flags.
			 * If the message in question is loaded in the current message pane menu, refresh
			 * (Just visible isn't sufficient, since the user might scroll to the message later.)
			 * Otherwise, ignore it, since we can't get to the message without rebuilding the menu. */
			if (MSG_SEQNO_IN_MENU_RANGE(client, seqno)) {
				msg = get_msg_by_seqno(client, seqno);
#ifdef FORCE_REFETCH_FLAGS
				msg->fetchflags |= MSG_FETCH_FLAGS; /* Existing message, but we need to update its flags */
				*mbox_resync_flags |= MBOX_NEED_FETCH_FLAGS;
				client->refreshflags |= REFRESH_MESSAGE_PANE;
				if (strstr(tmp, "\\Seen")) {
					client->refreshflags |= REFRESH_FOLDERS; /* Update folder counts */
				}
#else
				/* We can get the new flags for this message from the IDLE data itself.
				 * No need to issue a FETCH for the flags afterwards. */
				process_idle_fetch(client, msg, tmp);
#endif
			} else {
				/* If it's not visible, we do care if the \\Seen flag changed, so we can update
				 * the mailbox stats as appropriate.
				 * As well, we don't need to set MBOX_NEED_STATUS, since the update itself contains the flags. */
				if (seqno == client->end_seqno + 1) {
					/*! \todo BUGBUG FIXME Somehow missed the untagged EXISTS for this message?
					 * Observed happening when we reply to a message to ourself and
					 * miss the EXISTS because we've briefly stopped IDLE to store the
					 * \Answered flag on the message to which we replied
					 * (so it can be reproduced in this manner).
					 *
					 * Needs more investigation, but this might be a bug in libetpan,
					 * if it's flushing pending output when sending a command,
					 * or more likely, when it tries to read the response to the STORE
					 * command that gets sent, which is when it'll see the untagged EXISTS,
					 * but since we're not idling, *WE* don't get a callback to that,
					 * the library just silently ignores it.
					 *
					 * Once way to work around this would be set up a logging callback
					 * so that we always get a callback on data received from the server,
					 * specifically for untagged responses sent NOT during IDLE,
					 * (which the IMAP RFC allows either before or after the server processes
					 *  a command, forget which.)
					 *
					 * If this happens, just treat it like an EXISTS for now,
					 * until this bug is fixed. The below code is just copy/pasted from the EXISTS case. */
					client_debug(1, "WARNING: Missed an untagged EXISTS for message with seqno %u?", seqno);
					client->sel_mbox->total = seqno; /* Update number of messages in this mailbox */
					client->sel_mbox->uidnext++;
					client->refreshtypes |= IDLE_EXISTS;
					client->refreshflags |= REFRESH_FOLDERS;
					client->refreshflags |= REFRESH_MESSAGE_PANE;
					msg = new_message(client, num_messages(client), seqno);
					if (!msg) {
						return -1;
					}
					msg->fetchflags |= MSG_FETCH_ALL;
					*mbox_resync_flags |= MBOX_NEED_FETCH_ALL;
					if (seqno == client->end_seqno + 1) {
						client->end_seqno++;
					}
				} else {
					/* We don't know what the flags were on messages that aren't in memory,
					 * so we need to do a STATUS. */
					*mbox_resync_flags |= MBOX_NEED_STATUS;
				}
			}
		} else {
			client_debug(3, "Ignoring IDLE data: %s", tmp);
		}
	}
	return 0;
}

static int process_idle_updates(struct client *client, int mbox_resync_flags)
{
	/* Now that we know what happened during IDLE, go ahead and actually update our state. */

	if (mbox_resync_flags & MBOX_NEED_FETCH) {
		if (client_idle_stop(client) || client_fetch_postidle(client, mbox_resync_flags)) {
			return -1;
		}
	}

	/* Do STATUS last, since for EXISTS/EXPUNGE, we already manually updated mailbox stats
	 * (at least partially, if the messages were within the current window range),
	 * and since STATUS will give us the correct stats for sure, we may as well stick with this on the way out. */
	if (mbox_resync_flags & MBOX_NEED_STATUS) {
		if (client_idle_stop(client) || client_status_command(client, client->sel_mbox, NULL)) {
			return -1;
		}
	}

	return 0;
}

int process_idle(struct client *client)
{
	struct pollfd pfd;
	char *idledata;
	int res = 0;
	int empty = 0;
	int mbox_resync_flags = 0;

	if (!client->idling) {
		client_warning("IMAP server activity while not idle");
		return -1;
	}

	/* IDLE activity! */
	idledata = mailimap_read_line(client->imap);
	if (!idledata) {
		/* Check if the remote IMAP server may have disconnected us */
		client_warning("IDLE activity, but no data?");
		if (client_idle_stop(client) || client_idle_start(client)) {
			return -1;
		}
		return 0;
	}

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = client->imapfd;
	pfd.events = POLLIN;

	do {
		if (strlen_zero(idledata)) {
			client_warning("Empty IDLE response");
			if (empty++) {
				return client_idle_stop(client); /* Stop idling so we can restart, to detect failure properly */
			}
		} else {
			res |= process_idle_line(client, idledata, &mbox_resync_flags); /* Process a single line of data received during an IDLE */
		}
		/* mailimap_read_line will block, so we need to ensure that we break if there's no more data to read.
		 * We can't use poll, because multiple lines may be in the internal buffer already.
		 * Timeouts don't help either, since libetpan doesn't use them for this call.
		 * Checking the stream buffer length works, but if we're too quick, we might not have read it all yet,
		 * which is why we also need to poll for a little bit, in case there are other untagged messages on the way.
		 * Would be nice if there was something like mailimap_lines_available(), but there isn't...
		 */
		if ((client->imap->imap_stream && client->imap->imap_stream->read_buffer_len) || poll(&pfd, 1, 100) > 0) {
			idledata = mailimap_read_line(client->imap);
		} else {
			break;
		}
	} while (idledata && !res);

	if (res) {
		if (client_idle_stop(client)) {
			client_error("Failed to stop IDLE");
			return -1;
		}
		return 0;
	}

	return process_idle_updates(client, mbox_resync_flags);
}

static int __handle_store(struct client *client, int sign, struct mailimap_set *set, struct mailimap_flag_list *flag_list)
{
	int res;
	struct mailimap_store_att_flags *att_flags;

	assert(!client->idling);

	if (sign > 0) {
		att_flags = mailimap_store_att_flags_new_add_flags_silent(flag_list);
	} else {
		att_flags = mailimap_store_att_flags_new_remove_flags_silent(flag_list);
	}
	if (!att_flags) {
		goto cleanup;
	}

	res = mailimap_uid_store(client->imap, set, att_flags);
	if (res != MAILIMAP_NO_ERROR) {
		client_error("UID STORE failed: %s", maildriver_strerror(res));
	}
	/* Regardless of whether it failed or not, we're done */
	mailimap_store_att_flags_free(att_flags);
	mailimap_set_free(set);
	return 0;

cleanup:
	mailimap_flag_list_free(flag_list);
	mailimap_set_free(set);
	return -1;
}

int client_store(struct client *client, int sign, struct message *msg, int flags)
{
	int res = 0;
	struct mailimap_flag_list *flag_list;
	struct mailimap_set *set;

	assert(!client->idling);

	if (msg) {
		set = mailimap_set_new_single(msg->uid);
	} else {
		set = mailimap_set_new_interval(1, 0); /* fetch in interval 1:* */
	}
	if (!set) {
		return -1;
	}

	if (!flags) {
		client_warning("Called with no flags?");
		return -1;
	}

	flag_list = mailimap_flag_list_new_empty();
	if (flags & IMAP_MESSAGE_FLAG_SEEN) {
		res |= mailimap_flag_list_add(flag_list, mailimap_flag_new_seen());
	}
	if (flags & IMAP_MESSAGE_FLAG_DELETED) {
		res |= mailimap_flag_list_add(flag_list, mailimap_flag_new_deleted());
	}
	if (flags & IMAP_MESSAGE_FLAG_FLAGGED) {
		res |= mailimap_flag_list_add(flag_list, mailimap_flag_new_flagged());
	}
	if (flags & IMAP_MESSAGE_FLAG_ANSWERED) {
		res |= mailimap_flag_list_add(flag_list, mailimap_flag_new_answered());
	}
	if (res != MAILIMAP_NO_ERROR) {
		client_warning("LIST add failed: %s", maildriver_strerror(res));
		mailimap_flag_list_free(flag_list);
		mailimap_set_free(set);
		return -1;
	}

	return __handle_store(client, sign, set, flag_list);
}

int client_store_keyword(struct client *client, int sign, struct message *msg, const char *keyword)
{
	int res = 0;
	struct mailimap_flag_list *flag_list;
	struct mailimap_set *set;
	char *keyword_dup = NULL;
	struct mailimap_flag *flag;

	assert(!client->idling);

	if (msg) {
		set = mailimap_set_new_single(msg->uid);
	} else {
		set = mailimap_set_new_interval(1, 0); /* fetch in interval 1:* */
	}
	if (!set) {
		return -1;
	}

	if (!keyword) {
		client_warning("Called with no keyword?");
		return -1;
	}

	flag_list = mailimap_flag_list_new_empty();
	keyword_dup = strdup(keyword);
	if (!keyword_dup) {
		mailimap_flag_list_free(flag_list);
		mailimap_set_free(set);
		return -1;
	}

	flag = mailimap_flag_new_flag_keyword(keyword_dup);
	res |= mailimap_flag_list_add(flag_list, flag);

	if (res != MAILIMAP_NO_ERROR) {
		client_warning("LIST add failed: %s", maildriver_strerror(res));
		mailimap_flag_list_free(flag_list);
		mailimap_set_free(set);
		return -1;
	}
	return __handle_store(client, sign, set, flag_list);
}

int client_copy(struct client *client, struct message *msg, const char *newmbox)
{
	int res;
	struct mailimap_set *set;

	assert(!client->idling);

	client_debug(3, "=> COPY %u %s\n", msg->uid, newmbox);
	set = mailimap_set_new_single(msg->uid);
	if (!set) {
		return -1;
	}

	res = mailimap_uid_copy(client->imap, set, newmbox);
	if (res != MAILIMAP_NO_ERROR) {
		client_warning("UID COPY failed: %s", maildriver_strerror(res));
		return -1;
	}
	mailimap_set_free(set);
	return 0;
}

int client_move(struct client *client, struct message *msg, const char *newmbox)
{
	int res;
	struct mailimap_set *set;

	assert(!client->idling);

	client_debug(3, "=> MOVE %u %s", msg->uid, newmbox);
	set = mailimap_set_new_single(msg->uid);
	if (!set) {
		return -1;
	}

	if (client->capabilities & IMAP_CAPABILITY_MOVE) {
		res = mailimap_uid_move(client->imap, set, newmbox);
		if (res != MAILIMAP_NO_ERROR) {
			client_warning("UID MOVE failed: %s", maildriver_strerror(res));
		}
	} else {
		/* You're kidding me... right?
		 * Simulate MOVE using COPY + STORE \\Deleted */
		res = mailimap_uid_copy(client->imap, set, newmbox);
		if (res != MAILIMAP_NO_ERROR) {
			client_warning("UID COPY failed: %s", maildriver_strerror(res));
		} else {
			client_store_deleted(client, msg);
			/* XXX Should we do an EXPUNGE automatically? It could be dangerous! */
		}
	}
	mailimap_set_free(set);
	return res;
}

int client_expunge(struct client *client)
{
	assert(!client->idling);
	return mailimap_expunge(client->imap);
}

int client_append(struct client *client, const char *mailbox, int flags, const char *msg, size_t len)
{
	int res;
	struct mailimap_flag_list *flag_list;

	assert(!client->idling);

	/* Automark anything we upload as \Seen */
	flag_list = mailimap_flag_list_new_empty();
	if (flags & IMAP_MESSAGE_FLAG_SEEN) {
		mailimap_flag_list_add(flag_list, mailimap_flag_new_seen());
	}
	if (flags & IMAP_MESSAGE_FLAG_DRAFT) {
		mailimap_flag_list_add(flag_list, mailimap_flag_new_draft());
	}

	res = mailimap_append(client->imap, mailbox, flag_list, NULL, msg, len);
	mailimap_flag_list_free(flag_list);
	if (res != MAILIMAP_NO_ERROR) {
		client_warning("APPEND failed: %s", maildriver_strerror(res));
		return -1;
	} else {
		/*! \todo If not doing NOTIFY, manually increment size/unread/total count of mailbox as appropriate */
	}
	return 0;
}
