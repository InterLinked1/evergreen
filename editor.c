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
 * \brief Message editor
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "evergreen.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <form.h>

/* Initially, a double line break was used to indicate
 * a hard line break, but it's usually better to try
 * to heuristically determine this. Define this
 * to restore the old behavior.
 *
 * Pros of defining HARD_LINE_BREAK_REQUIRES_DOUBLE:
 * - Definitive algorithm for parsing line breaks, as opposed to heuristics
 *
 * Cons:
 * - It looks weird, not intuitive for users at all
 * - Hard line breaks need to be inserted into messages we reply to. There is currently incomplete logic for handling --- Forwarded Message --- headers, etc.
 */

/* #define HARD_LINE_BREAK_REQUIRES_DOUBLE */

/* ncurses internally for REQ_END_LINE uses After_End_Of_Data to search for the last non blank character on a line,
 * so no, there is nothing internal we can use to get at that, apart from computing it. */

static inline const char *get_current_text(FORM *form)
{
	const char *s;
	FIELD *field = current_field(form);
	form_driver(form, REQ_VALIDATION); /* flush buffer */
	s = field_buffer(field, 0) + (field->dcols * form->currow) + form->curcol;
	return s;
}

static inline int nonspace_after_in_line(FORM *form)
{
	int curcol = form->curcol;
	const char *c = get_current_text(form);
	while (*c) {
		if (*c != ' ') {
			return 1;
		}
		c++;
		if (++curcol == COLS) {
			break;
		}
	}
	return 0;
}

static inline int nonspace_after_in_field(FORM *form)
{
	const char *c = get_current_text(form);
	while (*c) {
		if (*c != ' ') {
			return 1;
		}
		c++;
	}
	return 0;
}

#ifndef HARD_LINE_BREAK_REQUIRES_DOUBLE
static inline int next_word_count(const char *c)
{
	int quoted = 0;
	int length = 0;

	if (*c == '>') {
		quoted = 1;
	}
	while (*c) {
		if (length >= COLS) {
			return length; /* ??? */
		}
		if (*c == ' ') {
			if (!quoted) {
				return length;
			}
			/* Tolerate just one space in this case: >> Something... */
			quoted = 0;
		} else {
			length++;
		}
		c++;
	}
	return length;
}
#endif

#define END_OF_LINE() (!nonspace_after_in_line(form))
#define END_OF_FIELD() (!nonspace_after_in_field(form))

#define FORMAT_FLOWED_WRAP_COL 72

static size_t get_field_length(FIELD *field, int cols, int trailing_crlf)
{
	int output_col = 0;
	int col = 0;
	int row = 0;
	size_t len = 0;
	int blank_lines = 0;
	int consec_spaces = 0;
	int in_quotes = 0, quote_depth = 0;
	int last_flowed = 0;
	const char *sp_start = NULL;
	const char *src = field_buffer(field, 0);

	assert(cols > 0);

	/* Compute the non-trivial field length.
	 * ncurses will allocate entire lines at a time, that are by default filled with spaces (see field_buffer(3))
	 * and these don't count.
	 *
	 * The algorithm here is based on copy_trimmed_str, just to calculate length instead of copy the characters. */

	/* Skip leading whitespace */
	while (*src == ' ') {
		src++;
	}
	while (*src) {
		if (col == 0) {
			if (consec_spaces > cols) {
				blank_lines++;
				consec_spaces = 0;
				sp_start = NULL;
			}
#ifndef HARD_LINE_BREAK_REQUIRES_DOUBLE
			if (consec_spaces > 0 && next_word_count(src) < consec_spaces - 7) {
				blank_lines++;
				consec_spaces = 0;
				sp_start = NULL;
			}
#endif
			in_quotes = *src == '>';
			quote_depth = in_quotes ? 1 : 0;
			if (last_flowed) {
				len++;
			}
			last_flowed = 0;
#if 0
		} else if (output_col == 1) {
			/* As below, assume that we'll have to space stuff, since we don't know what was last */
			len++;
			output_col++;
#endif
		} else if (output_col >= FORMAT_FLOWED_WRAP_COL) {
			len += 2; /* Just assume that we'd wrap. This is the only calculation that's not precise, since we don't keep track of dst when calculating length. */
			output_col = 0;
			len += quote_depth + 1; /* Assume we need to add quotes */
			last_flowed = 1;
		}
		if (*src == ' ') {
			if (!consec_spaces++) {
				sp_start = src;
			}
		} else {
			if (in_quotes) {
				if (*src == '>') {
					quote_depth++;
				} else {
					in_quotes = 0;
				}
			}
			if (!blank_lines && !col && row > 0) {
				if (*src == '>') {
					len += 2;
					output_col = 0;
					consec_spaces = 0; /* Let the normal logic handle this case */
				} else {
					len++;
					output_col++;
				}
			}
			len += blank_lines * 2;
			if (blank_lines) {
				output_col = 0;
				blank_lines = 0;
			}
			if (consec_spaces) {
				int diff = src - sp_start;
				if (col > 0) {
					len += diff + 1;
					output_col += diff + 1;
				} else {
					len++;
					output_col++;
				}
			} else {
				len++;
				output_col++;
			}
			consec_spaces = 0;
		}
		src++;
		if (++col == cols) {
			col = 0;
			row++;
		}
	}
	if (trailing_crlf) {
		len += 2; /* Add trailing CR LF to ensure message is well terminated */
	}
	return len;
}

static const char *field_names[] = {
	"From",
	"To",
	"Cc",
	"Bcc",
	"Reply-To",
	"Subject", /* This should be last, since the rest are all address related */
};
#define NUM_FIELDS 7 /* Number of headers above, plus 1 for message body itself */
#define FIELD_DESC_WIDTH 9 /* Max length of any of the above, plus 1 */

static inline __attribute__((always_inline)) int num_quotes(const char *s)
{
	int n = 0;
	while (*s == '>') {
		n++;
		s++;
	}
	return n;
}

static void copy_trimmed_str(char *restrict dst, const char *restrict src, size_t len, int cols, int trailing_crlf, size_t *restrict leftover)
{
	int output_col = 0;
	int col = 0;
	int row = 0;
	int blank_lines = 0;
	int consec_spaces = 0;
	int in_quotes = 0, quote_depth = 0;
	const char *sp_start = NULL;
	int last_flowed = 0;

	assert(cols > 0);

	/* This is a bit of an eyesore, but the reason we need to keep track of so much state is
	 * to keep the overall function linear time with respect to message size. */

	/* Skip leading whitespace */
	while (*src == ' ') {
		src++;
	}
	while (*src) {
		if (col == 0) {
			if (consec_spaces > cols) {
				client_debug(9, "Detected a blank line");
				blank_lines++;
				consec_spaces = 0;
				sp_start = NULL;
			}
#ifndef HARD_LINE_BREAK_REQUIRES_DOUBLE
			if (consec_spaces > 0 && next_word_count(src) < consec_spaces - 7) { /* Leave some wiggle room */
				/* We try to determine if this is a real line break
				 * or a "soft" line break due to wrapping.
				 * This won't be perfect, but if the previous line
				 * ended significantly before the end of the line,
				 * and the next word isn't that long,
				 * then that suggests a hard line break is appropriate. */
				client_debug(8, "Looks like a hard line break on line %d, based on context", row);
				blank_lines++;
				consec_spaces = 0;
				sp_start = NULL;
			}
#endif
			in_quotes = *src == '>';
			quote_depth = 0;
			if (last_flowed) {
				/* If we wrap text shorter due to a resize to smaller col dimensions,
				 * then we'll want to do that at the end of the actual line as well. */
				client_debug(7, "Last line was soft wrapped, adding a soft wrap here");
				*dst++ = ' ';
				len--;
			}
			last_flowed = 0;
#if 0
		/* Don't do this, since the quotes at beginnings of lines are for quoting messages,
		 * not quote literals in a reply. If that's what someone wants, the user will need
		 * to manually escape... */
		} else if (output_col == 1) {
			/* Space-stuff lines which start with a space, "From ", or ">". */
			if (dst[-1] == ' ' || dst[-1] == '>' || (dst[-1] == 'F' && !strncmp(src, "rom ", 4))) {
				client_debug(9, "Space stuffing line");
				*dst = dst[-1];
				dst[-1] = ' ';
				len++;
				output_col++;
			}
#endif
		} else if (output_col >= FORMAT_FLOWED_WRAP_COL) {
			/* Find the most recent occurence of a space that we've already copied */
			const char *sp = memrchr(dst - FORMAT_FLOWED_WRAP_COL, ' ', FORMAT_FLOWED_WRAP_COL);
			if (sp) { /* Most lines do not contain words that are ~70+ characters long */
				char *mvdst, *mvsrc;
				char mvsrcc;
				/* Say that the dest buffer looks like this:
				 *
				 * 0 1 2 3 4 5 6 7 8 9
				 * a b c   d e f g j _ <- current value of dst.
				 *
				 * memrchr(dst - 1) will start at 8 and look backwards for a space, which it finds at 3.
				 * Thus, dst - 1 - sp = 9 - 1 - 3 = 5, which is how many characters exist in the buffer after the space.
				 *
				 * We insert a newline at 4, and shift everything else forward two characters:
				 * memmove(dst - diff + 1, dst - diff, diff)
				 *
				 * If we have to insert quotes, we also need to leave room for # of quotes + another space.
				 */
				int diff = dst - 1 - sp;
				/* If we need to insert quotes, we need to leave room for those + 1 space */
				mvsrc = dst - diff;
				mvsrcc = *mvsrc;
				mvdst = dst - diff + 2;
				if (quote_depth) {
					client_debug(9, "Adjusted mvdst from %p to %p", mvdst, mvdst + (quote_depth + 1));
					mvdst += (quote_depth + 1);
				}
				client_debug(9, "Need to shift(%d) '%.*s'", diff, diff, mvsrc);
				memmove(mvdst, mvsrc, diff);
				dst[-diff] = '\r'; /* Insert soft line wrap at the start of that word, which'll now get wrapped to the next line. */
				dst[-diff + 1] = '\n';
				dst += 2;
				len -= 2;
				client_debug(5, "Detected long line on row %d at %d cols, wrapped at %d cols (starting at %d: '%c')",
					row, output_col, FORMAT_FLOWED_WRAP_COL - diff, mvsrcc, isprint(mvsrcc) ? mvsrcc : ' ');
				output_col = 0;
				/* When wrapping, maintain the same quote depth */
				if (quote_depth) {
					int j;
					/* Back up to the beginning of the line */
					dst -= diff;
					len += diff;
					client_debug(5, "Prefixing with %d quotes and a space", quote_depth);
					for (j = 0; j < quote_depth; j++) {
						*dst++ = '>';
						len--;
					}
					*dst++ = ' ';
					len--;
					if (unlikely(dst > mvdst)) {
						client_debug(1, "ERROR: Overran start of shifted data by %ld bytes! %p > %p", dst - mvdst, dst, mvdst);
						assert(dst == mvdst); /* Crash */
					}
					dst += diff; /* Skip data we copied */
					len -= diff;
				}
				assert(dst == mvdst + diff); /* Should be positioned after the data that we moved */
				last_flowed = 1;
			} else {
				client_debug(5, "Encountered super long word at row %d, can't wrap", row);
			}
		}
		if (*src == ' ') {
			if (!consec_spaces++) {
				sp_start = src;
			}
		} else {
			if (in_quotes) {
				if (*src == '>') {
					quote_depth++;
				} else {
					in_quotes = 0;
				}
			}
			if (!blank_lines && !col && row > 0) {
				if (*src == '>') {
					/* Quote at column 0, so actual newline */
					*dst++ = '\r';
					*dst++ = '\n';
					output_col = 0;
					len -= 2;
					consec_spaces = 0; /* Let the normal logic handle this case */
				} else {
					/* So that if text wraps to the next line, we insert a space as appropriate */
					if (*(dst - 1) == ' ') {
						/* XXX Should prevent this from happening, but don't add two spaces if we detect it */
						client_debug(9, "Already added space at end of line for row %d col %d, not adding another one before '%c'", row, col, *src);
					} else {
						client_debug(9, "Implicit line wrap on row %d col %d, adding space before '%c'", row, col, *src);
						*dst++ = ' ';
						output_col++;
						len--;
					}
				}
			}
			while (blank_lines > 0) {
				/* \n doesn't appear in the buffer, we have to determine where line breaks are by counting columns */
				/* Process empty lines in body */
				*dst++ = '\r';
				*dst++ = '\n';
				output_col = 0;
				len -= 2;
				blank_lines--;
			}
			if (consec_spaces) {
				if (col > 0) {
					/* Spaces in the middle of the line, print em out, they count */
					assert(sp_start != NULL);
					/* Yeah, we could use memcpy here, but this isn't a particularly common case either: */
					while (sp_start <= src) { /* up to and including the first char after the spaces */
						*dst++ = *sp_start++;
						len--;
						output_col++;
					}
				} else {
					*dst++ = *src;
					len--;
					output_col++;
				}
			} else {
				/* Normal character */
				*dst++ = *src;
				len--;
				output_col++;
			}
			consec_spaces = 0;
		}
		src++;
		if (++col == cols) {
			col = 0;
			row++;
		}
	}

	if (trailing_crlf) {
		*dst++ = '\r';
		*dst++ = '\n';
		len -= 2;
	}

	/* Was originally len == 1, but due to the conservative format=flowed line wrapping calculation, we might have some excess room left over */
	assert(len >= 1);
	if (len > 1) {
		client_debug(7, "Finished copying field with %lu bytes left over", len - 1);
	}
	*dst = '\0';
	len--;
	*leftover = len;
}

static void dump_body(const char *s, size_t len)
{
	client_debug(1, "Body(%lu):", len);
	while (*s) {
		const char *eol = strstr(s, "\r\n");
		if (eol) {
			int diff = (int) (eol - s);
			client_debug(10, "'%.*s'", diff, s);
			s += diff + 2;
		} else {
			client_debug(10, "%s", s);
			return;
		}
	}
}

/*! \brief Convert form fields into strings */
static int unformat_fields(FIELD *fields[NUM_FIELDS + 1], struct message_constructor *msgc)
{
	int i;
	char *s[NUM_FIELDS];
	size_t lengths[NUM_FIELDS];

	for (i = 0; i < NUM_FIELDS; i++) {
		lengths[i] = get_field_length(fields[i], fields[i]->dcols, i == NUM_FIELDS - 1);
		if (lengths[i]) {
			size_t leftover;
			s[i] = malloc(lengths[i] + 1);
			if (!s[i]) {
				/* Clean up unassigned results */
				for (i = 0; i < NUM_FIELDS; i++) {
					free_if(s[i]);
				}
				return -1;
			}
			/* Build trimmed string, which is also format=flowed wrapped at 72 columns. */
			client_debug(6, "Parsing message from %d-col field", fields[i]->dcols);
			copy_trimmed_str(s[i], field_buffer(fields[i], 0), lengths[i] + 1, fields[i]->dcols, i == NUM_FIELDS - 1, &leftover);
			if (i == NUM_FIELDS - 1) {
				/* Since get_field_length can over estimate for the body, subtract how much was actually left at the end
				 * to get the correct length. */
				msgc->bodylen = lengths[i] - leftover;
			}
		} else {
			s[i] = NULL;
		}
	}

#ifdef DEBUG_MODE
	/* Dump post-processed form fields */
	for (i = 0; i < NUM_FIELDS - 1; i++) {
		if (s[i]) {
			client_debug(1, "%s(%lu): '%s'", field_names[i], lengths[i], s[i]);
		}
	}
	/* This could be huge: */
	dump_body(s[NUM_FIELDS - 1], msgc->bodylen);
#endif

	/* Process message */
	msgc->from = s[0];
	msgc->to = s[1];
	msgc->cc = s[2];
	msgc->bcc = s[3];
	msgc->replyto = s[4];
	msgc->subject = s[5];
	msgc->body = s[6];

	return 0;
}

/*! \brief Create a RFC822 message from the form fields */
static char *create_message(FIELD *fields[NUM_FIELDS + 1], struct message_constructor *msgc, int addbcc, size_t *restrict msglen)
{
	char *msg;
	char *bcc;

	if (unformat_fields(fields, msgc)) {
		return NULL;
	}

	bcc = msgc->bcc;
	if (!addbcc) {
		/* hide Bcc from RFC822 message creation... */
		msgc->bcc = NULL;
	}
	msg = create_email_message(msgc, msglen);
	msgc->bcc = bcc; /* ... and restore it here, for the envelope */

	return msg;
}

static void cleanup_message_constructor(struct message_constructor *msgc)
{
	free_if(msgc->from);
	free_if(msgc->to);
	free_if(msgc->cc);
	free_if(msgc->bcc);
	free_if(msgc->replyto);
	free_if(msgc->subject);
	free_if(msgc->body);
	free_if(msgc->references);
}

static int reformat_msg(FIELD *fields[NUM_FIELDS + 1], struct message_constructor *msgc)
{
	memset(msgc, 0, sizeof(struct message_constructor));
	if (unformat_fields(fields, msgc)) {
		cleanup_message_constructor(msgc);
		return -1;
	}
	return 0;
}

/*! \brief Create and send a message */
static int send_message(struct client *client, FIELD *fields[NUM_FIELDS + 1], struct message_constructor *msgc, struct message_data *mdata)
{
	size_t msglen;
	int res = -1;
	char *msg;

	memset(msgc, 0, sizeof(struct message_constructor));

	if (mdata) {
		msgc->inreplyto = mdata->messageid; /* This is a direct reply to this message */
		msgc->references = mdata->references;
	}
	msg = create_message(fields, msgc, 0, &msglen); /* Don't add Bcc to the RFC822 message, only to the envelope */
	msgc->inreplyto = NULL; /* We didn't allocate these, don't free them */
	msgc->references = NULL;

	if (!msg) {
		cleanup_message_constructor(msgc);
		return 1;
	}

	/* Sending can take a moment, update the status bar now */
	client_set_status_nout(client, "Sending...");
	doupdate();

	if (0) {
		/*! \todo Future support for BURL IMAP */
	} else {
		/* The traditional way of sending a message via SMTP
		 * and then saving a copy of it to the Sent folder
		 * does involve a classic race condition, whereby if
		 * the message is sent but the program crashes prior
		 * to a copy being saved to "Sent", the message is lost.
		 * Server-side saving or BURL IMAP avoid this. */
		res = smtp_send(client, msgc, msg, msglen);
		if (!res && client->config->imap_append) {
			/* Save sent copy */
			res = client_idle_stop(client);
			if (!res) {
				res = client_append(client, SENT_MAILBOX(client), IMAP_MESSAGE_FLAG_SEEN, msg, msglen);
				if (!res && client->sent_mbox) {
					increment_stats_by_size(client->sent_mbox, msglen, 0);
					increment_stats_by_size(&client->mailboxes[0], msglen, 0); /* Aggregate stats */
				}
			} else {
				res = 2;
			}
		}
	}

	free(msg);
	return res ? 1 : 0; /* Don't abort program if SMTP transaction failed, just display error and continue */
}

/*! \brief Create a message and save to Drafts */
static int save_message(struct client *client, FIELD *fields[NUM_FIELDS + 1], struct message_constructor *msgc, struct message_data *mdata)
{
	size_t msglen;
	int res = -1;
	char *msg;

	memset(msgc, 0, sizeof(struct message_constructor));

	if (mdata) {
		msgc->inreplyto = mdata->messageid; /* This is a direct reply to this message */
		msgc->references = mdata->references;
	}
	msg = create_message(fields, msgc, 1, &msglen); /* Do add Bcc to RFC822 message, for Drafts */
	msgc->inreplyto = NULL; /* We didn't allocate these, don't free them */
	msgc->references = NULL;

	if (!msg) {
		cleanup_message_constructor(msgc);
		return 1;
	}

	/* Saving can take a moment, update the status bar now */
	client_set_status_nout(client, "Saving...");
	doupdate();

	/* Upload to Drafts folder */
	if (client_idle_stop(client)) {
		return -1;
	}
	res = client_append(client, DRAFTS_MAILBOX(client), IMAP_MESSAGE_FLAG_DRAFT, msg, msglen); /* Do not mark \Seen, but mark as \Draft */
	if (!res && client->draft_mbox) {
		increment_stats_by_size(client->draft_mbox, msglen, 1);
		increment_stats_by_size(&client->mailboxes[0], msglen, 1); /* Aggregate stats */
	}

	free(msg);
	return res ? 1 : 0;
}

static int addr_needs_quotes(const char *s)
{
	/* RFC 5322 3.2.4 */
	while (*s) {
		if (!isalnum(*s)) {
			switch (*s) {
				case '!':
				case '#':
				case '$':
				case '%':
				case '*':
				case '+':
				case '-':
				case '/':
				case '=':
				case '?':
				case '^':
				case '_':
				case '`':
				case '{':
				case '|':
				case '}':
				case '~':
					break;
				default:
					return 1;
			}
		}
		s++;
	}
	return 0;
}

static int compute_sender_identity(struct client *client, char *buf, size_t len)
{
	if (!strlen_zero(client->config->fromaddr)) {
		if (!strlen_zero(client->config->fromname)) {
			if (addr_needs_quotes(client->config->fromname)) {
				snprintf(buf, len, "\"%s\" <%s>", client->config->fromname, client->config->fromaddr);
			} else {
				snprintf(buf, len, "%s <%s>", client->config->fromname, client->config->fromaddr);
			}
		} else {
			snprintf(buf, len, "%s", client->config->fromaddr);
		}
		return 0;
	} else if (!strlen_zero(client->config->imap_username)) {
		if (strchr(client->config->imap_username, '@')) {
			snprintf(buf, len, "<%s>", client->config->imap_username);
		} else {
			snprintf(buf, len, "<%s@%s>", client->config->imap_username, client->config->imap_hostname);
		}
		return 0;
	} else {
		return -1;
	}
}

static void populate_fields(FIELD *fields[NUM_FIELDS + 1], struct message_constructor *msgcin)
{
#define PREPOPULATE(index, field) \
	if (msgcin->field) { \
		client_debug(9, "Prepopulating %s with %lu bytes", #field, index == NUM_FIELDS - 1 ? msgcin->bodylen : strlen(msgcin->field)); \
		set_field_buffer(fields[index], 0, msgcin->field); \
	}
	PREPOPULATE(0, from);
	PREPOPULATE(1, to);
	PREPOPULATE(2, cc);
	PREPOPULATE(3, bcc);
	PREPOPULATE(4, replyto);
	PREPOPULATE(5, subject);
	/* Not body here */
#undef PREPOPULATE
}

static inline __attribute__((always_inline)) void form_driver_str(FORM *form, const char *s)
{
	while (*s) {
		form_driver(form, *s);
		s++;
	}
}

static inline __attribute__((always_inline)) int line_len(const char *s)
{
	int n = 0;
	while (*s) {
		if (*s == '\r') {
			return n;
		} else if (*s == '\n') {
			client_debug(4, "Bare LF encountered?");
			return n;
		}
		s++;
		n++;
	}
	return n;
}

static void format_and_quote_body(FORM *form, const char *body, int addquotes)
{
	int inputcol = 0;
	int outputcol = 0;
	int in_quotes = 0, quote_depth = 0;
	int row = 0;
	const char *s = body;

	client_debug(4, "Formatting body for %d col display (add quotes: %d)", COLS, addquotes);

	/* We can't print newlines into the form field,
	 * we have to format it exactly as lines of width COLS.
	 *
	 * Additionally, quote each line with >
	 *
	 * This would be trivial, were it not for the fact that we want
	 * the quoted text to fill the entire terminal. */

#define VERIFY_INTEGRITY() \
	if (unlikely(form->curcol != outputcol)) { \
		client_debug(7, "row %d: curcol is %d but outputcol is %d???", row, form->curcol, outputcol); \
		assert(form->curcol == outputcol); /* Crash */ \
	}

#define FORM_PUTC(c) \
	form_driver(form, c); \
	outputcol++; \
	if (unlikely(form->curcol != outputcol)) { \
		client_debug(7, "row %d: curcol is %d but outputcol is %d? (after inserting %d/%c)??", row, form->curcol, outputcol, c, c); \
		assert(form->curcol == outputcol); /* Crash */ \
	}

	VERIFY_INTEGRITY();
	while (*s) {
		VERIFY_INTEGRITY();
#ifdef HARDCORE_DEBUG
		/* Dump it, dump it all... */
		client_debug(10, "row %d, col %d (outputcol %d, quote depth %d) - %d %c", row, inputcol, outputcol, quote_depth, *s, *s);
#endif
		if (!strncmp(s, "\r\n", 2)) {
			if (outputcol > 0 && s[-1] == ' ' && *(s + 2) && next_n_quotes(s + 2, quote_depth)) {
				/* We just printed the format=flowed space at the end of the input line,
				 * but that conflicts with this path:
				 * if (addquotes && inputcol == 0 && quote_depth == 0) {
				 */
				form_driver(form, REQ_DEL_PREV);
				outputcol--;

				client_debug(9, "format=flowed line break on row %d, col %d", row, outputcol);
				/* This is a format=flowed soft line wrap, don't actually wrap */
				s += STRLEN("\r\n"); /* Skip CR LF */
				s += quote_depth; /* Skip quotes */
				inputcol = quote_depth;
				if (*s == ' ') { /* XXX Looking back at this, I don't think there would be a space here, but doesn't hurt anything either */
					/* Skip space, since we already printed the format=flowed space at end of previous line */
					inputcol++;
					s++;
					client_debug(9, "Skipped format=flowed space, next character is '%c'", *s);
				} else {
					client_debug(9, "Didn't skip format=flowed space, next character is '%c'", *s);
				}
				/* Resume */
			} else {
				if (outputcol > 0 && s[-1] == ' ' && *(s + 2)) {
					client_debug(9, "Hard line break on row %d, col %d (would've soft wrapped but quote depth changed)", row, outputcol);
				} else {
					client_debug(10, "Hard line break on row %d, col %d", row, outputcol);
				}
				inputcol = 0;
				s += STRLEN("\r\n");
				form_driver(form, REQ_NEW_LINE);
				assert(form->curcol == 0);

				outputcol = 0;
				if (addquotes) {
					FORM_PUTC('>');
				}
			}
			row++;
		} else {
			if (outputcol == 0) {
				if (addquotes) {
					client_debug(9, "Quoting beginning of line");
					FORM_PUTC('>');
				}
			} else if (outputcol + 1 >= COLS) {
				int j;
				const char *last_sp;
				/* Need a line wrap, at a word boundary */
				client_debug(9, "Wrapping long line at %d cols", outputcol);
				last_sp = memrchr(s - outputcol, ' ', outputcol);
				if (last_sp) {
					int diff = s - 1 - last_sp;
					if (diff < outputcol - 2) {
						client_debug(9, "Backing up %d characters", diff);
						for (j = 0; j < diff; j++) {
							form_driver(form, REQ_DEL_PREV);
						}
						/* Back up and break the line there instead */
						s -= diff;
						outputcol -= diff;
						inputcol -= diff;
					} else {
						client_debug(1, "Can't wrap this line: %d/%d", diff, outputcol);
					}
				}
				outputcol = 0;
				form_driver(form, REQ_NEW_LINE);
				VERIFY_INTEGRITY();
				if (addquotes) {
					FORM_PUTC('>');
				}
				for (j = 0; j < quote_depth; j++) {
					FORM_PUTC('>');
				}
				if (quote_depth || *s != ' ') { /* Condition added since down below we also add a space, but only if quote_depth is 0 */
					/* Ensure there's a space after the quotes before continuing */
					FORM_PUTC(' ');
				}
				if (!strncmp(s, "\r\n", 2)) {
					client_debug(9, "Was at CR LF, skipping");
					s += 2;
					inputcol += 2; /* Needed to avoid adding extraneous "space between quotes and quoted text" */
					if (!*s) {
						break;
					}
				}
			}
			VERIFY_INTEGRITY();
			if (inputcol == 0) {
				if (*s == '>') {
					in_quotes = 1;
					quote_depth = 1;
				} else {
					in_quotes = 0;
					quote_depth = 0;
					client_debug(10, "Quote depth of row %d is %d", row, quote_depth);
				}
			} else if (in_quotes) {
				if (*s == '>') {
					quote_depth++;
				} else {
					int linelen = line_len(s);
					in_quotes = 0;
					client_debug(10, "Quote depth of row %d is %d (%d chars left on line)", row, quote_depth, linelen);
					/* It doesn't start with space, add one for readability */
					if (*s != ' ') {
						FORM_PUTC(' ');
					}
				}
			}
			if (addquotes && inputcol == 0 && quote_depth == 0) {
				/* If this line was previously unquoted, also add a space prior to the quoted text */
				client_debug(9, "Adding space between quotes (depth 1) and quoted text");
				FORM_PUTC(' ');
			}
			if (*s == '\t') {
				int t, sp_req = 8 - outputcol % 8;
				/* Convert tabs to spaces... the editor doesn't support tabs anyways */
				for (t = 0; t < sp_req; t++) {
					FORM_PUTC(' ');
				}
				s++;
				inputcol++;
			} else if (*s > 127) {
				switch (*s) {
				case 194:
					if (*(s + 1) == 160) {
						/* NO BREAK SPACE. Thunderbird-based stuff likes to use this for consecutive spaces, tabs, etc. */
						FORM_PUTC(' ');
						s += 2;
						inputcol += 2;
						break;
					}
					/* Fall through */
				default:
					client_debug(6, "Dunno how to handle UTF-8 character %d %d", *s, *(s + 1));
					s++;
					inputcol++;
				}
			} else if (!isprint(*s)) {
				client_debug(6, "Skipping non-printable character %d", *s);
				s++;
				inputcol++;
			} else {
				FORM_PUTC(*s);
				s++;
				inputcol++;
			}
		}
	}

#undef FORM_PUTC
#undef VERIFY_INTEGRITY

	/* Start on blank line at end */
	form_driver(form, REQ_NEW_LINE);
	form_driver(form, REQ_NEW_LINE);
}

static char *addrstr(char *s)
{
	while (*s) {
		if (*s == ',' || *s == ';') {
			return s;
		}
		s++;
	}
	return NULL;
}

/*! \brief Check whether an address is one of our identities */
static int one_of_our_idents(struct client *client, char *s)
{
	char findstr[256];
	const char *domain;
	char *space;
	int res = 0;
	static int wildcard_domains = -1;

	space = strchr(s, ' '); /* Since we didn't rtrim */
	if (space) {
		*space = '\0';
	}

	/* The trivial one */
	if (client->config->fromaddr[0] && strstr(s, client->config->fromaddr)) {
		client_debug(3, "'%s' is our from address", s);
		res = 1;
		goto cleanup;
	}

	if (!client->config->additional_identities) {
		client_debug(3, "'%s' is not our from address, no additional identities configured", s);
		goto cleanup;
	}

	if (wildcard_domains == -1) {
		wildcard_domains = strstr(client->config->additional_identities, "*@") ? 1 : 0;
	}

	/* Look for wildcard domain match */
	if (wildcard_domains) {
		domain = strchr(s, '@');
		if (domain) {
			domain++;
			if (*domain) {
				snprintf(findstr, sizeof(findstr), "*@%s", domain);
				if (strcasestr(client->config->additional_identities, findstr)) {
					client_debug(3, "'%s' is an additional identity, by wildcard domain match", s);
					res = 1;
					goto cleanup;
				}
			}
		}
	}

	/* Look for explicit match */
	if (strcasestr(client->config->additional_identities, s)) {
		client_debug(3, "'%s' is an additional identity, by exact address match", s);
		res = 1;
		goto cleanup;
	}

cleanup:
	if (space) {
		*space = ' ';
	}
	return res;
}

/*! \brief Remove email addresses in a list of recipients if they're one of our identites */
static int remove_our_idents(struct client *client, char *s)
{
	int removed = 0;
	char *nextaddr;
	char *addr = s;
	do {
		char *tmp;
		int res = 0;

		nextaddr = addrstr(s);
		if (nextaddr) {
			*nextaddr = '\0';
		}

		/* The actual parsing during this iteration is fairly sloppy,
		 * we just do a substring match in one_of_our_idents
		 * so that's all that matters */

		/* Check each address in the list to see if it's one of ours */
		while (*addr == ' ') { /* ltrim */
			addr++;
		}

		tmp = strchr(addr, '<');
		if (tmp) {
			tmp++;
			if (*tmp) {
				char *end = strchr(tmp, '>');
				if (end) {
					*end = '\0';
				}
				res = one_of_our_idents(client, tmp);
				if (end) {
					*end = '>';
				}
			}
		} else {
			res = one_of_our_idents(client, addr);
		}

		if (nextaddr) {
			*nextaddr = ',';
		}

		if (res) {
			/* Remove it */
			removed++;
			if (!nextaddr) {
				/* That was the last one, easy */
				*s = '\0';
				return removed;
			}
			/* There are more after, shift em up */
			memmove(s, nextaddr + 1, *(nextaddr + 1) ? 1 : strlen(nextaddr) + 1); /* Include NUL terminator when shifting up.*/
			nextaddr = s;
		}
	} while ((addr = nextaddr));
	return removed;
}

static int choose_reply_identity(struct client *client, char **from, char *s)
{
	char *nextaddr;
	char *addr = s;
	do {
		char *tmp;
		int res = 0;

		nextaddr = addrstr(s);
		if (nextaddr) {
			*nextaddr = '\0';
		}

		/* The actual parsing during this iteration is fairly sloppy,
		 * we just do a substring match in one_of_our_idents
		 * so that's all that matters */

		/* Check each address in the list to see if it's one of ours */
		while (*addr == ' ') { /* ltrim */
			addr++;
		}

		tmp = strchr(addr, '<');
		if (tmp) {
			tmp++;
			if (*tmp) {
				char *end = strchr(tmp, '>');
				if (end) {
					*end = '\0';
				}
				res = one_of_our_idents(client, tmp);
				if (res) {
					*from = strdup(tmp);
				}
				if (end) {
					*end = '>';
				}
			}
		} else {
			res = one_of_our_idents(client, addr);
			if (res) {
				*from = strdup(addr);
			}
		}

		if (nextaddr) {
			*nextaddr = ',';
		}

		if (res) {
			/* One of ours, it's one of ours! */
			return 1;
		}
	} while ((addr = nextaddr));
	return 0;
}

enum compose_type {
	COMPOSE_NEW,
	COMPOSE_REPLY,
	COMPOSE_EDIT,
	COMPOSE_FORWARD,
};

enum editor_outcome {
	OUTCOME_MESSAGE_DISCARDED = 0,
	OUTCOME_MESSAGE_SENT = 1,
	OUTCOME_MESSAGE_SAVED = 2,
};

static int __editor(struct client *client, struct pollfd *pfds, uint32_t uid, struct message_constructor *msgcin, const char *author, struct message_data *mdata, enum compose_type comptype, enum editor_outcome *restrict outcome);

static int __reply(struct client *client, struct pollfd *pfds, struct message *msg, struct message_data *mdata, int replyall, enum compose_type comptype);

int reply(struct client *client, struct pollfd *pfds, struct message *msg, struct message_data *mdata, int replyall)
{
	return __reply(client, pfds, msg, mdata, replyall, COMPOSE_REPLY);
}

int forward(struct client *client, struct pollfd *pfds, struct message *msg, struct message_data *mdata)
{
	return __reply(client, pfds, msg, mdata, 0, COMPOSE_FORWARD);
}

static int __reply(struct client *client, struct pollfd *pfds, struct message *msg, struct message_data *mdata, int replyall, enum compose_type comptype)
{
	struct message_data mdata_stack;
	struct message_constructor msgc;
	int mdata_created = mdata ? 0 : 1;
	int res;
	enum editor_outcome outcome; /* Discarded */

	if (mdata_created) {
		enum view_message_type mtype;
		mdata = &mdata_stack;
		memset(&mdata_stack, 0, sizeof(mdata_stack));
		if (client_idle_stop(client)) {
			return -1;
		}
		if (construct_message_data(client, msg, &mdata_stack, &mtype)) {
			return -1;
		}
		if (client_idle_start(client)) {
			return -1;
		}
	}

	memset(&msgc, 0, sizeof(msgc));

#define DUP_HDR_FLD(dst, src) \
	dst = strdup(src); \
	if (!dst) { \
		return -1; \
	}

	if (comptype == COMPOSE_REPLY) {
		/* Implement what I call the "email reply address algorithm".
		 * I'm sure this is documented somewhere formally,
		 * but it is something like this, heuristically, and from comparing
		 * with Thunderbird-based clients.
		 *
		 * To: there is a Reply-To header, use that for the "To" header. Otherwise, use the "From" header.
		 *
		 * If we're replying all, also:
		 * - copy over the "To" recipients to "To", except us
		 * - copy over the "Cc" recipients to "Cc", except us
		 *
		 */

		/* If there's a Reply-To address, use that */
		if (mdata->replyto) {
			DUP_HDR_FLD(msgc.replyto, mdata->replyto);
		} else {
			/* Reply to the sender, directly */
			if (msg->from) {
				DUP_HDR_FLD(msgc.to, msg->from);
				/* Do not call remove_our_idents for this case.
				 * We should be able to reply to ourself, if we're
				 * replying to a message we sent. */
			}
		}

		if (replyall) {
			if (mdata->to) {
				if (msgc.to) {
					size_t origlen = strlen(msgc.to);
					char *reallocd = realloc(msgc.to, origlen + strlen(mdata->to) + 1);
					if (!reallocd) {
						free(msgc.to); /* Leaks others but exiting */
						return -1;
					}
					strcpy(reallocd + origlen, mdata->to); /* Safe */
					msgc.to = reallocd;
				} else {
					DUP_HDR_FLD(msgc.to, mdata->to);
				}
				if (remove_our_idents(client, msgc.to)) {
					client_debug(2, "Automatically removed 'To' recipients");
				}
			}
			/* Cc anyone that was Cc'd originally, excluding us, if any of our identities were Cc'd */
			if (mdata->cc) {
				DUP_HDR_FLD(msgc.cc, mdata->cc);
				if (remove_our_idents(client, msgc.cc)) {
					client_debug(2, "Automatically removed 'Cc' recipients");
				}
			}
		}
	}

	/* The second part of this is determine the address from which we should reply.
	 * If one of our identities appeared as one of the recipients in "To" or "Cc" originally,
	 * reply from that address, unless it's the default one.
	 * Otherwise, fall back to the default one. */
	if (mdata->to) {
		choose_reply_identity(client, &msgc.from, mdata->to);
	}
	if (!msgc.from && mdata->cc) {
		choose_reply_identity(client, &msgc.from, mdata->cc);
	}
	if (!msgc.from) {
		char fromaddr[384];
		/* Default to using our default identity */
		if (!compute_sender_identity(client, fromaddr, sizeof(fromaddr))) {
			DUP_HDR_FLD(msgc.from, fromaddr);
		}
	}

	if (comptype == COMPOSE_REPLY) {
		if (asprintf(&msgc.subject, "%s%s", mdata->subject && !strncmp(mdata->subject, "Re: ", STRLEN("Re: ")) ? "" : "Re: ", mdata->subject ? mdata->subject : "") < 0) {
			return -1;
		}
	} else {
		if (asprintf(&msgc.subject, "%s%s", mdata->subject && !strncmp(mdata->subject, "Fwd: ", STRLEN("Fwd: ")) ? "" : "Fwd: ", mdata->subject ? mdata->subject : "") < 0) {
			return -1;
		}
	}

	if (mdata->pt_body) {
		msgc.body = strdup(mdata->pt_body);
		if (msgc.body) {
			char *s;
			msgc.bodylen = mdata->pt_size; /* Not used, but we have it... */
			/* rtrim, so that when formatting reply, there's no trailing whitespace */
			s = msgc.body + msgc.bodylen - 1;
			while (*s) {
				if (*s == ' ') {
					*s = '\0';
					s--;
				} else if (*s == '\n') {
					s--;
					*s = '\0'; /* Terminate at CR */
					s--;
				} else {
					break;
				}
			}
		}
	}

	/* In-Reply-To will be just mdata->messageid,
	 * and we handle that in create_message,
	 * but we need to append the direct message to which
	 * we're replying to the list of parent messages in
	 * the References header. Luckily, it's most recent one last. */
	if (mdata->messageid) {
		if (msgc.references) {
			char appendbuf[256];
			int len = snprintf(appendbuf, sizeof(appendbuf), ", %s", mdata->messageid);
			if (len < (int) sizeof(appendbuf)) {
				APPEND_STR(msgc.references, appendbuf, len);
			}
		} else {
			APPEND_STR(msgc.references, mdata->messageid, strlen(mdata->messageid));
		}
	}

	/* Prepopulate the editor with the preconstructed reply */
	/* msg is generally not safe to use within __editor since it could get deleted during IDLE,
	 * but msg->from will only get used immediately when the function starts, before we process IDLE,
	 * so it's safe */
	/* Pass in UID if we're replying to a message that hasn't yet been replied to (for storing \Answered) */
	res = __editor(client, pfds, msg && !(msg->flags & IMAP_MESSAGE_FLAG_ANSWERED) ? msg->uid : 0, &msgc, msg ? msg->from : NULL, mdata, comptype, &outcome);

	if (mdata_created) {
		client_cleanup_message(&mdata_stack);
	}
	return res;
}

int edit_message(struct client *client, struct pollfd *pfds, struct message *msg)
{
	struct message_data mdata;
	struct message_constructor msgc;
	enum view_message_type mtype;
	int res;
	uint32_t draft_uid;
	enum editor_outcome outcome;

	memset(&msgc, 0, sizeof(msgc));

	/* Edit an existing RFC822 message.
	 * Start off with logic similar to the viewer logic */
	memset(&mdata, 0, sizeof(mdata));
	if (construct_message_data(client, msg, &mdata, &mtype)) {
		return -1;
	}
	mtype = VIEW_MESSAGE_PT;
	if (client_fetch_mime(&mdata, 0, 0)) {
		if (client_fetch_mime(&mdata, 0, 1)) {
			client_set_status_nout(client, "Can't parse plaintext/HTML components");
			doupdate();
			client_cleanup_message(&mdata);
			return 0;
		}
		mtype = VIEW_MESSAGE_HTML;
		convert_html_to_pt(client, &mdata);
	}

	msgc.body = mtype == VIEW_MESSAGE_HTML ? mdata.html_body : mdata.pt_body;
	msgc.bodylen = mtype == VIEW_MESSAGE_HTML ? mdata.html_size : mdata.pt_size;

	/* Since we don't fully support attachments yet, refuse to edit drafts with attachments,
	 * since doing so would implicitly discard the attachment if saved/sent. */
	if (mdata.num_attachments) {
		client_set_status_nout(client, "Can't edit drafts with attachments");
		doupdate();
		client_cleanup_message(&mdata);
		return 0;
	}

	/* Copy over all the addresses verbatim */
	if (msg->from) {
		DUP_HDR_FLD(msgc.from, msg->from);
	}
	if (mdata.replyto) {
		DUP_HDR_FLD(msgc.replyto, mdata.replyto);
	}
	if (mdata.to) {
		DUP_HDR_FLD(msgc.to, mdata.to);
	}
	if (mdata.cc) {
		DUP_HDR_FLD(msgc.cc, mdata.cc);
	}
	if (mdata.bcc) { /* Any Bcc's while editing are stored in the message itself */
		DUP_HDR_FLD(msgc.bcc, mdata.bcc);
	}
	if (mdata.subject) {
		DUP_HDR_FLD(msgc.subject, mdata.subject);
	}
	if (!msgc.from) {
		char fromaddr[384];
		/* Default to using our default identity */
		if (!compute_sender_identity(client, fromaddr, sizeof(fromaddr))) {
			DUP_HDR_FLD(msgc.from, fromaddr);
		}
	}

	draft_uid = msg->uid; /* Save UID beforehand, since msg won't be valid after __editor returns */
	res = __editor(client, pfds, 0, &msgc, NULL, &mdata, COMPOSE_EDIT, &outcome);
	if (!res && outcome != OUTCOME_MESSAGE_DISCARDED) {
		struct message *origmsg;
		/* If saved or sent message, delete the original draft. Otherwise keep it.
		 * At this point, Thunderbird-based stuff will mark message as \Seen and \Deleted;
		 * no explicit EXPUNGE. This seems pretty reasonable. */
		client_debug(3, "Message was %s, marking original draft message %u as deleted", outcome == OUTCOME_MESSAGE_SENT ? "sent" : "saved", draft_uid);
		if (client_idle_stop(client)) {
			return -1;
		}
		origmsg = get_msg_by_uid(client, draft_uid);
		if (!origmsg) {
			return res;
		}

		/* Could do \Seen and \Deleted in one RTT here (using a single STORE), but
		 * this isn't a common operation anyways. */
		/* Mark \Seen */
		if (origmsg && !(origmsg->flags & IMAP_MESSAGE_FLAG_SEEN)) {
			if (client_store_seen(client, +1, origmsg)) {
				return -1;
			} else {
				mark_message_seen(client->sel_mbox, origmsg);
				client->mailboxes[0].unseen--; /* TOTAL */
			}
		}
		/* Mark \Deleted */
		if (client_store_deleted(client, origmsg)) {
			return -1;
		}
	}
	return res;
}

static inline void set_line_status(struct client *client, FORM *form, int before_row)
{
	if (form->currow != before_row) {
		char buf[56];
		snprintf(buf, sizeof(buf), "ESC for help | ln %d", form->currow + 1); /* 1-index the row number for the user */
		/* Tried saving original cursor position and restoring it afterwards, to prevent "flashing" in the status bar,
		 * but that doesn't seem to work, unfortunately.
		 * Disabling the cursor before/after doesn't work either (although this makes sense), since we're not refreshing the display here. */
		client_set_status_nout(client, buf);
	}
}

static int parse_sender_name(char *restrict buf, size_t len, char *addr)
{
	char *tmp;
	char *startbuf = buf;

	/* We're allowed to consume this address, since it's just going to be freed after this. */
	tmp = strchr(addr, '<');
	if (tmp) {
		/* Nix the email address */
		*tmp = '\0';
	}

	if (*addr == '"') {
		addr++;
		if (strlen_zero(addr)) {
			return -1;
		}
		tmp = strrchr(tmp, '"');
		if (tmp) {
			*tmp = '\0';
		}
		if (strlen_zero(addr)) {
			return -1;
		}
		safe_strncpy(buf, addr + 1, len);
	} else {
		/* Not quoted */
		safe_strncpy(buf, addr, len);
	}

	/* rtrim it */
	while (*buf) {
		buf++;
	}
	buf--;
	while (buf > startbuf && *buf == ' ') {
		*buf = '\0';
	}

	return 0;
}

int editor(struct client *client, struct pollfd *pfds)
{
	enum editor_outcome outcome;
	return __editor(client, pfds, 0, NULL, NULL, NULL, COMPOSE_NEW, &outcome);
}

static int need_beg_line_refresh_workaround(struct client *client)
{
	const char *term;

	(void) client;

	term = getenv("TERM");
	if (!strlen_zero(term) && !strcmp(term, "syncterm")) {
		client_debug(3, "Needs REQ_BEG_LINE refresh workaround");
		return 1;
	}
	return 0;
}

/*!
 * \brief Message editor, for new message composition or replies
 * \param client
 * \param pfds
 * \param uid UID of message being replied to
 * \param msgcin If provded, will be used to populate the fields with data about message being replied to
 * \param author Name of whoever wrote the message to which we're replying
 * \param mdata
 * \param comptype
 * \param[out] outcome Outcome of editing. 0 = no permanent action taken, 1 = message sent, 2 = message saved
 */
static int __editor(struct client *client, struct pollfd *pfds, uint32_t uid, struct message_constructor *msgcin, const char *author, struct message_data *mdata, enum compose_type comptype, enum editor_outcome *restrict outcome)
{
	int i, res = 0;
	int overtype = 0;
	int first_time = 1;
	FORM *form;
#define HEADER_FIELD_LENGTH COLS - FIELD_DESC_WIDTH
#define EDITING_BODY() (current_field(form) == fields[NUM_FIELDS - 1])
	FIELD *fields[NUM_FIELDS + 1]; /* From, To, Subject, Cc, Bcc, Reply-To */
	WINDOW *window;
	struct message_constructor msgc;
	int beg_line_workaround = need_beg_line_refresh_workaround(client);

	/* Very basic, lightweight editor, using the forms,
	 * sufficient for editing email messages,
	 * but not intended as a general purpose text editor.
	 *
	 * The ncurses form fields only have the concept of how text is displayed on the screen,
	 * essentially a canvas of characters. Therefore, while it works fine as an editor,
	 * there are some limitations.
	 *
	 * - Trailing whitespace on lines and in the message will be ignored, since we can't
	 *   differentiate that without keeping track of further state ourselves.
	 * - Pressing ENTER will visually insert two newlines, allowing us to parse a single
	 *   newline later, confidently, since otherwise we can't tell the difference between
	 *   text from the previous line simply wrapping to the next, or an actual desire
	 *   to insert a hard line break.
	 *
	 * This is embedded in the mail client so that we can receive new message
	 * notifications while the editor is active,
	 * and so that we can have complete control over the message editor.
	 * For example, we don't need to save to external files,
	 * we just need to keep the contents in memory. */

	/* Print status before setting up the form, that way the cursor is left in the right place */
	client_set_status_nout(client, "ESC for help");
	*outcome = OUTCOME_MESSAGE_DISCARDED; /* Default */

redraw:
	/* Set up all header fields (not message body field) */
	for (i = 0; i < NUM_FIELDS - 1; i++) {
		fields[i] = new_field(1, HEADER_FIELD_LENGTH, i, FIELD_DESC_WIDTH, 0, 0);
		if (!fields[i]) {
			/* Leaks, but exiting */
			return -1;
		}
		set_field_fore(fields[i], COLOR_PAIR(9));
		set_field_back(fields[i], A_UNDERLINE | COLOR_PAIR(9));
		field_opts_off(fields[i], O_AUTOSKIP | O_WRAP | O_STATIC); /* Disable autoskip */
	}

	/* Message body field
	 * The penultimate two arguments are not documented in the man page, but are here:
	 * https://tldp.org/HOWTO/NCURSES-Programming-HOWTO/forms.html
	 * # of offscreen buffers - in theory, I think this should be positive (same as arg 1, in fact),
	 * but it seems to work as is.
	 * # of additional buffers allocates additional buffers, that we can use for our own purposes.
	 */
	fields[i] = new_field(MAIN_PANE_HEIGHT - NUM_FIELDS + 1, COLS, i, 0, 0, 0); /* Take up as much of the rest of the window as possible */
	if (!fields[i]) {
		/* Leaks, but exiting */
		return -1;
	}
	set_field_fore(fields[NUM_FIELDS - 1], COLOR_PAIR(1)); /* Background color */
	set_field_back(fields[NUM_FIELDS - 1], COLOR_PAIR(1)); /* Foreground color */
	field_opts_off(fields[NUM_FIELDS - 1], O_AUTOSKIP | O_STATIC); /* Disable autoskip, allow dynamic resizing */
	set_max_field(fields[NUM_FIELDS - 1], 0); /* No max size for this field */

	fields[NUM_FIELDS] = NULL; /* Null terminate */

	/* Create form */
	form = new_form(fields);
	if (!form) {
		/* Leaks, but exiting */
		return -1;
	}

	window = newwin(LINES - 2, COLS, 1, 0); /* Full screen, minus top and bottom row */
	if (!window) {
		free_form(form);
		return -1;
	}

	wbkgd(window, COLOR_PAIR(1));
	keypad(window, TRUE);

	/* Associate with custom window, instead of default (stdscr) */
	set_form_win(form, window);
	set_form_sub(form, window);

	post_form(form);
	/* Draw field names */
	for (i = 0; i < NUM_FIELDS - 1; i++) {
		mvwprintw(window, i, 0, "%s", field_names[i]);
	}

	/* Populate fields if needed */
	if (msgcin) { /* Only do this first time */
		int have_sender = 0;
		char sender_ident[256];
		char author_dup[256];

		if (author) {
			safe_strncpy(author_dup, author, sizeof(author_dup));
			if (!parse_sender_name(sender_ident, sizeof(sender_ident), author_dup)) {
				have_sender = 1;
			}
		}

		/* Initialize */
		client_debug(5, "Prepopulating form fields for reply");
		populate_fields(fields, msgcin);

		form_driver(form, REQ_LAST_FIELD); /* We want to focus the body anyways, for replies */
		form_driver(form, REQ_BEG_FIELD); /* Start at beginning */
		if (msgcin->body) {
			char date[35];
			/* Preamble */
			if (comptype == COMPOSE_REPLY) {
				/* Thunderbird-based stuff is like this:
				 * e.g. "On 1/1/1991 6:01 AM, John Smith wrote:"
				 * Some other clients use different formats, e.g.:
				 * On Tuesday 01/01/1991 at 6:01 am, John Smith wrote:
				 * We use what's convenient for strftime to produce...
				 *
				 * We use the - modified to disable space/zero padding before the hour, month, and day,
				 * for a more natural, readable date string.
				 *
				 * Maximum length is "On 12/12/12 12:12 PM, " -> 35 with NUL.
				 */
				if (strftime(date, sizeof(date), "On %-m/%-d/%Y %-I:%M %p, ", &mdata->date) > 0) {
					form_driver_str(form, date);
				}
				if (have_sender) {
					form_driver_str(form, sender_ident);
				}
				form_driver_str(form, have_sender ? " wrote:" : "wrote:");
				form_driver(form, REQ_NEW_LINE);
			} else if (comptype == COMPOSE_FORWARD) {
				char fbuf[256];
#ifdef HARD_LINE_BREAK_REQUIRES_DOUBLE
#define ADD_LINE_BREAK() form_driver(form, REQ_NEW_LINE); form_driver(form, REQ_NEW_LINE);
#define ADD_LINE_BREAK_BEFORE() form_driver(form, REQ_INS_LINE); form_driver(form, REQ_INS_LINE);
				/* All the double line breaks are needed to tell the unparser that
				 * these are real line breaks, not soft line breaks.
				 * However, this looks very unnatural while editing.
				 *
				 * XXX This breaks down if you forward a forwarded message,
				 * since there is no logic to parse "-------- Forwarded Message --------"
				 * and insert line breaks in those headers... */
#else
#define ADD_LINE_BREAK() form_driver(form, REQ_NEW_LINE);
#define ADD_LINE_BREAK_BEFORE() form_driver(form, REQ_INS_LINE);
				/* Implemented improvement is we can check if a line break could possibly have been
				 * due to line wrapping - in most cases, if the number of spaces counted
				 * exceeds the length of the first word on the line significantly,
				 * it can be reasonably assumed to not be a hard line wrap. */
#endif
				form_driver_str(form, "-------- Forwarded Message --------");
				ADD_LINE_BREAK();
				if (!strlen_zero(msgcin->subject)) {
					snprintf(fbuf, sizeof(fbuf), "%9s: %s", "Subject", msgcin->subject);
					form_driver_str(form, fbuf);
					ADD_LINE_BREAK();
				}
				if (strftime(date, sizeof(date), "%a, %-e %b %Y %H:%M:%S %z", &mdata->date) > 0) {
					snprintf(fbuf, sizeof(fbuf), "%9s: %s", "Date", date);
					form_driver_str(form, fbuf);
					ADD_LINE_BREAK();
				}
				if (!strlen_zero(msgcin->from)) {
					snprintf(fbuf, sizeof(fbuf), "%9s: %s", "From", msgcin->from);
					form_driver_str(form, fbuf);
					ADD_LINE_BREAK();
				}
				if (!strlen_zero(msgcin->replyto)) {
					snprintf(fbuf, sizeof(fbuf), "%9s: %s", "Reply-To", msgcin->replyto);
					form_driver_str(form, fbuf);
					ADD_LINE_BREAK();
				}
				if (!strlen_zero(mdata->to)) {
					snprintf(fbuf, sizeof(fbuf), "%9s: %s", "To", mdata->to);
					form_driver_str(form, fbuf);
					ADD_LINE_BREAK();
				}
				if (!strlen_zero(mdata->cc)) {
					snprintf(fbuf, sizeof(fbuf), "%9s: %s", "Cc", mdata->cc);
					form_driver_str(form, fbuf);
					ADD_LINE_BREAK();
				}
				form_driver(form, REQ_NEW_LINE);
				ADD_LINE_BREAK();
			} /* COMPOSE_EDIT is verbatim, no special logic */
			format_and_quote_body(form, msgcin->body, comptype == COMPOSE_REPLY); /* Only quote if reply, not forward */
		}

		cleanup_message_constructor(msgcin);
		/* stack allocated, so don't call free(msgcin) */
		msgcin = NULL;
		if (comptype == COMPOSE_FORWARD) {
			form_driver(form, REQ_BEG_FIELD); /* Rewind body to top */
#define ENTERING_FIELDS_WITH_BLANK_LINES_FIRST_CLEARS_FIELD
#ifndef ENTERING_FIELDS_WITH_BLANK_LINES_FIRST_CLEARS_FIELD
			/* Insert blank lines prior, for our reply, if we're making one */
			ADD_LINE_BREAK();
			ADD_LINE_BREAK();
#else
			/* If seems that if a field starts with blank lines and gets focused,
			 * once you start typing it will clear the field.
			 * However, if you add the lines yourselves, then it's fine and that doesn't happen.
			 * So, for now, user will need to manually add the blank lines at the top. */
#endif
			set_current_field(form, fields[1]); /* Start with To: */
		}
	} else if (!first_time) {
		/* Reinitialize */
		populate_fields(fields, &msgc);
		form_driver(form, REQ_LAST_FIELD); /* We want to focus the body anyways, for replies */
		form_driver(form, REQ_BEG_FIELD); /* Start at beginning */
		if (msgc.body) {
			format_and_quote_body(form, msgc.body, 0);
		}
		cleanup_message_constructor(&msgc);
	} else {
		/* Defaults */
		char fromaddr[384];
		if (!compute_sender_identity(client, fromaddr, sizeof(fromaddr))) {
			set_field_buffer(fields[0], 0, fromaddr);
		}
		set_current_field(form, fields[1]); /* Start with To, not From address. Do this last, so the cursor is left in the right place. */
	}

	/*! \todo What would be neat to have for the address fields is autocompletion of addresses,
	 * where we start typing and it can suggest addresses used previously.
	 * However, this is difficult to do without storing anything, as our goal, after all, is to operate fully online
	 * and CACHE NOTHING! */

	wnoutrefresh(window);

	curs_set(2); /* Show cursor in editor, extra visible */
	client->cursor = 1;
	client->cur_win = window;
	doupdate();

	for (;;) {
		int c;
		int needresize = 0;

		/* Even though it's form->currow and form->curcol, it really gives us the position within the current field, not the overall form.
		 * The former is what we want anyways, so it works out. */
		int before_row = form->currow;
		int before_col = form->curcol;

		c = poll_input(client, pfds, 0);

		/*! \todo If there is an update during IDLE and the status bar is updated,
		 * then we'll want to refocus the cursor on the current field.
		 * Currently, poll_input won't return when such a thing happens,
		 * so we'd need to make it return, or pass in a callback to execute
		 * when processing IDLE. */

		switch (c) {
		/* Don't handle q or Q here, since those should go to the form driver */
		case -1:
			res = -1;
			goto done;
		case KEY_RESIZE:
			/* If this happens, the cursor will be repositioned to the end of the message body.
			 * This is honestly fine. This is an uncommon operation, I'm mainly happy that
			 * the message is rewrapped correctly (as far as I've tested).
			 * We could add logic to save the previous row and restore that, but the row could
			 * have changed due to the resize (and probably has), so probably not worth it anyways. */
resize:
			if (COLS < 80) {
				client_set_status_nout(client, "80 cols required");
				doupdate();
				continue;
			}
			/* Get the unformatted message as if we were sending it, then feed it back into format for the new dimensions */
			form_driver(form, REQ_VALIDATION);
			if (reformat_msg(fields, &msgc)) {
				return -1;
			}
			unpost_form(form);
			free_form(form);
			for (i = 0; i < NUM_FIELDS; i++) {
				free_field(fields[i]);
			}
			delwin(window);
			first_time = 0;
			goto redraw;
		case KEY_ESCAPE:
			curs_set(0);
			client->cursor = 0;
			SUB_MENU_PRE;
			res = c = show_help_menu(client, pfds, HELP_EDITOR);
			curs_set(2);
			client->cursor = 1;
			SUB_MENU_POST;
			/* Nothing has happened to the window,
			 * so doupdate() on its own won't redraw it by default,
			 * mark it as needing a redraw. This is the only place I'm aware of,
			 * where this is needed. */
			redrawwin(window);
			break;
		case 353: /* SHIFT + TAB */
			if (current_field(form) != fields[0]) {
				/* Previous field */
				form_driver(form, REQ_PREV_FIELD);
				form_driver(form, REQ_END_LINE); /* Start at end of any current input in the field */
			} else {
				beep();
			}
			break;
		case '\t':
			/* This is similar to the down key, but with an important distinction.
			 * For one, if we're editing the body, just add a tab.
			 *
			 * Conversely, if we're editing the header fields, and we press TAB,
			 * skip all the way to the subject field from any previous fields,
			 * rather than just going to the next one.
			 * This mirrors the behavior of Thunderbird-based mail clients,
			 * which allow skipping the "advanced" address fields (Cc, Bcc, Reply-To)
			 * when not needed. */
			if (EDITING_BODY()) {
				/* Unfortunately, ncurses forms don't take tab.
				 * We could convert it into 4 spaces, but some people might not like that. */
				beep();
			} else {
				/* If editing Subject or whatever is before that one, go to the next field.
				 * Otherwise, jump to Subject. */
				if (current_field(form) == fields[NUM_FIELDS - 2] || current_field(form) == fields[NUM_FIELDS - 3]) {
					form_driver(form, REQ_NEXT_FIELD); /* Next field */
				} else {
					set_current_field(form, fields[NUM_FIELDS - 2]);
				}
				if (current_field(form) == fields[NUM_FIELDS - 1] && comptype == COMPOSE_FORWARD) {
#ifdef ENTERING_FIELDS_WITH_BLANK_LINES_FIRST_CLEARS_FIELD
					FIELD *field = current_field(form);
					form_driver(form, REQ_BEG_FIELD);
					form_driver(form, REQ_VALIDATION); /* flush buffer */
					if (!strncmp(field_buffer(field, 0), "-------- Forwarded Message --------", STRLEN("-------- Forwarded Message --------"))) {
						/* Insert blank lines prior, for our reply, if we're making one */
						ADD_LINE_BREAK_BEFORE();
						ADD_LINE_BREAK_BEFORE();
						/* Now, the only way that the message will disappear is if we to to another field without typing anything and come back (unlikely).
						 * If that happens, user just needs to exit the editor and restart the forward. */
					}
#else
					form_driver(form, REQ_BEG_FIELD);
#endif
				} else {
					form_driver(form, REQ_END_LINE); /* Start at end of any current input in the field */
				}
			}
			break;

/* This is wrapped because in SyncTERM, using REQ_PREV_CHAR or REQ_BEG_LINE
 * to go to the beginning of a line in the body does not fully render properly.
 * The character is moved, but the cursor remains where it was, making it
 * appear as if nothing happened. Happens with HOME, ^A, and LEFT,
 * although LEFT works fine in the header fields, interestingly.
 *
 * So, we add some logic to force the cursor to update.
 * The secret is moving the cursor to another line, sending a screen update,
 * and then changing it where it actually needs to go, since REQ_PREV_LINE/REQ_NEXT_LINE LINE don't have this same issue.
 *
 * Obviously, this is slightly more inefficient, and users may occasionally notice
 * the cursor briefly being on the line below before ending up in the right spot.
 * Not ideal, but a small price to pay for ensuring the cursor actually updates. */
#define GOTO_LINE_BEGIN() \
	form_driver(form, REQ_BEG_LINE); \
	if (beg_line_workaround) { \
		/* Go to another line and come back, as hacky workaround. Go forward first since that always works */ \
		form_driver(form, REQ_NEXT_LINE); \
		wrefresh(window); \
		form_driver(form, REQ_PREV_LINE); \
	}

		case KEY_LEFT:
			if (before_col == 0) {
				if (EDITING_BODY() && before_row > 0) {
					client_debug(5, "At beginning of line, going to end of previous line");
					form_driver(form, REQ_PREV_LINE);
					form_driver(form, REQ_END_LINE);
				} else {
					/* In a header field, just stop */
					beep();
				}
			} else {
				if (EDITING_BODY() && before_col == 1) {
					GOTO_LINE_BEGIN();
				} else {
					form_driver(form, REQ_PREV_CHAR);
				}
			}
			break;
		case KEY_RIGHT:
			if (END_OF_LINE()) {
				if (EDITING_BODY()) {
					client_debug(5, "At the end of current row, treating as go to next line");
					/* REQ_NEXT_LINE defaults to first col, so it works out */
				} else {
					/* In a header field, just stop */
					beep();
				}
			} else {
				form_driver(form, REQ_NEXT_CHAR);
				break;
			}
			/* Fall through */
		case KEY_DOWN:
			/* If editing message, don't divert up and down */
			if (EDITING_BODY()) {
				if (END_OF_FIELD()) {
					/* There are no rows beneath this one. */
					client_debug(4, "No rows beneath current row");
					beep();
				} else {
					form_driver(form, REQ_NEXT_LINE);
					set_line_status(client, form, before_row);
				}
			} else {
				form_driver(form, REQ_NEXT_FIELD); /* Next field */
				form_driver(form, REQ_END_LINE); /* Start at end of any current input in the field */
			}
			break;
		case KEY_UP:
			if (EDITING_BODY()) {
				if (before_row > 0) {
					form_driver(form, REQ_PREV_LINE);
					set_line_status(client, form, before_row);
				} else {
					/* Allow jumping up back to headers, otherwise there is no other way to get back there once we start on the body */
					form_driver(form, REQ_PREV_FIELD);
					form_driver(form, REQ_END_LINE);
				}
			} else if (current_field(form) == fields[0]) {
				/* Don't allow going "up" wrapping around back to body field */
				beep();
			} else {
				form_driver(form, REQ_PREV_FIELD);
				form_driver(form, REQ_END_LINE);
			}
			break;
		case KEY_NPAGE:
			form_driver(form, REQ_SCR_FPAGE);
			set_line_status(client, form, before_row);
			break;
		case KEY_PPAGE:
			if (EDITING_BODY() && before_row < MAIN_PANE_HEIGHT - (NUM_FIELDS - 1)) {
				/* On the first page already, so go to first line */
				form_driver(form, REQ_BEG_FIELD);
			} else {
				form_driver(form, REQ_SCR_BPAGE);
			}
			set_line_status(client, form, before_row);
			break;
		case ctrl('h'): /* Alias for backspace, just in case the user's backspace isn't mapped properly */
		case KEY_BACKSPACE:
			/* By default, if we're at the beginning of the field, we'll go back to the previous field, so prevent that. */
			if (before_col == 0 && before_row == 0) {
				client_debug(5, "At beginning of field, can't backspace");
				beep();
			} else {
				if (before_col > 0) {
					/* We deleted a char from the current line */
					form_driver(form, REQ_DEL_PREV);
				} else if (before_row > 0) {
					client_debug(7, "Deleted current line, shifting rows up");
					form_driver(form, REQ_DEL_PREV);
					/* Don't actually delete the last char on the previous line immediately, that's jarring */
					set_line_status(client, form, before_row);
				}
			}
			break;
		case KEY_DC: /* Delete char: Forward delete */
		case KEY_DL: /* Delete line: Forward delete - this is what is actually sent for me, so use this for forward delete as well */
			if (EDITING_BODY() && END_OF_LINE()) {
				if (before_col) {
					/* We're on a empty line, so we can just yank the current line */
					form_driver(form, REQ_DEL_LINE);
				} else {
					/* We're on a line with text on it, but at the end of it.
					 * We want to delete the line break and move text on the next line
					 * onto this one. */
					form_driver(form, REQ_NEXT_LINE);
					form_driver(form, REQ_DEL_PREV);
				}
				/* Line number has not changed */
			} else {
				form_driver(form, REQ_DEL_CHAR);
			}
			break;
		case 331: /* INSERT */
			overtype = overtype ? 0 : 1;
			form_driver(form, overtype ? REQ_OVL_MODE : REQ_INS_MODE);
			client_set_status_nout(client, overtype ? "OVR" : "INS");
			break;
		case KEY_ENTER:
			if (EDITING_BODY()) {
				if (before_col == 0 && before_row == 0) {
					/* REQ_NEW_LINE doesn't work at the beginning of a field */
					ADD_LINE_BREAK_BEFORE();
					/* We're still on line 0, so no need to update status bar */
				} else {
					ADD_LINE_BREAK();
					client_debug(1, "Added line break...\n");
					set_line_status(client, form, before_row);
				}
			} else {
				form_driver(form, REQ_NEW_LINE); /* For header fields, this automatically goes to the next field */
			}
			break;
		case KEY_HOME:
			GOTO_LINE_BEGIN();
			break;
		case KEY_END:
			form_driver(form, REQ_END_LINE);
			break;
		/* Shifted arrow keys (there are up/down too, but they're not called that).
		 * These should not be assigned exclusive functions, since some terminal emulation modes
		 * do not support shifted arrow keys. */
		case KEY_SLEFT:
		case KEY_SRIGHT:
			break;
		/* CTRL keys - the following are not affected by cbreak: q, s, j, z, c, m, and is the same case as \t*/
		/* In assigning key bindings for the CTRL keys, I have tried to be consistent
		 * with existing uses of these keys in other settings, such as common *nix text editors. */
		case ctrl('w'): /* Cancel and exit */
			goto done;
		case ctrl('e'): /* Go to end of current line */
			form_driver(form, REQ_END_LINE);
			break;
		/* ^R - global refresh screen */
		case ctrl('t'):
		case ctrl('y'):
			break;
		case ctrl('u'): /* Clear line after cursor position */
			form_driver(form, REQ_CLR_EOL);
			break;
		case ctrl('o'): /* Save as draft */
			form_driver(form, REQ_VALIDATION); /* Flush buffer */
			res = save_message(client, fields, &msgc, mdata);
			cleanup_message_constructor(&msgc);
			if (res < 0) {
				goto done;
			} else if (res > 0) {
				client_set_status_nout(client, msgc.error[0] ? msgc.error : "Error saving message");
				beep();
				if (needresize) {
					goto resize;
				}
			} else {
				*outcome = OUTCOME_MESSAGE_SAVED;
				client_set_status_nout(client, "Message saved as draft");
				goto done;
			}
			if (needresize) {
				goto resize;
			}
			break;
		case ctrl('p'):
			break;
		/* 2nd row */
		case ctrl('a'): /* Go to beginning of current line */
			GOTO_LINE_BEGIN();
			break;
		case ctrl('d'): /* Send message */
			form_driver(form, REQ_VALIDATION); /* Flush buffer */
			res = send_message(client, fields, &msgc, mdata);
			cleanup_message_constructor(&msgc);
			if (res < 0) {
				goto done;
			} else if (res > 0) {
				client_set_status_nout(client, msgc.error[0] ? msgc.error : res == 2 ? "Sent, error saving message" : "Error sending message");
				beep();
				if (needresize) {
					goto resize;
				}
			} else {
				*outcome = OUTCOME_MESSAGE_SENT;
				client_set_status_nout(client, "Message sent!");
				if (uid) {
					if (comptype == COMPOSE_REPLY) {
						/* This was a reply to a message in this mailbox.
						 * Store the \Answered flag on that message. */
						struct message *repliedtomsg = get_msg_by_uid(client, uid);
						if (repliedtomsg) {
							client_debug(3, "Marking message with UID %u as \\Answered", uid);
							if (client_idle_stop(client) || client_mark_answered(client, repliedtomsg)) {
								res = -1;
								goto done;
							}
							repliedtomsg->flags |= IMAP_MESSAGE_FLAG_ANSWERED;
						} else {
							client_debug(3, "Can't find message with UID %u to store \\Answered flag", uid);
						}
					} else if (comptype == COMPOSE_FORWARD && client->sel_mbox->keywords_allowed) {
						/* Store $Forwarded */
						struct message *repliedtomsg = get_msg_by_uid(client, uid);
						if (repliedtomsg) {
							client_debug(3, "Marking message with UID %u as $Forwarded", uid);
							if (client_idle_stop(client) || client_store_keyword(client, +1, repliedtomsg, "$Forwarded")) {
								res = -1;
								goto done;
							}
							
							repliedtomsg->flags |= IMAP_MESSAGE_FLAG_ANSWERED;
						} else {
							client_debug(3, "Can't find message with UID %u to store $Forwarded flag", uid);
						}
					}
				}
				goto done;
			}
			if (needresize) {
				goto resize;
			}
			break;
		case ctrl('f'): /* Reserved for find */
			break;
		case ctrl('g'):
			break;
		/* ^H used for backspace */
		case ctrl('k'): /* Clear line after cursor, kill/yank line */
			form_driver(form, REQ_DEL_LINE);
			break;
		case ctrl('l'): /* Clear field */
			form_driver(form, REQ_CLR_FIELD);
			break;
		/* ^X - Toggle mouse support (handled by poll_input) */
		case ctrl('v'):
		case ctrl('b'): /* Go to beginning of field */
			form_driver(form, REQ_BEG_FIELD);
			break;
		case ctrl('n'): /* Go to end of field */
			form_driver(form, REQ_END_FIELD);
			break;
		default:
			if (!isprint(c)) {
				/* Not that the form_driver can't necessarily handle it,
				 * but we want to be sure that we're adding a character to the row length at this point. */
				client_debug(2, "Skipping character %d", c);
			} else if (form_driver(form, c) != E_OK) {
				client_debug(2, "Character %d not handled by form driver", c);
				if (form->curcol == 0) {
					/* We just shifted onto a new line, update the line info */
					set_line_status(client, form, before_row);
				}
			} /* else, success */
			break;
		}
		wnoutrefresh(window);
		doupdate();
	}

done:
	client->cur_win = NULL;
	unpost_form(form);
	free_form(form);
	for (i = 0; i < NUM_FIELDS; i++) {
		free_field(fields[i]);
	}
	delwin(window);
	curs_set(0);
	client->cursor = 0;
	return res;
}
