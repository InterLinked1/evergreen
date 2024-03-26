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
 * \brief Message Viewer
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "evergreen.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <wait.h>
#include <search.h>

struct pager {
	int line;
	int n_lines;
};

static int pad_page(WINDOW *pad, struct pager *restrict pager)
{
	/* Passing 1 starts drawing the pad at the first row, so we can keep the main header and footer visible */
	wnoutrefresh(stdscr);
	pnoutrefresh(pad, pager->line, 0, 1, 0, MAIN_PANE_HEIGHT, COLS);
	doupdate();
	return 0;
}

/* The idea here is that compliant mailers will also end lines with a space when the quote depth of the next line is different,
 * in which case it's not a continuation, it should be treated as a normal line break */
int next_n_quotes(const char *s, int n)
{
	int i;
	for (i = 0; i < n; i++, s++) {
		if (!*s) {
			return 0;
		}
		if (*s != '>') {
			/* This has fewer quotes than we wanted */
			client_debug(9, "Quote depth is %d (less than %d)", i, n);
			return 0;
		}
	}
	if (*s && *s == '>') {
		/* This has MORE quotes than we wanted, so also exclude */
		client_debug(9, "Quote depth is greater than %d", n);
		return 0;
	}
	return 1;
}

#define PLAINTEXT_FLOWED (1 << 0)

/* Skip "soft" new lines that are simply due to format=flowed wrapping */
#define IS_PLAINTEXT_FLOWED_NEWLINE(s, col) ((flags & PLAINTEXT_FLOWED) && col > 1 && *(s - 2) == ' ' && next_n_quotes(s + 1, quote_depth))

static inline __attribute__((always_inline)) const char *get_next_space(const char *restrict s)
{
	const char *next = s + 1;
	if (!*next) {
		return NULL;
	}
	return strchr(next, ' ');
}

static inline __attribute__((always_inline)) int should_wrap_line(const char *restrict s, int col)
{
	/* If we won't be able to fit the next word on this line,
	 * wrap the line here. */
	if (col >= COLS - 1) {
		/* Got no choice... */
		return 1;
	}
	if (col > 0 && *s == ' ' && (col < 1 || *(s - 1) != '>')) { /* Don't wrap right after > though, to prevent quoted material from being separated. */
		const char *next = get_next_space(s);
		if (next) {
			int diff = next - s;
			int cols_left = COLS - 1 - col;
			if (diff > cols_left) {
				/* Wrap text now to prevent splitting word across two lines */
				return 1;
			}
		}
	}
	return 0;
}

/*! \brief Compute how many lines the pad needs to be */
static int pager_add(struct pager *restrict pager, const char *restrict data, size_t len, int flags)
{
	const char *c;
	int flowed_line = 0;
	int col = 0; /* Actual column in source message */
	int outputcol; /* Visual output column on display */
	size_t i;
	int in_quotes = 0, quote_depth = 0;

	outputcol = 0;
	c = data;
	i = 0;

	/* The IMAP BODYSTRUCTURE could tell us how many lines are in the message,
	 * but not how many there are when we wrap them to a custom width,
	 * so we have to count anyways. */

	/* Count lines */
	/* Calculated same as in pad_add, but just count lines, rather than actually printing and formatting */
	for (; i < len; i++, c++, outputcol++, col++) {
		if (*c == '\r') {
			outputcol--; /* We're not drawing anything, and loop post will increment again */
			continue;
		} else if (*c == '\n') {
			if (IS_PLAINTEXT_FLOWED_NEWLINE(c, i)) {
				flowed_line = 1;
				/* If we're in a quote block, eat any quotes that follow,
				 * since we know we're at the same quote depth here */
				c++;
				i++;
				while (*c && *c == '>') {
					c++;
					i++;
				}
				outputcol--; /* We didn't actually draw the newline, and the loop post will increment again */
			} else {
				outputcol = -1;
				quote_depth = 0;
				flowed_line = 0;
				pager->n_lines++;
			}
			col = -1; /* Since loop post takes us back to 0 for next iteration */
		} else {
			if (col == 0 && *c == '>' && !flowed_line) {
				in_quotes = quote_depth = 1;
				continue;
			}
			if (should_wrap_line(c, outputcol)) {
				outputcol = -1;
				pager->n_lines++;
				if (quote_depth) {
					outputcol += quote_depth + 1;
				}
			} else {
				if (in_quotes) {
					if (*c == '>') {
						quote_depth++;
						continue;
					} else {
						in_quotes = 0;
					}
				}
				if (*c == '\t') {
					outputcol += 7;
				}
			}
		}
	}

	return 0;
}

/*! \brief Actually add text to the pad, respecting format=flowed formatting to properly line break and quote messages */
static int pad_add(WINDOW *pad, const char *restrict data, size_t len, int flags)
{
	size_t i;
	const char *c;
	int flowed_line = 0;
	int col = 0; /* Actual column in source message */
	int x = 0, y = 0;
	int outputcol; /* Visual output column on display */
	int j;
	int in_quotes = 0, quote_depth = 0;

	outputcol = 0;
	c = data;
	i = 0;

/* The default ACS_VLINE is x, which is pointless, not even close to a vertical bar.
 * | doesn't look much better, just stick with the authentic '>', I suppose... */
#define QUOTE_BAR() waddch(pad, '>')

	/* We can't output carriage returns to the screen */
	for (; i < len; i++, c++, outputcol++, col++) {
		getyx(pad, y, x);
		if (x != outputcol) {
			client_debug(1, "WARNING! outputcol is %d, but actually at row %d, col %d? (char %d: '%c')", outputcol, y, x, *c, isprint(*c) ? *c : ' ');
			if (x <= 127) {
				assert(x <= outputcol);
			} else if (x > outputcol) {
				/* Still a bug, but some Unicode characters make take up more than 1 column, and hard to do anything about that... just autocorrect. */
				outputcol = x;
			}
		}
		if (*c == '\r') {
			outputcol--; /* We're not drawing anything, and loop post will increment again */
			continue;
		} else if (*c == '\n') {
			if (IS_PLAINTEXT_FLOWED_NEWLINE(c, i)) {
				client_debug(9, "format=flowed line continuation");
				flowed_line = 1;
				/* If we're in a quote block, eat any quotes that follow,
				 * since we know we're at the same quote depth here */
				c++;
				i++;
				while (*c && *c == '>') {
					c++;
					i++;
				}
				outputcol--; /* We didn't actually draw the newline, and the loop post will increment again */
			} else {
				waddch(pad, *c);
				outputcol = -1;
				quote_depth = 0;
				flowed_line = 0;
				wattroff(pad, COLOR_PAIR(10));
			}
			col = -1; /* Since loop post takes us back to 0 for next iteration */
		} else {
			if (col == 0) {
				if (*c == '>' && !flowed_line) {
					in_quotes = quote_depth = 1;
					wattron(pad, COLOR_PAIR(10)); /* Make quoted text a different color to distinguish immediate reply from anything it quoted */
					QUOTE_BAR();
					client_debug(9, "This line is quoted...");
					continue;
				}
			}
			if (should_wrap_line(c, outputcol)) {
				outputcol = -1;
				waddch(pad, '\n');
				client_debug(9, "Wrapping text since out of room on this row");
				if (quote_depth) {
					/* If we're in quoted material, output the right number of quotes */
					client_debug(9, "Inserting quote markers since quote depth is %d", quote_depth);
					for (j = 0; j < quote_depth; j++) {
						QUOTE_BAR();
					}
					waddch(pad, ' '); /* Space between quote bar and text */
					outputcol += quote_depth + 1;
				}
			} else {
				if (in_quotes) {
					if (*c == '>') {
						quote_depth++;
						QUOTE_BAR();
						continue;
					} else {
						client_debug(9, "Replaced %d quotes with quotes", quote_depth);
						in_quotes = 0;
					}
				}
				if (*c == '\t') {
					/* Width is functionally 8, not 1, so add 7 more */
					outputcol += 7;
				}
				waddch(pad, *c);
			}
		}
	}
	wattroff(pad, COLOR_PAIR(10));
	return 0;
}

static int pad_add_color_col(WINDOW *pad, const char *restrict data, size_t len, int cp1, int cp2, int coldelim)
{
	size_t i;
	int col = 0;
	const char *c;

	/* We can't output carriage returns to the screen */
	for (c = data, i = 0; i < len; i++, c++) {
		if (*c != '\r') {
			if (col == 0) {
				wattron(pad, COLOR_PAIR(cp1));
			} else if (col == coldelim) {
				wattron(pad, COLOR_PAIR(cp2));
			}
			waddch(pad, *c);
			/* We don't care about COLS, since line wrapped lines should maintain second color all the way through,
			 * even if at col positions less than coldelim on the terminal. */
			if (*c == '\n') {
				col = 0;
			} else {
				col++;
			}
		}
	}
	wattroff(pad, COLOR_PAIR(cp1));
	wattroff(pad, COLOR_PAIR(cp2));
	return 0;
}

/* Should be a little longer than the longest header name, and not much longer */
#define HEADER_WIDTH 12

#define HEADER_FMTSTR "%*.*s%s%s"
#define HEADER_FMT(hdr, name) hdr ? HEADER_WIDTH : 0, hdr ? HEADER_WIDTH : 0, hdr ? name : "", hdr ? hdr : "", hdr ? "\n" : ""

static int format_headers(struct message *msg, struct message_data *restrict mdata)
{
	int res;
	char date[28] = ""; /* This is the exact amount of space required, including NUL */
	char received[28] = "";
	const char *datestr = date;
	const char *recvstr = received;
	/* No padding before single digit day of months or hours */
	strftime(date, sizeof(date), "%a %b %-e %-l:%M:%S %P %Y", &msg->date);
	strftime(received, sizeof(received), "%a %b %-e %-l:%M:%S %P %Y", &msg->intdate);
	/* Print out these headers, if they exist */
	res = asprintf(&mdata->headersfmt,
		HEADER_FMTSTR
		HEADER_FMTSTR
		HEADER_FMTSTR
		HEADER_FMTSTR
		HEADER_FMTSTR
		HEADER_FMTSTR
		HEADER_FMTSTR
		"\n", /* End of headers */
		HEADER_FMT(datestr, "Sent "),
		HEADER_FMT(recvstr, "Received "),
		HEADER_FMT(msg->from, "From "),
		HEADER_FMT(msg->subject, "Subject "),
		HEADER_FMT(mdata->to, "To "),
		HEADER_FMT(mdata->cc, "Cc "),
		HEADER_FMT(mdata->replyto, "Reply-To ")
		);
	if (res > 0) {
		mdata->headersfmtlen = (size_t) res;
	}
	return res < 0 ? -1 : 0;
}

static ssize_t full_write(int fd, char *restrict buf, size_t len)
{
	char *pos = buf;
	ssize_t written = 0;
	do {
		ssize_t res = write(fd, pos, len);
		if (res < 0) {
			return res;
		}
		written += res;
		pos += res;
		len -= res;
	} while (len > 0);
	return written;
}

int convert_html_to_pt(struct client *client, struct message_data *mdata)
{
	ssize_t res;
	char sizebuf[6];
	pid_t pid;
	int status;
	int readpipe[2], writepipe[2];
	char *converted = NULL;
	size_t converted_len;
	/* html2text: It's not perfect, but it's something... some emails that have lots of sloppy HTML
	 * don't render the best with this, but it's still better than looking at HTML source...
	 * 
	 * width: It doesn't hurt to go over, since we'll wrap, but wrapping too early is bad, since that won't
	 * make full use of the screen. So output should definitely be at least as big as the current screen. */
	char *const argv[] = { "html2text", "-width", sizebuf, NULL };

	/* Convert HTML to plain text, using html2text:
	 * https://github.com/marado/html2text/tree/master
	 */

	if (pipe(readpipe)) {
		client_error("pipe failed: %s", strerror(errno));
		return -1;
	} else if (pipe(writepipe)) {
		client_error("pipe failed: %s", strerror(errno));
		close(readpipe[0]);
		close(readpipe[1]);
		return -1;
	}

	snprintf(sizebuf, sizeof(sizebuf), "%d", COLS);

	pid = fork();
	if (pid < 0) {
		client_error("fork failed: %s", strerror(errno));
		return -1;
	} else if (!pid) {
		close(readpipe[0]);
		close(writepipe[1]);
		if (dup2(writepipe[0], STDIN_FILENO) == -1 || dup2(readpipe[1], STDOUT_FILENO) == -1) {
			_exit(errno);
		}
		close(STDERR_FILENO);
		execvp("html2text", argv);
		_exit(errno);
	} /* else, parent: */
	close(writepipe[0]);
	close(readpipe[1]);

	/* Send all input data on STDIN */
	res = full_write(writepipe[1], mdata->html_body, mdata->html_size);
	close(writepipe[1]);
	if (waitpid(pid, &status, 0) == -1) {
		client_error("waitpid failed: %s", strerror(errno));
	} else {
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 0) {
				res = 0;
			} else {
				client_debug(1, "html2text failed: %s", strerror(WEXITSTATUS(status)));
				if (WEXITSTATUS(status) == ENOENT) {
					client_set_status_nout(client, "html2text not installed!");
				}
				res = -1;
			}
		} else {
			client_debug(1, "html2text did not exit normally");
			res = -1;
		}
		if (res != -1) {
			char buf[BUFSIZ];
			for (;;) {
				res = read(readpipe[0], buf, sizeof(buf));
				/* Shouldn't be too many reallocs, since hopefully
				 * we're reading fairly large chunks at a time. */
				if (res <= 0) {
					break;
				}
				APPEND_STR(converted, buf, res);
			}
			if (res < 0) {
				client_error("read failed: %s", strerror(errno));
			}
		}
	}
	close(readpipe[0]);
	if (!converted) {
		return -1;
	}

	/* Swap */
	converted_len = strlen(converted);
	client_debug(5, "Successfully parsed %lu-byte HTML body into %lu-byte plain text representation", mdata->html_size, converted_len);
	free(mdata->html_body);
	mdata->html_body = converted; /* Steal reference */
	mdata->html_size = converted_len;
	return 0;
}

int construct_message_data(struct client *client, struct message *msg, struct message_data *restrict mdata, enum view_message_type *restrict mtype)
{
	*mtype = VIEW_MESSAGE_PT;

	/* FETCH the entire RFC822 message */
	/*! \todo Would probably make sense to use BODYSTRUCTURE to just extract the plain text / HTML components directly */
	if (client_fetch(client, msg, mdata)) {
		return -1;
	}

#ifdef AUTO_MARK_SEEN
	/* Since we got the body without peeking, if the message was previously unseen,
	 * it's now seen, and if it was previously recent, it's no longer. */
	mark_message_read(client->sel_mbox, msg);
	display_mailbox_info(client); /* We need to update the stats, too */
#endif

	/* Parse out the plain text or HTML message body.
	 * Ask for the plain text version first, but fall back to HTML if that's not available. */
	if (client_fetch_mime(mdata, 1, 0)) { /* Only parse headers on first pass */
		*mtype = VIEW_MESSAGE_HTML;
		if (client_fetch_mime(mdata, 0, 1)) {
			/* Message missing both pt and html components.
			 * Go ahead and display the headers,
			 * and allowing viewing source if desired. */
			*mtype = VIEW_MESSAGE_EMPTY;
		} else {
			convert_html_to_pt(client, mdata);
		}
	}

	format_headers(msg, mdata); /* Generate viewable headers for message */

	/* Save off anything else we might need about the message */
	mdata->date = msg->date;

	return 0;
}

int view_message(struct client *client, struct pollfd *pfds, struct message *msg)
{
	WINDOW *pad = NULL;
	char footer[128];
	int res = 0;
	int flags = 0;
	enum view_message_type mtype, default_mtype;
	struct message_data mdata;
	struct pager pager_stack, *pager = &pager_stack;
	int x, y;
	int max_pager_line;
	uint32_t seqno = msg->seqno, uid = msg->uid; /* Save seqno and UID off */

	memset(&mdata, 0, sizeof(mdata));
	if (construct_message_data(client, msg, &mdata, &mtype)) {
		return -1;
	}
	default_mtype = mtype;

	/* No longer used in this function, and if the current message is expunged, would become invalid.
	 * The only small downside is the sequence number could change while we're viewing the message,
	 * (if expunges happen from a different client in this mailbox). */
	msg = NULL;

mknewpad:
	flags |= mtype == VIEW_MESSAGE_PT && mdata.pt_flowed ? PLAINTEXT_FLOWED : 0;
	if (mtype == VIEW_MESSAGE_PT && !mdata.pt_body) {
		/* Didn't parse plain text the first time, so parse now if needed */
		if (client_fetch_mime(&mdata, 0, 0)) {
			beep();
			client_set_status_nout(client, "No PT version");
			mtype = default_mtype;
			goto display;
		}
	} else if (mtype == VIEW_MESSAGE_HTML && !mdata.html_body) {
		/* Didn't parse HTML version the first time, so parse now if needed */
		if (client_fetch_mime(&mdata, 0, 1)) {
			beep();
			client_set_status_nout(client, "No HTML version");
			mtype = default_mtype;
			goto display;
		}
		convert_html_to_pt(client, &mdata);
	}
	memset(&pager_stack, 0, sizeof(pager_stack));
	if (mtype == VIEW_MESSAGE_PT) {
		/* Calculate how big the pad needs to be */
		if (mdata.headersfmt && pager_add(pager, mdata.headersfmt, mdata.headersfmtlen, 0)) {
			client_cleanup_message(&mdata);
			return -1;
		}
		if (pager_add(pager, mdata.pt_body, mdata.pt_size, flags)) {
			client_cleanup_message(&mdata);
			return -1;
		}
	} else if (mtype == VIEW_MESSAGE_HTML) {
		if (mdata.headersfmt && pager_add(pager, mdata.headersfmt, mdata.headersfmtlen, 0)) {
			client_cleanup_message(&mdata);
			return -1;
		}
		if (pager_add(pager, mdata.html_body, mdata.html_size, flags)) {
			client_cleanup_message(&mdata);
			return -1;
		}
	} else { /* VIEW_MESSAGE_SOURCE */
		if (pager_add(pager, mdata.msg_body, mdata.msg_size, flags)) {
			client_cleanup_message(&mdata);
			return -1;
		}
	}

	if (mtype == VIEW_MESSAGE_PT || mtype == VIEW_MESSAGE_HTML) {
		pager->n_lines += mdata.num_attachments ? mdata.num_attachments + 2 : 0;
	}

	/* Free previous pad, if needed */
	if (pad) {
		delwin(pad);
	}

	/* Since we set the pad width to COLS, it will automatically wrap text for us.
	 * However, that will eat into the height of the pad, so we shouldn't let things auto-wrap,
	 * we should add line wrappings, and increase the line count, manually. */
	pad = newpad(pager->n_lines > MAIN_PANE_HEIGHT ? pager->n_lines : MAIN_PANE_HEIGHT, COLS);
	if (!pad) {
		client_error("pad failed");
		client_cleanup_message(&mdata);
		return -1;
	}
	keypad(pad, TRUE);

	/* Draw all the data to the pad */
	if (mtype == VIEW_MESSAGE_PT) {
		/* Make all the headers cyan/green on black, to differentiate them, and then we don't need to waste a line drawing a separator */
		if (mdata.headersfmt && pad_add_color_col(pad, mdata.headersfmt, mdata.headersfmtlen, 8, 5, HEADER_WIDTH)) {
			res = -1;
			goto done;
		}
		if (pad_add(pad, mdata.pt_body, mdata.pt_size, flags)) {
			res = -1;
			goto done;
		}
		snprintf(footer, sizeof(footer), "#%u | UID %u | PT | %lu B", seqno, uid, mdata.pt_size);
	} else if (mtype == VIEW_MESSAGE_HTML) {
		/* Make all the headers cyan/green on black, to differentiate them, and then we don't need to waste a line drawing a separator */
		if (mdata.headersfmt && pad_add_color_col(pad, mdata.headersfmt, mdata.headersfmtlen, 8, 5, HEADER_WIDTH)) {
			res = -1;
			goto done;
		}
		if (pad_add(pad, mdata.html_body, mdata.html_size, flags)) {
			res = -1;
			goto done;
		}
		snprintf(footer, sizeof(footer), "#%u | UID %u | HTML | %lu B", seqno, uid, mdata.html_size);
	} else { /* VIEW_MESSAGE_SOURCE */
		if (pad_add(pad, mdata.msg_body, mdata.msg_size, flags)) {
			res = -1;
			goto done;
		}
		snprintf(footer, sizeof(footer), "#%u | UID %u | source | %lu B", seqno, uid, mdata.msg_size);
	}

	client_debug(3, "Message has %d attachment%s", mdata.num_attachments, mdata.num_attachments == 1 ? "" : "s");
	if (mdata.num_attachments && (mtype == VIEW_MESSAGE_PT || mtype == VIEW_MESSAGE_HTML)) {
		/* Blank line, then # attachments, then one per line */
		char atbuf[256];
		size_t atlen;
		int atnum = 0;
		struct attachment *attachment;
		pad_add(pad, "\n", 1, 0); /* Add newlines separately since colors are disabled after a newline by pad_add */
		atlen = (size_t) snprintf(atbuf, sizeof(atbuf), "=== Attachments: %d\n", mdata.num_attachments);
		wattron(pad, COLOR_PAIR(8));
		pad_add(pad, atbuf, atlen, 0);
		wattroff(pad, COLOR_PAIR(8));
		attachment = mdata.attachments;
		do {
			char sizebuf[8];
			wattron(pad, COLOR_PAIR(5));
			format_size(attachment->size, sizebuf, sizeof(sizebuf));
			atlen = (size_t) snprintf(atbuf, sizeof(atbuf), "  [%d] %6s %s\n", atnum + 1, sizebuf, attachment->name);
			pad_add(pad, atbuf, atlen, 0);
			atnum++;
		} while ((attachment = attachment->next));
		wattroff(pad, COLOR_PAIR(5));
	}

	/* Check that pager_add and pad_add agreed about how big the pad should be */
	getyx(pad, y, x);
	(void) x; /* Not used */
	if (y < pager->n_lines - 1) {
		client_debug(5, "Pager has %d lines, but only drew %d?", pager->n_lines, y);
	}

	client_set_status_nout(client, footer); /* pad_page calls doupdate() */

display:
	max_pager_line = pager->n_lines - MAIN_PANE_HEIGHT;
	for (;;) {
		int c;
		MEVENT mevent;
		pad_page(pad, pager);
		c = __poll_input(client, pfds, 0, BUTTON4_PRESSED | BUTTON5_PRESSED); /* Accept mouse input, but only scrolling */
		switch (c) {
		case 'Q':
		case -1:
			res = -1;
			goto done;
		case 'q':
		case KEY_ESCAPE:
			goto done;
		case KEY_BACKSPACE:
			if (mtype != default_mtype) {
				/* "Go back" to previous */
				mtype = default_mtype;
				goto mknewpad;
			}
			goto done;
		case 'h':
		case '?':
		case KEY_HELP:
			SUB_MENU_PRE;
			res = show_help_menu(client, pfds, HELP_GLOBAL | HELP_VIEWER);
			SUB_MENU_POST;
			break;
		case 'U': /* Mark unread and return */
		case 'u': /* Mark unread */
		case 's': /* Mark seen */
		case 'F': /* Toggle flagged/unflagged */
		case 'r': /* Reply */
		case 'R': /* Reply All */
		case 'f': /* Forward */
		case 'c': /* Copy to mailbox */
		case 'C': /* Copy to last dest mailbox */
		case 'm': /* Move to mailbox */
		case 'M': /* Move to last dest mailbox */
		case 'l': /* Display last destination mailbox */
		case 'j': /* Move to junk */
		case 't': /* Move to trash */
		case KEY_DL: /* Same as 't' */
			/* We need to get a handle on msg again, in case it disappeared during IDLE.
			 * We should do so by UID, not sequence number, to guarantee it's this message. */
			msg = get_msg_by_uid(client, uid);
			if (!msg) {
				/* Could happen, if expunged while we were reading the message */
				client_warning("Message with UID %u no longer exists", uid);
			} else {
				res = handle_message_op(client, pfds, msg, &mdata, c);
				if (res > 1) {
					/* If it returns 2, stop displaying message but still return 0. */
					res = 0;
					goto done;
				} else if (res < 0) {
					goto done;
				} else { /* res is 0 or 1 */
					res = 0;
				}
				doupdate(); /* Update status bar */
				msg = NULL;
			}
			break;
		case KEY_LEFT: /* Previous message */
		case KEY_RIGHT: /* Next message */
		case KEY_SLEFT: /* Previous unread message */
		case KEY_SRIGHT: /* Next unread message */
			/* Allow going between messages */
			res = c;
			goto done;
		case KEY_RESIZE:
resize:
			if (mtype == VIEW_MESSAGE_HTML) {
				/* If the screen just got larger, reconvert the HTML to plain text,
				 * in case the screen just got larger and we should now wrap at longer
				 * line length. */
				convert_html_to_pt(client, &mdata);
			}
			goto mknewpad; /* Make new pad with the new amount of columns, but keep our line number */
		case KEY_ENTER:
		case KEY_DOWN:
down:
			/* If there is content beneath the current viewport, allow scrolling down to it */
			if (pager->line < max_pager_line) {
				pager->line++;
			} else {
				beep();
			}
			break;
		case KEY_UP:
up:
			if (pager->line > 0) {
				pager->line--;
			} else {
				beep();
			}
			break;
		case KEY_PPAGE:
			/* Page up */
			if (pager->line > 0) {
				pager->line -= MAIN_PANE_HEIGHT;
				if (pager->line < 0) {
					pager->line = 0;
				}
			} else {
				beep();
			}
			break;
		case KEY_NPAGE:
		case ' ':
			/* Page down */
			/* If there is content beneath the current viewport, allow paging down to it */
			if (pager->line < max_pager_line) {
				pager->line += MAIN_PANE_HEIGHT;
				if (pager->line > max_pager_line) {
					pager->line = max_pager_line;
					client_debug(6, "pager->line limited to %d/%d (MH %d)", pager->line, pager->n_lines, MAIN_PANE_HEIGHT);
				}
			} else {
				beep();
			}
			client_debug(6, "pager->line now %d/%d", pager->line, pager->n_lines);
			break;
#define SET_NEW_VIEW_MTYPE(typ) \
	if (mtype == typ) { \
		beep(); \
	} else { \
		mtype = typ; \
		goto mknewpad; \
	}
		case 'P': /* View plain text version, if available */
			SET_NEW_VIEW_MTYPE(VIEW_MESSAGE_PT);
			break;
		case 'H': /* View HTML version, if available */
			SET_NEW_VIEW_MTYPE(VIEW_MESSAGE_HTML);
			break;
		case 'S': /* View message source */
			SET_NEW_VIEW_MTYPE(VIEW_MESSAGE_SOURCE);
			break;
#undef SET_NEW_VIEW_MTYPE
		case KEY_MOUSE:
			if (getmouse(&mevent) == OK) {
				client_debug(7, "Mouse event at row %d, col %d, SHIFT: %d, CTRL: %d, ALT: %d", mevent.y, mevent.x,
					mevent.bstate & BUTTON_SHIFT ? 1 : 0, mevent.bstate & BUTTON_CTRL ? 1 : 0, mevent.bstate & BUTTON_ALT ? 1 : 0);
				if (mevent.bstate & BUTTON4_PRESSED) {
					/* Scroll up */
					goto up;
				} else if (mevent.bstate & BUTTON5_PRESSED) {
					/* Scroll down */
					goto down;
				}
			} else {
				client_debug(8, "Failed to get mouse info");
				doupdate();
			}
			break;
		default:
			beep();
			break;
		}
	}

done:
	delwin(pad);
	client_cleanup_message(&mdata);
	return res;
}
