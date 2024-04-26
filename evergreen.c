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

/*!
 * \note Supports the following features and functionality:
 *
 * IMAP
 * - RFC 2177 IDLE
 * - Stores \Answered and $Forwarded flags
 * - Save and resume drafts
 * - Message forwarding
 *
 * SMTP
 * - RFC 1870 SIZE declaration
 *
 * Email address management
 * - Multiple identities, by address and wildcard domain
 * - Don't reply to one our identities when replying all
 * - Automatically from matching identity in original recipient list
 *
 * RFC822 message formatting
 * - format=flowed plaintext message support (viewing and composing)
 * - window resizing and 80+ column support
 * - view HTML emails as plain text formatted
 * - Preserves threading in replies using References and In-Reply-To
 *
 * Notable missing features
 * - Message sorting/search/threading in message pane view
 * - Ability to create/delete folders
 * - Multi-account support
 * - Autocompletion/suggestion of addresses
 *
 * Currently missing, but soon to be added (hopefully):
 * - Honoring read receipts (configurable)
 * - Full attachment support (upload from disk, download/view attachments, forward message with its attachments)
 *      Ability to do disk operations (upload/download) needs to be disableable by a runtime flag, for restricted environments.
 * - IMAP NOTIFY + periodically issue STATUS for all mailboxes
 * - Create/delete/move mailboxes
 * - BURL IMAP support
 * - NNTP support?
 */

/*!
 * \note This codebase includes some code from LBBS (Lightweight Bulletin Board System),
 * (mostly based on code in mod_webmail, or other utility functions).
 * Such code is included here under the same license.
 */

#include "evergreen.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>

#include <sys/resource.h> /* use rlimit */

enum {
	CURSES_NOT_RUNNING,
	CURSES_INITIALIZING,
	CURSES_RUNNING,
	CURSES_CLEANING_UP,
	CURSES_ENDED,
};

static int ncurses_running = CURSES_NOT_RUNNING; 
static FILE *log_fp = NULL;
static int debug_level = 0;
static int event_fd = -1;

void safe_strncpy(char *restrict dst, const char *restrict src, size_t size)
{
	while (*src && size) {
		*dst++ = *src++;
		size--;
	}
	if (unlikely(!size)) {
		dst--;
	}
	*dst = '\0';
}

static void client_set_permstatus(struct client *client, const char *s)
{
	wmove(client->win_footer, 0, 0);
	wclrtoeol(client->win_footer); /* Clear line */
	/* Write message to status bar (footer) */
	mvwaddstr(client->win_footer, 0, 0, s);
	wnoutrefresh(client->win_footer);
}

static void client_set_status(struct client *client, const char *s)
{
	wmove(client->win_footer, 0, STATUS_BAR_START_COL);
	wclrtoeol(client->win_footer); /* Clear line */
	/* Write message to status bar (footer) */
	mvwaddstr(client->win_footer, 0, STATUS_BAR_START_COL, s);
	wrefresh(client->win_footer);
}

void client_set_status_nout(struct client *client, const char *s)
{
	wmove(client->win_footer, 0, STATUS_BAR_START_COL);
	wclrtoeol(client->win_footer); /* Clear line */
	/* Write message to status bar (footer) */
	mvwaddstr(client->win_footer, 0, STATUS_BAR_START_COL, s);
	wnoutrefresh(client->win_footer);
}

static void client_clear_status(struct client *client)
{
	wmove(client->win_footer, 0, STATUS_BAR_START_COL);
	wclrtoeol(client->win_footer); /* Clear line */
	wnoutrefresh(client->win_footer);
}

void __attribute__ ((format (printf, 7, 8))) __client_log(struct client *client, int loglevel, int level, const char *file, int lineno, const char *func, const char *fmt, ...)
{
	int len;
	va_list ap;
	char datestr[21];
	char logminibuf[512];
	char *buf = logminibuf;
	int dynamic = 0;

	if (loglevel == LOG_DEBUG && level > debug_level) {
		return;
	}

	va_start(ap, fmt);
	len = vsnprintf(logminibuf, sizeof(logminibuf), fmt, ap);
	va_end(ap);

	if (len >= (int) sizeof(logminibuf) - 1) {
		/* Too large for stack allocated buffer. Dynamically allocate it. */
		dynamic = 1;
		buf = malloc((size_t) len + 2); /* + room for newline and NUL */
		if (!buf) {
			return;
		}
		va_start(ap, fmt);
#undef vsprintf
		vsprintf(buf, fmt, ap); /* vsprintf is safe, vsnprintf is unnecessary here */
		va_end(ap);
	}

	if (ncurses_running == CURSES_RUNNING) {
		if (loglevel != LOG_DEBUG) {
			client_set_status(client, buf);
		}
	} else if (ncurses_running == CURSES_NOT_RUNNING) {
		buf[len] = '\n'; /* Change NUL to newline */
		fwrite(buf, 1, len + 1, stderr);
	}

	if (log_fp) {
		time_t lognow;
		struct tm logdate;
		struct timeval now;
		int datelen;
		gettimeofday(&now, NULL);
		lognow = time(NULL);
		localtime_r(&lognow, &logdate);
		datelen = strftime(datestr, sizeof(datestr), "%Y-%m-%d %T ", &logdate);

		fwrite(datestr, 1, datelen, log_fp);
		fprintf(log_fp, "%s:%d [%s] ", file, lineno, func);
		buf[len] = '\n'; /* Change NUL to newline, if we didn't already */
		fwrite(buf, 1, len + 1, log_fp);
#ifdef DEBUG_MODE
		/* Flush log messages prior to crash, so we don't lose anything */
		fflush(log_fp);
#else
		if (loglevel == LOG_ERROR || loglevel == LOG_WARNING) {
			fflush(log_fp);
		}
#endif
	}

	if (dynamic) {
		free(buf);
	}
}

static void window_cleanup(struct client *client)
{
	delwin(client->win_header);
	delwin(client->win_folders);
	delwin(client->win_main);
	delwin(client->win_footer);
}

static int client_term_cleanup(struct client *client)
{
	ncurses_running = CURSES_CLEANING_UP;

	cleanup_folder_menu(client);
	cleanup_message_menu(client);
	window_cleanup(client);
	endwin();

	ncurses_running = CURSES_ENDED;

	free_folder_items(client);
	free_message_items(client);
	free_cached_messages(client);
	return 0;
}

#define COLOR_PAIR_MESSAGES 1
#define COLOR_PAIR_FOLDERS 2

static inline void setup_header_footer(struct client *client)
{
	client->win_header = newwin(1, COLS, 0, 0); /* Top */
	client->win_footer = newwin(1, COLS, LINES - 1, 0); /* Bottom */
	wbkgd(client->win_header, COLOR_PAIR(3));
	wbkgd(client->win_footer, COLOR_PAIR(3));

	refresh(); /* Needs to be done before header setup */

	/* Set up header */
	mvwaddstr(client->win_header, 0, 0, EVERGREEN_PROGNAME);
	wnoutrefresh(client->win_header);
}

/*! \brief Set up the top-level ncurses windows */
static int setup_interface(struct client *client)
{
	/* nlines, ncols, begin_y, begin_x */
	setup_header_footer(client);
	client->win_folders = newwin(MAIN_PANE_HEIGHT, LIST_PANE_WIDTH, 1, 0);
	client->win_main = newwin(MAIN_PANE_HEIGHT, MAIN_PANE_WIDTH, 1, LIST_PANE_WIDTH);

	/* Set colors, since we have a 4-coloring, so border is necessary */
	/* These colors here apply to the base windows themselves, not any subwindows (e.g. menus) created in them */
	wbkgd(client->win_main, COLOR_PAIR(COLOR_PAIR_MESSAGES));
	wbkgd(client->win_folders, COLOR_PAIR(COLOR_PAIR_FOLDERS));
	return 0;
}

/*! \brief Redraw header/footer (for if a submenu resizes) */
static void redraw_header_footer(struct client *client)
{
	client_debug(6, "Redrawing header/footer");
	delwin(client->win_header);
	delwin(client->win_folders);
	setup_header_footer(client);
	wnoutrefresh(client->win_header);
	wnoutrefresh(client->win_footer);
	display_mailbox_info(client);
}

/*! \brief Initialize ncurses on startup */
static int client_term_init(struct client *client)
{
	ncurses_running = CURSES_INITIALIZING;

	initscr();

	if (COLS < 80) {
		client_error("Terminal must have at least 80 cols");
		return -1;
	}

	cbreak();
#ifdef USE_NONL
	nonl();
#endif
    noecho();
	keypad(stdscr, TRUE); /* Enable keypad for function key interpretation (escape sequences) */
	curs_set(0); /* Disable cursor */
	start_color(); /* Enable colors */

	/* Since menus are by default white on black,
	 * keep the first two that way for consistency. */

	init_pair(1, COLOR_WHITE, COLOR_BLACK);
	init_pair(2, COLOR_WHITE, COLOR_BLACK);
	init_pair(3, COLOR_CYAN, COLOR_BLUE);
	init_pair(4, COLOR_WHITE, COLOR_CYAN);
	init_pair(5, COLOR_GREEN, COLOR_BLACK);
	init_pair(6, COLOR_CYAN, COLOR_BLACK);
	init_pair(7, COLOR_CYAN, COLOR_BLACK);
	init_pair(8, COLOR_MAGENTA, COLOR_BLACK);
	init_pair(9, COLOR_WHITE, COLOR_BLUE);
	init_pair(10, COLOR_RED, COLOR_BLACK); /* Quoted text font for viewer */

	clear();
	client_debug(1, "Terminal dimensions are %d rows, %d cols", LINES, COLS);

	setup_interface(client);
	doupdate();

	ncurses_running = CURSES_RUNNING;
	return 0;
}

static void set_focus(struct client *client, int f)
{
	if (client->focus != f) {
		client_debug(5, "Setting window focus to %d", f);
		client->focus = f;
	}
}

void format_size(size_t size, char *restrict buf, size_t len)
{
	if (SIZE_KB(size) < 1) {
		snprintf(buf, len, "%luB", size);
	} else if (SIZE_MB(100) < 100) {
		snprintf(buf, len, "%luK", SIZE_KB(size));
	} else {
		snprintf(buf, len, "%luM", SIZE_MB(size));
	}
}

void display_mailbox_info(struct client *client)
{
	char quota[32] = "";
	char sizebuf[22];
	struct mailbox *mbox = client->sel_mbox;
	char buf[STATUS_BAR_START_COL + sizeof(sizebuf)]; /* Can't display more than this, so limit the buf to this + sizebuf for snprintf truncation warning */

	if (client->quota_limit) {
		if (SIZE_MB(client->quota_used) >= 10 || SIZE_MB(client->quota_limit) > 100) {
			snprintf(quota, sizeof(quota), " [%d/%dM]", SIZE_MB(client->quota_used), SIZE_MB(client->quota_limit));
		} else {
			snprintf(quota, sizeof(quota), " [%d/%dK]", client->quota_used, client->quota_limit);
		}
	}
	format_size(mbox->size, sizebuf, sizeof(sizebuf));
	if (COLS >= MIN_COLS_FOR_EXPANDED_MAILBOX_STATS) {
		snprintf(buf, sizeof(buf), "%d (%dU, %dR), %s%s, %dN/%dV", mbox->total, mbox->unseen, mbox->recent, sizebuf, quota, mbox->uidnext, mbox->uidvalidity);
	} else {
		snprintf(buf, sizeof(buf), "%d (%dU, %dR), %s%s", mbox->total, mbox->unseen, mbox->recent, sizebuf, quota);
	}
	client_set_permstatus(client, buf);
}

/*! \note buf must be at least size NUM_IMAP_MESSAGE_FLAGS + 1 (to hold all flags) */
static void build_flags_str(struct message *msg, char *restrict buf)
{
	char *p = buf;

	/* Order flags from most significant/interesting to least... */
	if (msg->flags & IMAP_MESSAGE_FLAG_FLAGGED) {
		*p++ = 'F';
	}
	if (msg->flags & IMAP_MESSAGE_FLAG_DELETED) {
		*p++ = 'T'; /* Trashed */
	}
	if (msg->flags & IMAP_MESSAGE_FLAG_ANSWERED) {
		*p++ = 'A';
	}
	if (msg->flags & IMAP_MESSAGE_FLAG_DRAFT) {
		*p++ = 'D';
	}
	/* We already have a column for recent and seen/unseen (*), so this is the least important */
	if (msg->flags & IMAP_MESSAGE_FLAG_RECENT) {
		*p++ = 'R';
	}
	if (msg->flags & IMAP_MESSAGE_FLAG_SEEN) {
		*p++ = 'S';
	}
	*p = '\0';
}

static struct message *get_selected_message(struct client *client)
{
	/* This is constant time, instead of using get_msg, which
	 * could take O(n/2) time, where n is FETCHLIST_INTERVAL. */
	struct message *msg;
	ITEM *selection = current_item(client->message_list.menu);
	msg = item_userptr(selection);
	assert(msg != NULL);
	return msg;
}

/* \note doupdate() must be called after calling this function */
static void display_message_info(struct client *client, struct message *msg)
{
	/* Find the message that is selected. */
	char buf[STATUS_BAR_WIDTH + 1]; /* This is all that can be displayed, so no point in using a buffer any larger */
	char flags[NUM_IMAP_MESSAGE_FLAGS + 1];
	char *pos = buf;
	size_t len;
	int i;

	if (!msg) {
		msg = get_selected_message(client);
		assert(msg != NULL);
	}

	/* Update status bar with more message info */
	build_flags_str(msg, flags);
	len = snprintf(buf, sizeof(buf), "#%d | UID %d [%s", msg->seqno, msg->uid, flags);
	pos += len;
	for (i = 0; i < client->sel_mbox->num_keywords; i++) { /* Check with mailbox keywords are associated this message */
		if (msg->keywords & (1 << i)) {
			/* This keyword is associated with this message */
			len = snprintf(pos, sizeof(buf) - (pos - buf),  ";%s", client->sel_mbox->keywords[i]);
			pos += len;
		}
	}
	len = snprintf(pos, sizeof(buf) - (pos - buf), "]");
	client_set_status_nout(client, buf);
}

static int rerender_folder_pane(struct client *client, int selected_item)
{
	cleanup_folder_menu(client);
	free_folder_items(client);

	/* Create menu options for each mailbox, then create the menu */
	if (create_folder_items(client) || create_folder_menu(client)) {
		return -1;
	}

	/* Post menu */
	post_menu(client->folders.menu);

	/* Restore any previous selection by index */
	if (selected_item != -1) {
		set_current_item(client->folders.menu, client->folders.items[selected_item]);
	} else {
		/* Don't let the top mailbox (pseudo for aggregate stats) be selected by default */
		set_current_item(client->folders.menu, client->folders.items[1]);
	}

	wnoutrefresh(client->win_folders);
	return 0;
}

int redraw_folder_pane(struct client *client)
{
	/* Save current position so we can restore.
	 * We can't save the ITEM* directly, so save the index. */
	ITEM *selection = current_item(client->folders.menu);
	int saved_folder_item = item_index(selection);
	cleanup_folder_menu(client);
	if (rerender_folder_pane(client, saved_folder_item)) { /* Rerender the folder pane */
		return -1;
	}
	client->refreshflags &= ~REFRESH_FOLDERS;
	return 0;
}

static const char *ncurses_strerror(int err)
{
	switch (err) {
		case E_OK: return "Success";
		case E_SYSTEM_ERROR: return strerror(errno);
		case E_BAD_ARGUMENT: return "Bad argument";
		case E_POSTED: return "Already posted";
		case E_BAD_STATE: return "Bad state";
		case E_NO_ROOM: return "No room";
		case E_NOT_POSTED: return "Not posted";
		case E_NOT_CONNECTED: return "Not connected";
		case E_NO_MATCH: return "No match";
		case E_UNKNOWN_COMMAND: return "Unknown command";
		case E_REQUEST_DENIED: return "Request denied";
		default: return "Unknown error";
	}
}

static const char *mouse_event_name(MEVENT *mevent)
{
	mmask_t state = mevent->bstate;

	if (state & BUTTON1_PRESSED) {
		return "Button 1 Pressed";
	} else if (state & BUTTON1_RELEASED) {
		return "Button 1 Released";
	} else if (state & BUTTON1_CLICKED) {
		return "Button 1 Clicked";
	} else if (state & BUTTON1_DOUBLE_CLICKED) {
		return "Button 1 Double-Clicked";
	} else if (state & BUTTON1_TRIPLE_CLICKED) {
		return "Button 1 Triple-Clicked";
	} else if (state & BUTTON2_PRESSED) {
		return "Button 2 Pressed";
	} else if (state & BUTTON2_RELEASED) {
		return "Button 2 Released";
	} else if (state & BUTTON2_CLICKED) {
		return "Button 2 Clicked";
	} else if (state & BUTTON2_DOUBLE_CLICKED) {
		return "Button 2 Double-Clicked";
	} else if (state & BUTTON2_TRIPLE_CLICKED) {
		return "Button 2 Triple-Clicked";
	} else if (state & BUTTON3_PRESSED) {
		return "Button 3 Pressed";
	} else if (state & BUTTON3_RELEASED) {
		return "Button 3 Released";
	} else if (state & BUTTON3_CLICKED) {
		return "Button 3 Clicked";
	} else if (state & BUTTON3_DOUBLE_CLICKED) {
		return "Button 3 Double-Clicked";
	} else if (state & BUTTON3_TRIPLE_CLICKED) {
		return "Button 3 Triple-Clicked";
	} else if (state & BUTTON4_PRESSED) {
		return "Button 4 Pressed";
	} else if (state & BUTTON4_RELEASED) {
		return "Button 4 Released";
	} else if (state & BUTTON4_CLICKED) {
		return "Button 4 Clicked";
	} else if (state & BUTTON4_DOUBLE_CLICKED) {
		return "Button 4 Double-Clicked";
	} else if (state & BUTTON4_TRIPLE_CLICKED) {
		return "Button 4 Triple-Clicked";
	} else if (state & BUTTON5_PRESSED) {
		return "Button 5 Pressed";
	} else if (state & BUTTON5_RELEASED) {
		return "Button 5 Released";
	} else if (state & BUTTON5_CLICKED) {
		return "Button 5 Clicked";
	} else if (state & BUTTON5_DOUBLE_CLICKED) {
		return "Button 5 Double-Clicked";
	} else if (state & BUTTON5_TRIPLE_CLICKED) {
		return "Button 5 Triple-Clicked";
	} else {
		return "Unknown";
	}
}

static void cleanup_message_pane(struct client *client)
{
	cleanup_message_menu(client);
	free_message_items(client);
}

/*!
 * \note If the message pane menu has not changed and simply needs to be rerendered,
 * then the selected_item should be passed in since it's faster to find it by that.
 * However, if we need to completely reconstruct messages, then in order to reselect
 * the same message after rebuilding the message cache and rebuilding a new menu,
 * we need to do so by UID, since indices could change when everything is rebuilt.
 *
 * Since the text of the underlying menu items could change due to the new dimensions,
 * we can't just use wresize, since we're fundamentally redrawing the content *in* the window.
 */
static int render_message_pane(struct client *client, int selected_item, uint32_t selected_uid, uint32_t selected_seqno)
{
	int res;

	if (!client->sel_mbox->total) {
		/* Mailbox is empty. Just clear screen. */
		werase(client->win_main);
		wnoutrefresh(client->win_main);
		return 0;
	}

	/* XXX In theory, we could just rebuild the items and then use set_menu_items to replace the menu's items
	 * (still calling set_current_item), which would be more efficient than destroying/recreating the menu too. */
	if (create_message_items(client) || create_messages_menu(client)) {
		return -1;
	}

	/* Post menu */
	res = post_menu(client->message_list.menu);
	if (res != E_OK) {
		client_error("Failed to post menu: %s", ncurses_strerror(res));
		return -1;
	}

	/* Restore any previous selection by index */
	if (selected_uid) {
		/* Scan all messages to find the one with the same UID as before. */
		int new_index = find_message_by_uid(client, selected_uid);
		/* If it's not there anymore, the message was probably expunged.
		 * In this case, the most natural thing to do is select
		 * the "nearest" message to the message that was expunged,
		 * one with a nearby sequence number (not necessarily UID). */
		if (new_index == -1) {
			new_index = client->message_list.n - 1;
		}
		set_current_item(client->message_list.menu, client->message_list.items[new_index]);
	} else if (selected_seqno) {
		int new_index = find_message_by_seqno(client, selected_seqno);
		if (unlikely(new_index == -1)) {
			/* This should exist, since we know whether a sequence number would exist in advance (in the case where we use this) */
			client_warning("Can't find message with seqno %u?", selected_seqno);
			/* If this happens, we probably missed a deletion somehow,
			 * as there are really fewer messages in the mailbox than we think there are. */
			/*! \todo Readd the assert once the underlying bug is fixed */
#if 0
			assert(0);
#endif
		} else {
			set_current_item(client->message_list.menu, client->message_list.items[new_index]);
		}
	} else if (selected_item != -1) {
		if (selected_item >= client->message_list.n) {
			selected_item = client->message_list.n - 1; /* Out of range (e.g. deleted the highest sequence message), just use the highest one that remains */
		}
		set_current_item(client->message_list.menu, client->message_list.items[selected_item]);
	}

	wnoutrefresh(client->win_main);
	return 0;
}

static int rerender_message_pane(struct client *client, int selected_item, uint32_t selected_uid, uint32_t selected_seqno)
{
	cleanup_message_pane(client);
	return render_message_pane(client, selected_item, selected_uid, selected_seqno);
}

/*! \brief Completely destroy all existing messages, generate messages again, generate a new menu, and restore a particular selected item */
static int refetch_regenerate_messages(struct client *client, int selected_item, uint32_t selected_uid, uint32_t selected_seqno)
{
	int res;
	cleanup_message_pane(client); /* Clean up the entire message pane and start fresh */
	if (client_idle_stop(client)) { /* Need to stop idling before we issue a FETCH command */
		return -1;
	}
	res = client_fetchlist(client); /* Fetch everything over again */
	if (res) {
		return -1;
	}
	return render_message_pane(client, selected_item, selected_uid, selected_seqno); /* Rerender the message pane */
}

/* By default, autoselect the newest message in a mailbox */
#define render_message_pane_default(client) rerender_message_pane(client, -1, 0, client->sel_mbox->total)

#define rerender_message_pane_by_index(client, index) rerender_message_pane(client, index, 0, 0)

static int redraw_message_pane(struct client *client, int saved_message_item, uint32_t selected_uid)
{
	int res = 0;

	/* Save current position so we can restore.
	 * We can't save the ITEM* directly, so save the index. */
	if ((client->refreshflags & REFRESH_MESSAGE_PANE) || (client->refreshtypes & (IDLE_EXISTS | IDLE_EXPUNGE))) {
		display_mailbox_info(client); /* Update the footer (permament status), since stats have likely changed */
	}

	if (client->refreshtypes & IDLE_EXPUNGE) {
		if ((uint32_t) saved_message_item >= num_messages(client)) {
			/* Messages expunged such that our old index is now invalid.
			 * Cap it as the number of messages. */
			saved_message_item = num_messages(client);
		}
	}

	if (client->refreshflags & REFRESH_MESSAGE_PANE) {
		/* If it's not just message properties that have changed, but
		 * entire messages have come or gone, we need to redraw the message list.
		 * Thus, there is no guarantee that our index into the message array will be the same message
		 * after as it was before, i.e. we can't even reuse the index.
		 * We need to use the UID to reselect the currently selected message afterwards. */

		/* Small edge case: if so many messages were expunged that the message won't fill the entire screen anymore,
		 * then do a complete refetch as well. */
		if (num_messages(client) < (uint32_t) MAIN_PANE_HEIGHT) {
			res = refetch_regenerate_messages(client, saved_message_item, selected_uid, 0);
		} else {
			res = rerender_message_pane(client, saved_message_item, selected_uid, 0);
		}
		client->refreshflags &= ~REFRESH_MESSAGE_PANE;
	} else {
		cleanup_message_menu(client);
		res = rerender_message_pane_by_index(client, saved_message_item); /* Render new message pane */
	}
	client->refreshflags &= ~REFRESH_MESSAGE_PANE;
	return res;
}

static int handle_idle(struct client *client, int mpanevisible)
{
	/* Before processing IDLE updates, save what message is currently selected,
	 * since sequence numbers and indices could change after that returns. */
	int res = 0;
	ITEM *selection = current_item(client->message_list.menu);
	int saved_message_item = item_index(selection);
	uint32_t selected_uid = get_selected_message(client)->uid;

	res = process_idle(client);
	if (res) {
		return res;
	}

	/* Refresh interface, based on what happened */

	if (!mpanevisible) {
		/* If top-level message selection pane not visible, nothing to refresh. */
		client->refreshflags &= ~REFRESH_MESSAGE_PANE;
	} else if ((client->refreshflags & REFRESH_MESSAGE_PANE) && redraw_message_pane(client, saved_message_item, selected_uid)) {
		return -1;
	}

	if (!mpanevisible) {
		/* If the folder pane isn't visible, we don't need to update that window.
		 * (If the message selection pane isn't visible, neither is the folder pane).
		 * It will be redrawn when the current full screen window gives way back
		 * to the main window anyways. */
		client->refreshflags &= ~REFRESH_FOLDERS;
	} else if ((client->refreshflags & REFRESH_FOLDERS) && redraw_folder_pane(client)) {
		return -1;
	}

	/* Only new mail is worth getting the user's attention about */
	if (client->refreshtypes & (IDLE_EXISTS | IDLE_STATUS_EXISTS)) {
		/* New mail notification. Incidentally this happens to get cleared by something else after a second,
		 * so this just incidentally but conveniently happens to work like a temporary pop-up notification. */
		beep(); /* Ring the bell */
		flash(); /* Flash the screen */
		client_set_status_nout(client, "You've got mail!");
	}
	client->refreshtypes = 0;

	doupdate();

	/* That's all, resume idling if we stopped.
	 * We know IDLE is supported since handle_idle was called in the first place. */
	return client_idle_start(client);
}

int __poll_input(struct client *client, struct pollfd *pfds, int mpanevisible, mmask_t mouse_events)
{
	/* Only poll IMAP fd if idling (which can only happen if a mailbox is selected) */
	time_t now;
	int do_idle = client->sel_mbox && IMAP_HAS_CAPABILITY(client, IMAP_CAPABILITY_IDLE) ? 1 : 0;

	pfds[0].revents = pfds[1].revents = pfds[2].revents = 0;

	/* Start idling if we're not already */
	if (do_idle && client_idle_start(client)) {
		return -1;
	}

	/* Mouse support, if needed */
	mousemask(client->mouse_enable ? mouse_events : 0, NULL); /* Every event except REPORT_MOUSE_POSITION */

	for (;;) {
		ssize_t res;
		int poll_ms = -1;
		now = time(NULL);
		if (do_idle) {
			/* Time counts from when IDLE started, not when this particular poll started */
			time_t diff = now - client->idlestart;
			poll_ms = (MAX_IDLE_POLL_SEC - diff) * 1000;
		}
		/* If idling, poll for slightly less than 30 minutes, since the server could disconnect us after that */
		res = poll(pfds, do_idle ? 3 : 2, do_idle ? poll_ms : -1);
		if (res < 0) {
			if (errno != EINTR) {
				client_debug(0, "poll failed: %s", strerror(errno));
				return -1;
			}
		} else if (!res) {
			if (do_idle && (client_idle_stop(client) || client_idle_start(client))) {
				return -1;
			}
		} else if (pfds[0].revents & POLLIN) {
			/* Activity on STDIN */
			int c = getch();
			if (c == ERR) {
				client_warning("getch returned ERR");
				return -1;
			} else if (isalnum(c)) {
				client_debug(8, "Input received: '%c'", c);
			} else {
				client_debug(7, "Input received: %d", c);
			}
			if (c == 330) {
				/* For some reason, this is delete for me */
				client_debug(5, "Translating input %d to KEY_DL", c);
				c = KEY_DL;
			}
			if (c == ctrl('r')) {
				/* Force full screen refresh (mainly for debugging, since in theory, should not be necessary) */
				return KEY_RESIZE;
			}
			if (c == ctrl('x')) {
				/* Internally handled - toggle mouse support.
				 * Users may want to do this as when the mouse is enabled,
				 * you cannot select text in the terminal like you usually can
				 * (e.g. to copy and paste to something outside of the terminal emulator). */
				client->mouse_enable = !client->mouse_enable;
				mousemask(client->mouse_enable ? mouse_events : 0, NULL); /* Every event except REPORT_MOUSE_POSITION */
				client_set_status_nout(client, client->mouse_enable ? "Mouse enabled" : "Mouse disabled");
				doupdate();
				continue;
			}
			if (c == 10 || c == 13) {
				/* The ENTER behavior differs by key and depending on whether nonl() has been set or not.
				 * The ENTER key in the middle of the keyboard returns 10 without nonl() and 13 with nonl().
				 * The ENTER key in the lower right of the keyboard returns 343 (which is KEY_ENTER).
				 * To simplify application usage, just return KEY_ENTER for all of them, since users will
				 * probably expect that these keys behave the same. */
				/* Depending on if nonl() was called, we don't expect to get the other character,
				 * so ignore that in case we get a CR LF, or otherwise we'll double up and think
				 * we got two newlines. */
#ifdef USE_NONL
				static int ignore_c = 10; /* We get a 13 on ENTER */
#else
				static int ignore_c = 13; /* We get a 10 on ENTER */
#endif
				if (c == ignore_c) {
					client_debug(5, "Ignoring input %d", c);
					continue;
				}
				client_debug(5, "Translating input %d to KEY_ENTER", c);
				c = KEY_ENTER;
			}
			return c;
		} else if (pfds[1].revents & POLLIN) {
			/* Window resize occured */
			uint64_t ec;
			ssize_t rres = read(event_fd, &ec, sizeof(ec));
			(void) rres;
			(void) ec;
			endwin(); /* Since we're manually handling resizes, we need to call endwin first */
			refresh(); /* Retrieve new terminal dimensions */
			/* Proceed as if ncurses had told us that a resize occured */
			if (!mpanevisible) {
				/* We're in a submenu, but menus above this will need to be rerendered.
				 * In fact, we could have multiple levels of this, so simply setting
				 * a flag true here isn't sufficient. For example, say A is the top level menu,
				 * which calls B, which calls C. Each of these have their own windows.
				 * If a resize occurs while running C, C will be resized immediately,
				 * but B will need to be redrawn when C returns to it, and same with A when B returns.
				 * If we returned from C to B and B noticed that the flag was true, it could resize,
				 * but then we'd want to clear the flag to prevent further redundant resizes of B,
				 * but this would prevent A from knowing about the resize.
				 *
				 * The essence of what we need is a way to notify the menu above this that it needs
				 * to resize immediately when we return to it, but not afterwards, while allowing
				 * menus above THAT menu to also be notified.
				 *
				 * Further complicating this is that submenus' windows are allocated/freed in each stack frame,
				 * so there is no persistent data about them once we return. We just have to work with the client structure.
				 *
				 * A simple way to make this work is to record the depth at which a resize occured.
				 * A menu above that can check if the resize depth would necessitate it resizing or not.
				 * Once it has, it can decrement the resize depth.
				 *
				 * Of course, this means we need to store the depth of each call to poll_input, which we do.
				 */
				assert(client->menu_depth > 0);
				client->resize_depth = client->menu_depth; /* Force all windows with this depth or lower to resize */

				/* If we're in a submenu, also be sure to refresh header/footer on resize,
				 * since those are only redrawn manually at the top-level menu. */
				if (client->resize_depth) {
					redraw_header_footer(client);
				}
			} else {
				assert(client->menu_depth == 0);
			}
			client_debug(4, "Window resized to %dx%d at depth %d (resize %d)", COLS, LINES, client->menu_depth, client->resize_depth);
			return KEY_RESIZE;
		} else if (pfds[2].revents & POLLIN) {
			/* Activity on IMAP file descriptor (IDLE) */
			if (handle_idle(client, mpanevisible)) {
				return -1;
			}
		} else {
			client_error("Poll returned activity, but no activity?");
			return -1;
		}
	}
}

int show_help_menu(struct client *client, struct pollfd *pfds, enum help_types help_types)
{
#define MAX_HELP_ITEMS 64
#define EMPTY_HELP_ITEM items[i++] = new_item(" ", "");
	int res = 0;
	int i = 0;
	MENU *menu;
	ITEM *items[MAX_HELP_ITEMS];
	WINDOW *window;

	/* These will show up in groups of 2.
	 * Additionally, because none of the items are selectable,
	 * this ends up looking more like a table. */

	/* Global options */
	if (help_types & HELP_GLOBAL) {
		items[i++] = new_item("q", "Quit current screen");
		items[i++] = new_item("Q", "Fast quit (entire program)");
	} else {
		items[i++] = new_item("ESC", "Exit current menu");
		EMPTY_HELP_ITEM;
	}

	items[i++] = new_item("^X", "Toggle mouse support");
	items[i++] = new_item("^R", "Force redraw screen");

	/* Main menu options */
	if (help_types & HELP_MAIN) {
		items[i++] = new_item("LEFT", "Switch focus to folder pane");
		items[i++] = new_item("RIGHT", "Switch focus to message pane");

		items[i++] = new_item("ENTER", "Select mailbox or message");
		EMPTY_HELP_ITEM;

		items[i++] = new_item("i", "View mailbox or message info");
		items[i++] = new_item("n", "Compose new message");

		items[i++] = new_item("e", "Empty trash");
		items[i++] = new_item("E", "Expunge mailbox");

		items[i++] = new_item("UP/L", "Select previous message");
		items[i++] = new_item("DN/R", "Select next message");

		items[i++] = new_item(" +SHIFT", "Select previous unread msg*");
		items[i++] = new_item(" +SHIFT", "Select next unread msg*");

		items[i++] = new_item("  +CTRL", "Jump prev folder with unread");
		items[i++] = new_item("  +CTRL", "Jump next folder with unread");

		items[i++] = new_item(",", "Jump to msg by seqno");
		items[i++] = new_item(".", "Jump to msg by UID");
	}

	/* Mailbox/message options */
	if (help_types & (HELP_MAIN | HELP_VIEWER)) {
		items[i++] = new_item("u", "Mark message unread");
		items[i++] = new_item("s", "Mark message read");

		if (help_types & HELP_VIEWER) {
			items[i++] = new_item("U", "Mark message unread and return");
			EMPTY_HELP_ITEM;
		}

		items[i++] = new_item("F", "Toggle flagged/unflagged");
		EMPTY_HELP_ITEM;

		items[i++] = new_item("r", "Reply to message");
		items[i++] = new_item("R", "Reply all to message");

		items[i++] = new_item("f", "Forward message");
		EMPTY_HELP_ITEM;

		items[i++] = new_item("c", "Copy message");
		items[i++] = new_item("C", "Copy msg to last dest folder"); /* Don't make descriptions any longer than this, we're already at the limit for 80 cols */

		items[i++] = new_item("m", "Move message");
		items[i++] = new_item("M", "Move msg to last dest folder");

		items[i++] = new_item("l", "Display last dest mailbox");
		EMPTY_HELP_ITEM;

		items[i++] = new_item("j", "Move message to Junk");
		items[i++] = new_item("t", "Delete message (move to Trash)");
	}

	/* Message viewer options */
	if (help_types & HELP_VIEWER) {
		items[i++] = new_item("P", "View plain text version");
		items[i++] = new_item("H", "View HTML version");

		items[i++] = new_item("S", "View message source");
		items[i++] = new_item("BKSP", "Go back to last view");

		items[i++] = new_item("LEFT", "Go to previous message");
		items[i++] = new_item("RIGHT", "Go to next message");

		items[i++] = new_item(" +SHIFT", "Go to previous unread message"); /* Don't make key names any longer, we're already at the limit */
		items[i++] = new_item(" +SHIFT", "Go to next unread message");
	}

	/* Message editor options */
	if (help_types & HELP_EDITOR) {
		items[i++] = new_item("^W", "Cancel, discard draft");
		EMPTY_HELP_ITEM;

		items[i++] = new_item("^D", "Send message");
		items[i++] = new_item("^O", "Save as draft");

		items[i++] = new_item("^A", "Go to beginning of line");
		items[i++] = new_item("^E", "Go to end of line");

		items[i++] = new_item("^U", "Clear remainder of line");
		items[i++] = new_item("^K", "Delete entire line");

		items[i++] = new_item("^B", "Go to beginning of field");
		items[i++] = new_item("^N", "Go to end of field");

		items[i++] = new_item("^L", "Clear entire field");
		EMPTY_HELP_ITEM;
	}

	/* "Footnotes" */
	if (help_types & HELP_MAIN) {
		items[i++] = new_item(" ", "*Marked mailbox, for folder pane");
	}

	assert(i < MAX_HELP_ITEMS);
	for (; i < MAX_HELP_ITEMS; i++) {
		items[i] = NULL;
	}
	for (i = 0; i < MAX_HELP_ITEMS; i++) {
		if (items[i]) {
			item_opts_off(items[i], O_SELECTABLE);
		}
	}

redraw:
	window = newwin(LINES - 2, COLS, 1, 0); /* Full screen, minus top and bottom row */
	if (!window) {
		/* Leaks, but exiting */
		return -1;
	}

	wclrtoeol(client->win_footer); /* Clear line */
	mvwaddstr(window, 0, 0, EVERGREEN_PROGNAME " " EVERGREEN_VERSION " " EVERGREEN_COPYRIGHT);
	wnoutrefresh(client->win_footer);

	menu = new_menu(items);
	if (!menu) {
		goto cleanup;
	}
	set_menu_win(menu, window);
	keypad(window, TRUE);
	/* We can't seem to use wbkgd here to set the colors,
	 * so do that manually for each item instead. */
	set_menu_sub(menu, derwin(window, 0, 0, 1, 0)); /* Skip first row */
	set_menu_format(menu, COLS - 2, 2); /* 2 columns of options, to better utilize space */
	set_menu_mark(menu, "");

	post_menu(menu);
	wnoutrefresh(window);

	doupdate();

	for (;;) {
		int c = poll_input(client, pfds, 0);
		switch (c) {
		case 'Q':
		case -1:
			res = -1;
			/* Fall through */
		case 'q':
		case KEY_ESCAPE:
			goto done;
		case KEY_RESIZE:
			unpost_menu(menu);
			free_menu(menu);
			delwin(window);
			goto redraw;
		case KEY_DOWN:
			menu_driver(menu, REQ_DOWN_ITEM);
			wrefresh(window);
			break;
		case KEY_UP:
			menu_driver(menu, REQ_UP_ITEM);
			wrefresh(window);
			break;
		default:
			beep();
			break;
		}
	}

done:
	/* Clean up */
	unpost_menu(menu);
	free_menu(menu);

cleanup:
	for (i = 0; i < MAX_HELP_ITEMS; i++) {
		if (items[i]) {
			free_item(items[i]);
		}
	}
#undef MAX_HELP_ITEMS
#undef EMPTY_HELP_ITEM
	delwin(window);
	return res;
}

static int show_mailbox_info(struct client *client, struct pollfd *pfds)
{
	/* There are 84 keywords, so this needs to be 64 + 1 + the others */
#define NUM_INFO_ITEMS 84
	int res = 0;
	int i = 0, k = 0;
	MENU *menu;
	ITEM *items[NUM_INFO_ITEMS];
	WINDOW *window;
	struct mailbox *mbox = client->sel_mbox;
	char uidvalidity[16], uidnext[16], unseen[16], recent[16], total[16], size[22];
	char keywordscount[16];

	snprintf(uidvalidity, sizeof(uidvalidity), "%u", mbox->uidvalidity);
	snprintf(uidnext, sizeof(uidnext), "%u", mbox->uidnext);
	snprintf(unseen, sizeof(unseen), "%u", mbox->unseen);
	snprintf(recent, sizeof(unseen), "%u", mbox->recent);
	snprintf(total, sizeof(total), "%u", mbox->total);
	format_size(mbox->size, size, sizeof(size));
	snprintf(keywordscount, sizeof(keywordscount), "%d", mbox->num_keywords);

	items[i++] = new_item("Mailbox", mbox->name);
	items[i++] = new_item("UIDVALIDITY", uidvalidity);
	items[i++] = new_item("UIDNEXT", uidnext);
	items[i++] = new_item("UNSEEN", unseen);
	items[i++] = new_item("RECENT", recent);
	items[i++] = new_item("Total", total);
	items[i++] = new_item("SIZE", size);

	items[i++] = new_item("Keywords", keywordscount);
	for (k = 0; k < mbox->num_keywords; k++) {
		/* ncurses will decline to make an item if the first argument is completely empty,
		 * so just make it a space, so it will still appear as an empty cell on the screen. */
		items[i++] = new_item(" ", mbox->keywords[k]);
	}

	assert(i < NUM_INFO_ITEMS);
	for (; i < NUM_INFO_ITEMS; i++) {
		items[i] = NULL;
	}
	for (i = 0; i < NUM_INFO_ITEMS; i++) {
		if (items[i]) {
			item_opts_off(items[i], O_SELECTABLE);
		}
	}

redraw:
	window = newwin(LINES - 2, 0, 1, 0); /* Full screen, minus top and bottom row */
	if (!window) {
		return -1;
	}

	menu = new_menu(items);
	if (!menu) {
		goto cleanup;
	}
	set_menu_win(menu, window);
	keypad(window, TRUE);
	/* We can't seem to use wbkgd here to set the colors,
	 * so do that manually for each item instead. */
	set_menu_sub(menu, derwin(window, 0, 0, 1, 0)); /* Skip first row */
	set_menu_format(menu, COLS - 2, 1); /* 2 columns of options, to better utilize space */
	set_menu_mark(menu, "");

	post_menu(menu);
	wrefresh(window);

	for (;;) {
		int c = poll_input(client, pfds, 0);
		switch (c) {
		case -1:
		case 'Q':
			res = -1;
			/* Fall through */
		case 'q':
		case KEY_ESCAPE:
			goto done;
		case KEY_RESIZE:
			unpost_menu(menu);
			free_menu(menu);
			delwin(window);
			goto redraw;
		case KEY_DOWN:
			menu_driver(menu, REQ_DOWN_ITEM);
			wrefresh(window);
			break;
		case KEY_UP:
			menu_driver(menu, REQ_UP_ITEM);
			wrefresh(window);
			break;
		default:
			beep();
			break;
		}
	}

done:
	/* Clean up */
	unpost_menu(menu);
	free_menu(menu);
	delwin(window);

cleanup:
	for (i = 0; i < NUM_INFO_ITEMS; i++) {
		if (items[i]) {
			free_item(items[i]);
		}
	}
	return res;
}

/*! \brief Paginate up or down, while keeping the range within the bounds of the mailbox size */
static void adjust_start_seqno(struct client *client, uint32_t current, int offset)
{
	uint32_t adjustment, old = client->start_seqno;
	uint32_t oldmax = client->start_seqno + FETCHLIST_INTERVAL;

	/* Say we want to view messages 50 through 74.
	 * It makes sense to fetch more messages than this,
	 * since if a user pages down with the arrow keys,
	 * we don't want to have to do another FETCH LIST
	 * for each key up/down.
	 *
	 * In other words, we want to also cache the messages
	 * that would scroll off the top and bottom of the screen,
	 * so we can easily load them if needed, without making another request.
	 *
	 * Of course, *eventually* we will have to make another request,
	 * but this should result in a low amortized number of them.
	 *
	 * Rather than fetching messages 50 to 50 + FETCHLIST_INTERVAL,
	 * we instead *center* the interval on 50 to 74, rather than starting it at 50,
	 * to allow for scrolling in either direction. */

	/* This math here is not complicated, but we have to be careful
	 * to avoid doing anything that would result in a negative number,
	 * since uint32_t is unsigned, and that would underflow to something huge. */

	if (oldmax > client->sel_mbox->total) {
		oldmax = client->sel_mbox->total;
	}
	if (offset < 0) {
		/* Going down */
		adjustment = (uint32_t) (-offset);
		if (adjustment >= current) {
			/* Can't decrease it anymore than down to 1 */
			client->start_seqno = 1;
		} else {
			client->start_seqno = current - adjustment;
		}
	} else {
		/* Going up */
		uint32_t max_start_seqno;

		if (client->sel_mbox->total > (uint32_t) FETCHLIST_INTERVAL) {
			max_start_seqno = client->sel_mbox->total - FETCHLIST_INTERVAL;
		} else {
			max_start_seqno = 1;
		}

		adjustment = (uint32_t) offset;
		if (current + adjustment > max_start_seqno) {
			client->start_seqno = max_start_seqno;
		} else {
			client->start_seqno = current + adjustment;
		}
	}
	client->end_seqno = client->start_seqno + FETCHLIST_INTERVAL;
	if (client->end_seqno > client->sel_mbox->total) {
		client->end_seqno = client->sel_mbox->total;
	}
	client_debug(2, "Adjusted current range from [%u:%u] -> [%u,%u] (total: %u)", old, oldmax, client->start_seqno, client->end_seqno, client->sel_mbox->total);
	if (client->sel_mbox->total) {
		assert(client->start_seqno >= 1);
	} else {
		assert(client->start_seqno == 0);
	}
	if (unlikely(client->end_seqno > client->sel_mbox->total)) {
		client_error("End seqno %u > %u", client->end_seqno, client->sel_mbox->total);
	}
	assert(client->end_seqno <= client->sel_mbox->total);
}

static int select_helper(struct client *client, struct mailbox *mbox, int index)
{
	int res = client_select(client, mbox);
	if (!res) {
		/* Make sure this mailbox is focused in the folder pane */
		set_current_item(client->folders.menu, client->folders.items[index]);
		wnoutrefresh(client->win_folders);
		/* Reset */
		client->start_seqno = 0;
		client->end_seqno = 0;
		adjust_start_seqno(client, client->sel_mbox->total, +0); /* Show most recent messages first. We call this function simply to set the bounds right */
		display_mailbox_info(client);
		/* Initialize the message pane */
		res = client_fetchlist(client);
	}
	if (!res) {
		res = render_message_pane_default(client); /* Render new message pane */
	}
	if (!res) {
		/* Switch focus to the message pane automatically */
		set_focus(client, FOCUS_MESSAGES);
		/* Start idling, to stay updated about going ons */
		if (client_idle_start(client)) {
			return -1;
		}
	}

	doupdate();
	return res;
}

/*! \brief Select a mailbox, by menu index */
static int select_mailbox_by_index(struct client *client, int i)
{
	return select_helper(client, &client->mailboxes[i], i);
}

static int select_mailbox_by_name(struct client *client, const char *name)
{
	/* INBOX is probably the first mailbox, but there's no guarantee, so check */
	int i;
	for (i = 0; i < client->num_mailboxes; i++) {
		if (!strcmp(client->mailboxes[i].name, name)) {
			return select_helper(client, &client->mailboxes[i], i);
		}
	}
	return -1;
}

static int redraw_windows(struct client *client)
{
	int saved_folder_item, saved_menu_item = 0;

	/* Save current position so we can restore.
	 * We can't save the ITEM* directly, so save the index. */
	ITEM *selection = current_item(client->folders.menu);
	saved_folder_item = item_index(selection);
	if (client->sel_mbox) {
		selection = current_item(client->message_list.menu);
		saved_menu_item = item_index(selection);
	}

	/* Recreate and rerender all the windows */
	client_debug(3, "Recreating and rerendering all windows");
	cleanup_folder_menu(client);
	cleanup_message_menu(client);
	window_cleanup(client); /* Clean up existing windows */
	setup_interface(client); /* Recreate windows with updated size */
	if (rerender_folder_pane(client, saved_folder_item)) { /* Rerender the folder pane */
		return -1;
	}
	if (client->sel_mbox) {
		display_mailbox_info(client);
		if (rerender_message_pane_by_index(client, saved_menu_item)) { /* Message pane could change layout upon resize */
			return -1;
		}
	} else {
		/* If we were displaying help, we'll want to ensure this is again blank */
		werase(client->win_main);
		wnoutrefresh(client->win_main);
	}
	doupdate();
	return 0;
}

static void set_highlighted_folder(struct client *client)
{
	ITEM *selection = current_item(client->folders.menu);
	int selected_item = item_index(selection);
	struct mailbox *mbox = &client->mailboxes[selected_item];
	client_set_status_nout(client, mbox->name); /* Display the full mailbox name in status bar, in case it's truncated in folder pane */
	wnoutrefresh(client->win_folders);
	doupdate();
}

#define UPDATE_MPANE_NOREFRESH(client) \
	wnoutrefresh(client->win_main); \
	display_message_info(client, NULL);

/* It's more efficient to batch wnoutrefresh calls together and then call doupdate once,
 * rather than calling wrefresh multiple times, so do this when possible */
#define UPDATE_MPANE_FOOTER(client) \
	UPDATE_MPANE_NOREFRESH(client); \
	doupdate();

/* This is one of the key differentiating factors behind this mail client.
 * We operate completely online. We do not cache anything on disk,
 * and only cache FETCHLIST_INTERVAL message headers in memory at a time.
 * If we need to view other messages, we will dynamically update the set
 * of cached messages on the fly, recentered around the currently selected message.
 * This allows the mail client to remain fairly responsive most of the time,
 * while keeping startup time and overall memory usage low. */
#define FIRST_ITEM_IN_MENU_SELECTED(client, selected_item) (selected_item == 0)
#define LAST_MSG_IN_MENU_SELECTED(client, selected_item) (selected_item == client->message_list.n - 1)
#define FIRST_ITEM_AND_ITEMS_EXIST_BEFORE_SELECTED_ITEM(client, selected_item) (get_selected_message(client)->seqno > 1)
#define LAST_MSG_AND_ITEMS_EXIST_AFTER_SELECTED_ITEM(client, selected_item) (get_selected_message(client)->seqno < client->sel_mbox->total)

#define FIRST_PAGE_AND_ITEMS_EXIST_BEFORE_CURRENT_ITEM(client, selected_item) (selected_item > 0 && selected_item < MAIN_PANE_HEIGHT)
#define LAST_PAGE_AND_FOLDERS_EXIST_AFTER_CURRENT_ITEM(client, selected_item) (selected_item < client->folders.n - 1 && selected_item >= client->folders.n - MAIN_PANE_HEIGHT)
#define LAST_FOLDER_IN_MENU_SELECTED(client, selected_item) (selected_item == client->folders.n - 1)

/* If you are on the first page, pressing PAGE UP will not do anything, even if there are items above, i.e. it will not autoselect the first item on the page.
 * This is important for implementation details of dynamically paging up to previous messages are that are currently off-menu.
 * This logic needs to trigger if we are anywhere on the first page, not merely if the first item is selected.
 * Similar logic applies to page down operations. */
#define FIRST_PAGE_AND_PAGES_EXIST_BEFORE_CURRENT_PAGE(client, selected_item) (client->start_seqno > 1 && selected_item < MAIN_PANE_HEIGHT)
#define LAST_MSG_PAGE_AND_PAGES_EXIST_AFTER_CURRENT_PAGE(client, selected_item) (client->end_seqno < client->sel_mbox->total && (uint32_t) selected_item >= client->end_seqno - MAIN_PANE_HEIGHT)
#define FIRST_MESSAGE_IN_CURRENT_MENU(client) (client->start_seqno == 1)
#define LAST_MESSAGE_IN_CURRENT_MENU(client) (client->end_seqno == client->sel_mbox->total)

static int repaginate(struct client *client, uint32_t seqno, int diff, int newseqno)
{
	/* There are more messages if we scroll.
	 * Redownload headers, centered at where we are now,
	 * so we can scroll up/down to another FETCHLIST_INTERVAL/2 in either direction without another repagination. */
	adjust_start_seqno(client, seqno, diff);
	/* Completely rebuild messages, and reselect the message we would have paged to,
	 * which has a sequence number 1 smaller than the one that was previously selected. */
	client_set_status(client, "Please wait... repaginating");
	return refetch_regenerate_messages(client, -1, 0, newseqno);
}

static ITEM *get_item_at_row(MENU *menu, int row)
{
	int i, cur_row;
	int min = 0, max = 0;
	ITEM **items = menu_items(menu);
	for (i = 0; i < item_count(menu); i++) {
		if (item_visible(items[i])) {
			break;
		}
	}
	if (i >= item_count(menu)) {
		/* Exceeded menu */
		return NULL;
	}
	/* The first visible item is on row 1 */
	min = i;
	for (cur_row = 1; i < item_count(menu); i++, cur_row++) {
		if (cur_row == row) {
			return items[i];
		}
		max = i;
		if (!item_visible(items[i])) {
			break;
		}
	}
	client_debug(5, "Couldn't find item at row %d [%d,%d]", row, min, max);
	return NULL;
}

#define NUMBUF_RESET() \
	numbufpos = numbuf; \
	numbufleft = sizeof(numbuf);

/* If out of room, just start over, there aren't any seqnos/UIDs that long */
#define NUMBUF_APPEND(c) \
	if (numbufleft <= 1) { \
		numbufpos = numbuf + 1; \
		numbufleft = sizeof(numbuf) - 1; \
	} \
	*numbufpos++ = c; \
	*numbufpos = '\0'; \
	numbufleft--;

#define PRINT_NUMBUF() { \
	char _msgbuf[32]; \
	snprintf(_msgbuf, sizeof(_msgbuf), "Jump %s: %s", numbuf[0] == ',' ? "seqno" : "UID", numbuf + 1); \
	client_set_status(client, _msgbuf); \
}

static int client_menu(struct client *client)
{
	char numbuf[16] = "";
	char *numbufpos;
	size_t numbufleft;
	struct pollfd pfds[3];
	int res = 0; /* XXX This should not need to be initialized, but o/w get warning about res == 336 check */
	MEVENT mevent;

	NUMBUF_RESET();

	memset(&pfds, 0, sizeof(pfds));
	pfds[0].fd = STDIN_FILENO; /* Since ncurses has the terminal unbuffered, we can poll it just like anything else */
	pfds[0].events = POLLIN;
	pfds[1].fd = event_fd;
	pfds[1].events = POLLIN;
	pfds[2].fd = client->imapfd;
	pfds[2].events = POLLIN;

	/* IMAP LIST */
	if (client_list(client)) {
		return -1;
	}

	/* Clear any stale status from LIST or before */
	client_clear_status(client);

	if (rerender_folder_pane(client, 1)) { /* The first folder is the aggregate view, so the first real mailbox is at index 1, show that by default */
		return -1;
	}
	doupdate();

	/* Automatically select the INBOX when we start */
	select_mailbox_by_name(client, "INBOX");

	for (;;) {
		int c = __poll_input(client, pfds, 1, ALL_MOUSE_EVENTS);
		if (!isdigit(c) && c != KEY_BACKSPACE && c != KEY_ENTER) {
			/* If we stop jumping and do something else, don't save partial and resume later */
			NUMBUF_RESET();
		}
		switch (c) {
		case -1:
			return -1;
		case 'Q':
		case 'q':
			return 0; /* Quit */
		case KEY_ESCAPE:
			/* Since we hit escape to exit a message and return to the menu,
			 * we don't want an accidental double escape to quit the program. */
			client_set_status(client, "Hit q to quit");
			break;
		case 'i':
			if (client->sel_mbox) {
				SUB_MENU_PRE;
				res = show_mailbox_info(client, pfds);
				SUB_MENU_POST;
				goto redraw;
			} else {
				client_set_status(client, "Select mailbox to show info");
			}
			break;
		case 'n': /* Compose new message */
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				/*! \todo Could make it create a new mailbox */
				beep(); /* Invalid for folders */
			} else { /* FOCUS_MESSAGES */
				SUB_MENU_PRE;
				res = editor(client, pfds);
				SUB_MENU_POST;
				goto redraw; /* Redraw, leaving status bar intact */
			}
			break;
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
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				beep(); /* Invalid for folders */
			} else { /* FOCUS_MESSAGES */
				SUB_MENU_PRE;
				res = handle_message_op(client, pfds, get_selected_message(client), NULL, c);
				SUB_MENU_POST;
				if (res > 1) {
					/* Message pane and folder pane need redraw */
					goto resize;
				} else if (res > 0) {
redraw: /* Rerender folder pane, message pane, leave status bar alone */
					/* Message pane and folder pane need redraw, don't clear status bar */
					ITEM *selection = current_item(client->message_list.menu);
					int saved_message_item = item_index(selection);
					client->refreshflags |= REFRESH_MESSAGE_PANE;
					client_debug(3, "Redrawing folder/message pane, not status bar");
					if (redraw_folder_pane(client) || rerender_message_pane_by_index(client, saved_message_item)) {
						return -1;
					}
				}
				doupdate();
			}
			break;
		case 'e': /* Empty trash */
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				beep(); /* Invalid for folders */
			} else { /* FOCUS_MESSAGES */
				ITEM *selection = current_item(client->message_list.menu);
				int saved_message_item = item_index(selection);
				if (handle_emptytrash(client)) { /* Mark all messages for deletion, but don't expunge */
					return 0;
				}
				/* Status bar and message pane changed ('T' flag added to all) */
				if (rerender_message_pane_by_index(client, saved_message_item)) {
					return -1;
				}
				doupdate();
			}
			break;
		case 'E': /* Expunge mailbox */
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				beep(); /* Invalid for folders */
			} else { /* FOCUS_MESSAGES */
				/* First, confirm, so user doesn't do this by accident */
				SUB_MENU_PRE;
				res = handle_expunge(client, pfds);
				SUB_MENU_POST;
				if (res) {
					return 0;
				}
				goto redraw;
			}
			break;
		case 'h':
		case '?':
		case KEY_HELP:
			SUB_MENU_PRE;
			res = show_help_menu(client, pfds, HELP_GLOBAL | HELP_MAIN);
			SUB_MENU_POST;
			if (res) {
				/* Don't return -1 from top-level menus, since sub menus return -1 to force immediate quit,
				 * and we should return with a normal exit status in this case. */
				return 0;
			}
			/* Fall through */
		case KEY_RESIZE:
resize: /* Complete redraw of folder pane, message pane, status bar */
			if (COLS < 80) {
				clear();
				refresh();
				client_error(">= 80 cols required");
			} else {
				client_debug(3, "Redrawing folder/message/status pane");
				if (redraw_windows(client)) {
					return -1;
				}
			}
			break;
		case KEY_LEFT:
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				beep();
			} else {
				set_focus(client, FOCUS_FOLDERS);
			}
			break;
		case KEY_RIGHT:
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				ITEM *selection = current_item(client->folders.menu);
				int selected_item = item_index(selection);
				/* If the focused mailbox is not the selected one,
				 * then the user might be trying to select it. */
				if (client->sel_mbox == &client->mailboxes[selected_item]) {
					/* If already a mailbox selected, switch focus back to it */
					set_focus(client, FOCUS_MESSAGES);
				} else {
					client_set_status(client, "Hit ENTER to select mailbox");
					beep();
				}
			} else {
				beep();
			}
			break;
		case KEY_ENTER:
			if (numbufpos > numbuf) {
				char msgbuf[48];
				int jumpmsgnum, find_uid, new_index;
				/* Used , or . to try to jump to a specific message by number */
				if (numbufpos == numbuf + 1) {
					/* Still empty */
					beep();
					break;
				}
				find_uid = numbuf[0] == '.';
				jumpmsgnum = atoi(numbuf + 1);
				client_debug(3, "Requested jump to %s %d", find_uid ? "UID" : "seqno", jumpmsgnum);
				NUMBUF_RESET();

				/* Try to select this message, by sequence number or UID, if it exists in this mailbox.
				 * If not, throw an error. */
				new_index = find_uid ? find_message_by_uid(client, jumpmsgnum) : find_message_by_seqno(client, jumpmsgnum);
				if (new_index < 0) {
					snprintf(msgbuf, sizeof(msgbuf), "No msg with %s %d", find_uid ? "UID" : "seqno", jumpmsgnum);
					client_set_status(client, msgbuf);
					beep();
					break;
				}
				set_current_item(client->message_list.menu, client->message_list.items[new_index]);
				/* Fall through */
			}
select_current:
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				/* Select the focused mailbox */
				ITEM *selection = current_item(client->folders.menu);
				int selected_item = item_index(selection);
				if (client->mailboxes[selected_item].flags & IMAP_MAILBOX_NOSELECT) {
					client_set_status_nout(client, "Can't select this mailbox");
					doupdate();
					break;
				}
				/* If we're currently idling, stop, since we're switching mailboxes */
				if (client_idle_stop(client)) {
					return -1;
				}
				cleanup_message_pane(client); /* Clean up old message pane */
				res = select_mailbox_by_index(client, selected_item);
				if (res) {
					return res;
				}
			} else { /* FOCUS_MESSAGES */
viewmsg:
				/* Selected the focused message */
				struct message *msg;
				int needresize;
				if (!current_item(client->message_list.menu)) {
					/* Mailbox must be empty */
					beep();
					break;
				}
				if (client_idle_stop(client)) {
					return -1;
				}
				msg = get_selected_message(client);
				/* If this is the Drafts folder, open the message for editing.
				 * Otherwise, display the message. */
				display_message_info(client, msg); /* In case we selected a message right after selecting a mailbox, this message's info wasn't already being shown, so show it */
				if (client->sel_mbox == client->draft_mbox) {
					/* Open for editing */
					SUB_MENU_PRE;
					res = edit_message(client, pfds, msg);
					SUB_MENU_POST;
				} else {
					/* Open for viewing */
					/* view_message contains a call to doupdate(), so no need to update here */
					SUB_MENU_PRE;
					res = view_message(client, pfds, msg);
					SUB_MENU_POST_DELAYRESIZE(needresize);
				}
				if (res == KEY_LEFT || res == KEY_RIGHT || res == KEY_SLEFT || res == KEY_SRIGHT) {
					/* Navigate between messages.
					 *
					 * Pressing the left or right arrow keys while viewing a message
					 * will jump back or forward to the previous or next message.
					 * Holding the SHIFT key while doing so will jump back or forward
					 * to the previous or next unread message.
					 *
					 * Do this before resize redirect, to ensure
					 * the main menu isn't redrawn if we're flipping between messages.
					 * This effectively "ignores" popping the resize for now,
					 * and we'll deal with it later.
					 *
					 * However, if we do need to resize and can't actually open a different
					 * message now, we'll need to do that below. */
huntmsg:
					ITEM *selection = current_item(client->message_list.menu);
					int selected_item = item_index(selection);
					if (res == KEY_LEFT || res == KEY_SLEFT) {
						if (FIRST_ITEM_IN_MENU_SELECTED(client, selected_item)) {
							/* We're trying to scroll up off the top of the menu */
							if (FIRST_ITEM_AND_ITEMS_EXIST_BEFORE_SELECTED_ITEM(client, selected_item)) {
								uint32_t seqno = get_selected_message(client)->seqno;
								if (repaginate(client, seqno, -FETCHLIST_INTERVAL/2, seqno - 1)) {
									return -1;
								}
							} else {
								client_debug(1, "No %s messages available", res == KEY_SLEFT ? "older, unread" : "older");
								beep();
								if (needresize) {
									goto resize;
								}
							}
						} else {
							menu_driver(client->message_list.menu, REQ_UP_ITEM);
							if (res == KEY_SLEFT) {
								/* Only want older messages that are unread */
								if (get_selected_message(client)->flags & IMAP_MESSAGE_FLAG_SEEN) {
									goto huntmsg;
								}
							}
							UPDATE_MPANE_NOREFRESH(client);
						}
					} else { /* res == KEY_RIGHT || res == KEY_SRIGHT */
						if (LAST_MSG_IN_MENU_SELECTED(client, selected_item)) {
							/* We're trying to scroll down off the bottom of the menu */
							if (LAST_MSG_AND_ITEMS_EXIST_AFTER_SELECTED_ITEM(client, selected_item)) {
								uint32_t seqno = get_selected_message(client)->seqno;
								if (repaginate(client, seqno, +FETCHLIST_INTERVAL/2, seqno + 1)) {
									return -1;
								}
							} else {
								client_debug(1, "No %s messages available", res == KEY_SLEFT ? "newer, unread" : "newer");
								beep();
								if (needresize) {
									goto resize;
								}
							}
						} else {
							menu_driver(client->message_list.menu, REQ_DOWN_ITEM);
							if (res == KEY_SRIGHT) {
								/* Only want newer messages that are unread */
								if (get_selected_message(client)->flags & IMAP_MESSAGE_FLAG_SEEN) {
									goto huntmsg;
								}
							}
							UPDATE_MPANE_NOREFRESH(client);
						}
					}
					if (needresize) {
						/* Since we kicked the resize can down the road, we need to keep track of this
						 * for next time, so that we will eventually resize. */
						client->resize_depth++;
						client_debug(1, "Incrementing resize depth to %d", client->resize_depth);
					}
					goto viewmsg; /* View that message directly */
				}
				goto resize; /* Redraw main screen */
			}
			break;

/* The first one is ALL, which isn't even selectable, so start at 1.
 * However, we first focus the "ALL" pseudofolder to ensure that it's always visible
 * in case it's not initially. Otherwise, it's possible that we might
 * not be able to get it back into focus. */
#define FOCUS_FIRST_FOLDER() \
	set_current_item(client->folders.menu, client->folders.items[0]); \
	set_current_item(client->folders.menu, client->folders.items[1]);

		case 337: /* SHIFT + UP */
		case KEY_SLEFT: /* SHIFT + LEFT, since some terminals like qodem don't pass SHIFT + UP/DN, only SHIFT + L/R */
		case 572: /* CTRL+SHIFT+LEFT, PuTTY supports it but qodem does not */
		case KEY_UP: /* Go up to lower sequenced numbered message */
up:
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				ITEM *selection = current_item(client->folders.menu);
				int selected_item = item_index(selection);
				if (FIRST_ITEM_IN_MENU_SELECTED(client, selected_item) || selected_item == 1) {
					beep();
				} else {
					menu_driver(client->folders.menu, REQ_UP_ITEM);
					if (c == 337 || c == KEY_SLEFT) {
						/* Only want to jump to marked mailboxes */
						selection = current_item(client->folders.menu);
						selected_item = item_index(selection);
						if (!(client->mailboxes[selected_item].flags & IMAP_MAILBOX_MARKED)) {
							goto up;
						}
					} else if (c == 572) {
						/* Jump to unread */
						selection = current_item(client->folders.menu);
						selected_item = item_index(selection);
						if (client->mailboxes[selected_item].unseen == 0) {
							goto up;
						}
					}
				}
				set_highlighted_folder(client);
			} else { /* FOCUS_MESSAGES */
huntupmsg:
				int selected_item;
				ITEM *selection = current_item(client->message_list.menu);
				if (!selection) {
					client_debug(1, "No selection (mailbox must be empty)");
					/* Status bar already says mailbox is empty */
					beep();
					break;
				}
				selected_item = item_index(selection);
				if (FIRST_ITEM_IN_MENU_SELECTED(client, selected_item)) {
					/* We're trying to scroll up off the top of the menu */
					if (FIRST_ITEM_AND_ITEMS_EXIST_BEFORE_SELECTED_ITEM(client, selected_item)) {
						uint32_t seqno = get_selected_message(client)->seqno;
						if (repaginate(client, seqno, -FETCHLIST_INTERVAL/2, seqno - 1)) {
							return -1;
						}
					} else {
						client_debug(1, "Attempt to scroll up beyond limit");
						beep();
					}
				} else {
					menu_driver(client->message_list.menu, REQ_UP_ITEM);
					if (c == 337 || c == KEY_SLEFT) {
						/* Only want older messages that are unread */
						if (get_selected_message(client)->flags & IMAP_MESSAGE_FLAG_SEEN) {
							goto huntupmsg;
						}
					} else if (c == 572) {
						beep();
					}
					UPDATE_MPANE_FOOTER(client);
				}
			}
			break;
		case 336: /* SHIFT + DOWN */
		case KEY_SRIGHT: /* SHIFT + LEFT, since some terminals like qodem don't pass SHIFT + UP/DN, only SHIFT + L/R */
		case 531: /* CTRL+SHIFT+LEFT, PuTTY supports it but qodem does not */
		case KEY_DOWN: /* Go down to higher sequence numbered message */
down:
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				ITEM *selection = current_item(client->folders.menu);
				int selected_item = item_index(selection);
				if (LAST_FOLDER_IN_MENU_SELECTED(client, selected_item)) {
					beep();
				} else {
					menu_driver(client->folders.menu, REQ_DOWN_ITEM);
					if (c == 336 || c == KEY_SRIGHT) {
						/* Only want to jump to marked mailboxes */
						selection = current_item(client->folders.menu);
						selected_item = item_index(selection);
						if (!(client->mailboxes[selected_item].flags & IMAP_MAILBOX_MARKED)) {
							goto down;
						}
					} else if (c == 531) {
						/* Jump to unread */
						selection = current_item(client->folders.menu);
						selected_item = item_index(selection);
						if (client->mailboxes[selected_item].unseen == 0) {
							goto down;
						}
					}
				}
				set_highlighted_folder(client);
			} else { /* FOCUS_MESSAGES */
huntdownmsg:
				int selected_item;
				ITEM *selection = current_item(client->message_list.menu);
				if (!selection) {
					client_debug(1, "No selection (mailbox must be empty)");
					/* Status bar already says mailbox is empty */
					beep();
					break;
				}
				selected_item = item_index(selection);
				if (LAST_MSG_IN_MENU_SELECTED(client, selected_item)) {
					/* We're trying to scroll down off the bottom of the menu */
					if (LAST_MSG_AND_ITEMS_EXIST_AFTER_SELECTED_ITEM(client, selected_item)) {
						uint32_t seqno = get_selected_message(client)->seqno;
						if (repaginate(client, seqno, +FETCHLIST_INTERVAL/2, seqno + 1)) {
							return -1;
						}
					} else {
						client_debug(1, "Attempt to scroll down beyond limit");
						beep();
					}
				} else {
					menu_driver(client->message_list.menu, REQ_DOWN_ITEM);
					if (c == 336 || c == KEY_SRIGHT) {
						/* Only want newer messages that are unread */
						if (get_selected_message(client)->flags & IMAP_MESSAGE_FLAG_SEEN) {
							goto huntdownmsg;
						}
					} else if (c == 531) {
						beep();
					}
					UPDATE_MPANE_FOOTER(client);
				}
			}
			break;
		case KEY_PPAGE: /* Page up to lower sequence numbered messages */
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				ITEM *selection = current_item(client->folders.menu);
				int selected_item = item_index(selection);
				if (FIRST_PAGE_AND_ITEMS_EXIST_BEFORE_CURRENT_ITEM(client, selected_item)) {
					/* Same as HOME key if on first page already */
					FOCUS_FIRST_FOLDER();
				} else {
					if (selected_item > 0) {
						menu_driver(client->folders.menu, REQ_SCR_UPAGE);
					} else {
						beep();
					}
				}
				set_highlighted_folder(client);
			} else { /* FOCUS_MESSAGES */
				ITEM *selection = current_item(client->message_list.menu);
				int selected_item = item_index(selection);
				if (FIRST_PAGE_AND_PAGES_EXIST_BEFORE_CURRENT_PAGE(client, selected_item)) {
					uint32_t seqno = get_selected_message(client)->seqno;
					uint32_t newseqno = newseqno = seqno - MAIN_PANE_HEIGHT;
					newseqno = newseqno < 1 ? 1 : newseqno;
					if (repaginate(client, seqno, -FETCHLIST_INTERVAL/2, newseqno)) {
						return -1;
					}
				} else {
					menu_driver(client->message_list.menu, REQ_SCR_UPAGE);
					UPDATE_MPANE_FOOTER(client);
				}
			}
			break;
		case KEY_NPAGE: /* Page down to higher sequence numbered messages */
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				ITEM *selection = current_item(client->folders.menu);
				int selected_item = item_index(selection);
				if (LAST_PAGE_AND_FOLDERS_EXIST_AFTER_CURRENT_ITEM(client, selected_item)) {
					/* Same as END key if on last page already */
					set_current_item(client->folders.menu, client->folders.items[client->folders.n - 1]);
				} else {
					if (selected_item < client->folders.n - 1) {
						menu_driver(client->folders.menu, REQ_SCR_DPAGE);
					} else {
						beep();
					}
				}
				set_highlighted_folder(client);
			} else { /* FOCUS_MESSAGES */
				ITEM *selection = current_item(client->message_list.menu);
				int selected_item = item_index(selection);
				if (LAST_MSG_PAGE_AND_PAGES_EXIST_AFTER_CURRENT_PAGE(client, selected_item)) {
					uint32_t seqno = get_selected_message(client)->seqno;
					uint32_t newseqno = seqno + MAIN_PANE_HEIGHT;
					newseqno = newseqno > client->sel_mbox->total ? client->sel_mbox->total : newseqno;
					if (repaginate(client, seqno, +FETCHLIST_INTERVAL/2, newseqno)) {
						return -1;
					}
				} else {
					menu_driver(client->message_list.menu, REQ_SCR_DPAGE);
					UPDATE_MPANE_FOOTER(client);
				}
			}
			break;
		case KEY_HOME:
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				FOCUS_FIRST_FOLDER();
				set_highlighted_folder(client);
			} else { /* FOCUS_MESSAGES */
				if (FIRST_MESSAGE_IN_CURRENT_MENU(client)) {
					set_current_item(client->message_list.menu, client->message_list.items[0]);
					wrefresh(client->win_main);
				} else {
					adjust_start_seqno(client, get_selected_message(client)->seqno, -client->sel_mbox->total); /* Subtract max # so we jump to 1 */
					client_set_status(client, "Please wait... repaginating");
					res = refetch_regenerate_messages(client, -1, 0, 1); /* Select first message */
					if (res) {
						return res;
					}
				}
			}
			break;
		case KEY_END:
			if (FOCUSED(client, FOCUS_FOLDERS)) {
				set_current_item(client->folders.menu, client->folders.items[client->folders.n - 1]);
				set_highlighted_folder(client);
			} else { /* FOCUS_MESSAGES */
				if (LAST_MESSAGE_IN_CURRENT_MENU(client)) {
					set_current_item(client->message_list.menu, client->message_list.items[client->message_list.n]);
					wrefresh(client->win_main);
				} else {
					adjust_start_seqno(client, get_selected_message(client)->seqno, +client->sel_mbox->total); /* Add max # so we jump to last message */
					client_set_status(client, "Please wait... repaginating");
					res = refetch_regenerate_messages(client, -1, 0, client->sel_mbox->total); /* Select last message */
					if (res) {
						return res;
					}
				}
			}
			break;
		case KEY_MOUSE:
			res = getmouse(&mevent);
			if (res == OK) {
				client_debug(7, "Mouse event %s at row %d, col %d, SHIFT: %d, CTRL: %d, ALT: %d", mouse_event_name(&mevent), mevent.y, mevent.x,
					mevent.bstate & BUTTON_SHIFT ? 1 : 0, mevent.bstate & BUTTON_CTRL ? 1 : 0, mevent.bstate & BUTTON_ALT ? 1 : 0);
				if (mevent.y > 0 && mevent.y < LINES - 1) {
					/* According to the man page, the menu driver can do the work for us of figuring out what was selected,
					 * by passing KEY_MOUSE as the input to menu_driver.
					 * However, this black magic doesn't seem to work for me (just returns E_REQUEST_DENIED), so compute the selection manually. */
					if (mevent.bstate & (BUTTON1_CLICKED | BUTTON1_DOUBLE_CLICKED)) {
						/* Left click */
						/* Unlike most cases, instead of using the FOCUSED macro,
						 * we base the target on the column in the mouse event. */
						int tgt_folders = mevent.x < LIST_PANE_WIDTH;
						MENU *cur_menu = tgt_folders ? client->folders.menu : client->message_list.menu;
						ITEM *item = get_item_at_row(cur_menu, mevent.y);
						if (item) {
							set_current_item(cur_menu, item);
							if (tgt_folders) {
								set_highlighted_folder(client);
								if (!FOCUSED(client, FOCUS_FOLDERS)) {
									/* Automatically switch focus to folder pane */
									set_focus(client, FOCUS_FOLDERS);
								}
							} else {
								UPDATE_MPANE_FOOTER(client);
								if (!FOCUSED(client, FOCUS_MESSAGES)) {
									/* Automatically switch focus to message pane */
									set_focus(client, FOCUS_MESSAGES);
								}
							}
						}
						if (mevent.bstate & BUTTON1_DOUBLE_CLICKED) {
							/* If it was a double click, go ahead and handle it as if ENTER were pushed */
							goto select_current;
						}
					} else if (mevent.bstate & BUTTON2_CLICKED) {
						/* Middle click */
					} else if (mevent.bstate & BUTTON3_CLICKED) {
						/* Right click */
					} else if (mevent.bstate & BUTTON4_PRESSED) {
						/* Scroll up */
						goto up;
					} else if (mevent.bstate & BUTTON5_PRESSED) {
						/* Scroll down */
						goto down;
					}
				}
			} else {
				client_debug(8, "Failed to get mouse info");
				/* refresh screen */
				doupdate();
			}
			break;
		case KEY_BREAK:
			client_debug(2, "Ignoring break");
			beep();
			break;
		case KEY_BACKSPACE:
			if (numbufpos > numbuf + 1) {
				*(--numbufpos) = '\0';
				numbufleft++;
				PRINT_NUMBUF();
			} else {
				client_debug(2, "Ignoring backspace");
				beep();
			}
			break;
		case ',': /* Jump to message by sequence number */
			NUMBUF_APPEND(c);
			client_set_status(client, "Jump seqno: ");
			break;
		case '.': /* Jump to message by UID */
			NUMBUF_APPEND(c);
			client_set_status(client, "Jump UID: ");
			break;
		case '0' ... '9':
			if (numbufpos == numbuf) {
				/* Need to start first */
				client_set_status_nout(client, "Hit , or . first");
				beep();
				doupdate();
			} else {
				NUMBUF_APPEND(c);
				PRINT_NUMBUF();
			}
			break;
		case '/': /* Reserved for future use: search */
		default:
			client_debug(2, "Ignoring unbound key %d", c);
			beep();
		}
	}

done:
	return res;
}

static const char *getopt_settings = "?c:dhl:V";

static int read_line(const char *name, char *buf, size_t len)
{
	char *ret, *nl;

	fprintf(stdout, "%s: ", name);
	fflush(stdout);
	ret = fgets(buf, len, stdin);
	if (!ret) {
		return -1;
	}

	/* Remove line ending */
	nl = strchr(buf, '\n');
	if (nl) {
		*nl = '\0';
		if (nl > buf) {
			--nl;
			if (*nl == '\r') {
				*nl = '\0';
			}
		}
	}
	if (strlen_zero(buf)) {
		return -1;
	}
	return 0;
}

static int read_hidden_line(const char *name, char *buf, size_t len)
{
	char *ret, *nl;
	struct termios term, orig;

	/* Disable echo for reading password */
    if (tcgetattr(STDIN_FILENO, &term)) {
		fprintf(stderr, "tcgetattr failed: %s", strerror(errno));
		return -1;
	}

	orig = term;
    term.c_lflag &= ~(ECHO);          

    if (tcsetattr(STDIN_FILENO, TCSANOW, &term)) {
		fprintf(stderr, "tcsetattr failed: %s", strerror(errno));
		return -1;
	}

	/* Read password from STDIN */
	fprintf(stdout, "%s: ", name);
	fflush(stdout);
	ret = fgets(buf, len, stdin);
	if (!ret) {
		return -1;
	}

	/* Remove line ending */
	nl = strchr(buf, '\n');
	if (nl) {
		*nl = '\0';
		if (nl > buf) {
			--nl;
			if (*nl == '\r') {
				*nl = '\0';
			}
		}
	}
	fprintf(stdout, "\n"); /* Manually output newline since none was echoed */
	if (tcsetattr(STDIN_FILENO, TCSANOW, &orig)) { /* Restore terminal */
		fprintf(stderr, "tcsetattr failed: %s", strerror(errno));
		return -1;
	}
	if (strlen_zero(buf)) {
		return -1;
	}
	return 0;
}

static int phony_options = 0;

static int process_option(struct config *config, const char *optname, const char *val)
{
	char key[256];
	char *tmp;

	if (phony_options) {
		client_debug(10, "Processed option '%s'", optname);
		return 0;
	}

	/* The config file uses option_name, while the command line options use option-name.
	 * Convert if needed to a canonical format. */
	safe_strncpy(key, optname, sizeof(key));
	tmp = key;
	while (*tmp) {
		if (*tmp == '-') {
			*tmp = '_';
		}
		tmp++;
	}

	if (!strcmp(key, "fromname")) {
		safe_strncpy(config->fromname, val, sizeof(config->fromname));
	} else if (!strcmp(key, "fromaddr")) {
		safe_strncpy(config->fromaddr, val, sizeof(config->fromaddr));
	} else if (!strcmp(key, "additional_identities")) {
		config->additional_identities = strdup(val);
		if (!config->additional_identities) {
			return -1;
		}
	} else if (!strcmp(key, "imap_hostname")) {
		safe_strncpy(config->imap_hostname, val, sizeof(config->imap_hostname));
	} if (!strcmp(key, "smtp_hostname")) {
		safe_strncpy(config->smtp_hostname, val, sizeof(config->smtp_hostname));
	} else if (!strcmp(key, "imap_port")) {
		config->imap_port = atoi(val);
	} else if (!strcmp(key, "smtp_port")) {
		config->smtp_port = atoi(val);
	} else if (!strcmp(key, "imap_security")) {
		if (!strcasecmp(val, "tls")) {
			config->imap_security = SECURITY_TLS;
		} else if (!strcasecmp(val, "starttls")) {
			config->imap_security = SECURITY_STARTTLS;
			fprintf(stderr, "STARTTLS not supported for IMAP\n");
			return -1;
		} else {
			config->smtp_security = SECURITY_NONE;
		}
	} else if (!strcmp(key, "smtp_security")) {
		if (!strcasecmp(val, "tls")) {
			config->smtp_security = SECURITY_TLS;
		} else if (!strcasecmp(val, "starttls")) {
			config->smtp_security = SECURITY_STARTTLS;
			return -1;
		} else {
			config->smtp_security = SECURITY_NONE;
		}
	} else if (!strcmp(key, "imap_username")) {
		safe_strncpy(config->imap_username, val, sizeof(config->imap_username));
	} else if (!strcmp(key, "imap_password")) {
		safe_strncpy(config->imap_password, val, sizeof(config->imap_password));
	} else if (!strcmp(key, "smtp_username")) {
		safe_strncpy(config->smtp_username, val, sizeof(config->smtp_username));
	} else if (!strcmp(key, "smtp_password")) {
		/* Unfortunately, we have to keep this password around, since
		 * SMTP connections are set up as needed.
		 * Fat chance this password is different than the IMAP one,
		 * but if it was, this does reduce the attack surface somewhat. */
		safe_strncpy(config->smtp_password, val, sizeof(config->smtp_password));
	} else if (!strcmp(key, "imap_append")) {
		config->imap_append = !strncasecmp(val, "y", 1) || !strcasecmp(val, "on");
	} else {
		return 1;
	}
	return 0;
}

static struct option long_options[] = {
	{ "fromname", 1, NULL, 0 },
	{ "fromaddr", 1, NULL, 0 },
	{ "additional-identities", 1, NULL, 0 },
	{ "imap-hostname", 1, NULL, 0 },
	{ "smtp-hostname", 1, NULL, 0 },
	{ "imap-port", 1, NULL, 0 },
	{ "smtp-port", 1, NULL, 0 },
	{ "imap-security", 1, NULL, 0 },
	{ "smtp-security", 1, NULL, 0 },
	{ "imap-username", 1, NULL, 0 },
	{ "imap-password", 1, NULL, 0 },
	{ "smtp-username", 1, NULL, 0 },
	{ "smtp-password", 1, NULL, 0 },
	{ "imap-append", 1, NULL, 0 },
	{ NULL, 0, NULL, 0 }
};

static void show_help(void)
{
	long unsigned int i;
	printf(EVERGREEN_PROGNAME " " EVERGREEN_VERSION " " EVERGREEN_COPYRIGHT " -- an online only terminal mail user agent\n");
	printf("\n");
	printf("Usage: evergreen [-opts[modifiers]]\n");
	printf("  -c <file>      Load custom config file [default: ./" EVERGREEN_CONFIG_FILE "]\n");
	printf("  -d             Increase debug level for logging (specify 1-10 times)\n");
	printf("  -l             Logfile to use for runtime logging\n");
	printf("  -V             Display program version and exit\n");
	printf("  -?             Display this help and exit\n");
	for (i = 0; i < sizeof(long_options) / sizeof(struct option) - 1; i++) {
		printf("  --%-13s\n", long_options[i].name);
	}
	printf("\n");
}

static int load_config(struct config *restrict config, int argc, char *argv[])
{
	int c;
	FILE *fp;
	char filename[256] = EVERGREEN_CONFIG_FILE;
	int option_index;

	while ((c = getopt_long(argc, argv, getopt_settings, long_options, &option_index)) != -1) {
		switch (c) {
		case 0:
			break; /* Handle all the long options later */
		case 'c':
			safe_strncpy(filename, optarg, sizeof(filename));
			break;
		case 'd':
			debug_level++;
			break;
		case 'h':
		case '?':
			show_help();
			return 1;
		case 'V':
			fprintf(stderr, EVERGREEN_PROGNAME " " EVERGREEN_VERSION " " EVERGREEN_COPYRIGHT "\n");
			return 1;
		default:
			break;
		}
	}

	fp = fopen(filename, "r");
	if (fp) {
		char buf[512];
		/* Simple config parsing */
		while ((fgets(buf, sizeof(buf), fp))) {
			char *tmp;
			char *key, *val = buf;

			tmp = strchr(buf, '#'); /* Ignore comments */
			if (tmp) {
				*tmp = '\0';
			}
			tmp = strchr(buf, '\n');
			if (tmp) {
				*tmp = '\0';
			}
			tmp = strchr(buf, '\r');
			if (tmp) {
				*tmp = '\0';
			}
			if (strlen_zero(val)) {
				continue;
			}
			/* Trim leading whitespace */
			while (*val == ' ') {
				val++;
			}
			if (strlen_zero(val)) {
				continue;
			}
			key = strsep(&val, "=");
			if (strlen_zero(key)) {
				continue;
			}
			if (process_option(config, key, val) < 0) {
				return -1;
			}
		}
		fclose(fp);
	}

	/* Read long command line options */
	optind = 1;
	while ((c = getopt_long(argc, argv, getopt_settings, long_options, &option_index)) != -1) {
		switch (c) {
		case 0:
			if (process_option(config, long_options[option_index].name, optarg) < 0) {
				return -1;
			}
			break;
		case 'l':
			safe_strncpy(config->logfile, optarg, sizeof(config->logfile));
			break;
		default:
			break;
		}
	}

	/* Open log file */
	if (config->logfile[0]) {
		log_fp = fopen(config->logfile, "a");
		if (!log_fp) {
			fprintf(stderr, "Failed to open log file %s: %s\n", config->logfile, strerror(errno));
			explicit_bzero(config->imap_password, sizeof(config->imap_password)); /* Zero the password out from memory */
			explicit_bzero(config->smtp_password, sizeof(config->smtp_password));
			return -1;
		}
	}

	/* Dump options for debugging, here, since log file isn't open prior to this */
	optind = 1;
	phony_options = 1;
	while ((c = getopt_long(argc, argv, getopt_settings, long_options, &option_index)) != -1) {
		switch (c) {
		case 0:
			process_option(config, long_options[option_index].name, optarg);
			break;
		default:
			client_debug(10, "Processed option '%c'", c);
			break;
		}
	}

	/* If still missing stuff (not in config file or on command line), prompt for it on STDIN */
	if (!config->imap_hostname[0] && read_line("IMAP Hostname", config->imap_hostname, sizeof(config->imap_hostname))) {
		return -1;
	}
	/* Assume default port and no security, if not in config file */
	if (!config->imap_username[0] && read_line("IMAP Username", config->imap_username, sizeof(config->imap_username))) {
		return -1;
	}
	if (!config->imap_password[0] && read_hidden_line("IMAP Password", config->imap_password, sizeof(config->imap_password))) {
		return -1;
	}
	if (!config->smtp_password[0] && read_hidden_line("SMTP Password", config->smtp_password, sizeof(config->smtp_password))) {
		return -1;
	}

	if (!config->smtp_username[0]) {
		/* Default to same as imap_username */
		safe_strncpy(config->smtp_username, config->imap_username, sizeof(config->smtp_username));
	}

	return 0;
}

static void handle_SIGWINCH(int sig)
{
	(void) sig;

    if (ncurses_running == CURSES_RUNNING) {
		uint64_t x = 1;
		ssize_t wres = write(event_fd, &x, sizeof(x));
		(void) wres;
    }
}

int main(int argc, char *argv[])
{
	int res = -1;
	struct client client;
	struct config config = {
		.imap_port = 143,
		.smtp_port = 587,
		.imap_security = SECURITY_NONE,
		.smtp_security = SECURITY_NONE,
		.imap_hostname = "127.0.0.1",
		.imap_username = "",
		.imap_password = "",
		.logfile = "",
		.imap_append = 1, /* Save copies of sent messages via IMAP by default */
	};

	memset(&client, 0, sizeof(client));
	client.mouse_enable = 1; /* Enable mouse by default */

	res = load_config(&config, argc, argv);
	if (res) {
		if (res < 0) {
			fprintf(stderr, "Fatal startup error\n");
		}
		return 0;
	}

	event_fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
	if (event_fd < 0) {
		fprintf(stderr, "Failed to open event fd: %s\n", strerror(errno));
		explicit_bzero(config.imap_password, sizeof(config.imap_password)); /* Zero the password out from memory */
		fclose(log_fp);
		exit(errno);
	}

	if (1) {
		/* Allow dumping core */
		struct rlimit limits;
		memset(&limits, 0, sizeof(limits));
		limits.rlim_cur = RLIM_INFINITY;
		limits.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE, &limits)) {
			fprintf(stderr, "Unable to disable core size resource limit: %s\n", strerror(errno));
			explicit_bzero(config.imap_password, sizeof(config.imap_password)); /* Zero the password out from memory */
			goto cleanup;
		}
	}

	/* Install our own signal handler, even though ncurses includes one,
	 * since KEY_RESIZE is only returned by getch,
	 * and doesn't involve poll(STDIN) returning any activity.
	 * Our custom signal handler also ensures that our poll() call gets woken up. */
	if (signal(SIGPIPE, SIG_IGN) || signal(SIGWINCH, handle_SIGWINCH)) {
		fprintf(stderr, "Failed to install signal handler: %s", strerror(errno));
		explicit_bzero(config.imap_password, sizeof(config.imap_password)); /* Zero the password out from memory */
		goto cleanup;
	}

	/* Initialize terminal */
	if (client_term_init(&client)) {
		explicit_bzero(config.imap_password, sizeof(config.imap_password)); /* Zero the password out from memory */
		goto cleanup;
	}

	client_debug(1, "--------------- Starting session ---------------");

	/* Connect to the IMAP server */
	if (client_connect(&client, &config)) {
		explicit_bzero(config.imap_password, sizeof(config.imap_password)); /* Zero the password out from memory */
		goto cleanup;
	}

	/* Authenticate to the IMAP server */
	res = client_login(&client, &config);
	if (!res) {
		/* Load the main menu */
		client.config = &config; /* So later we can access the username, hostname, etc. */
		res = client_menu(&client);
	} else {
		/* Wait for keypress to exit */
		getch();
	}

	/* Clean up terminal */
	client_term_cleanup(&client);
	free_if(config.additional_identities);
	client_destroy(&client);
	client_debug(1, "--------------- Ending session %d ---------------", res);

cleanup:
	close(event_fd);
	if (log_fp) {
		fclose(log_fp);
	}
	return res;
}
