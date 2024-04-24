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
 * \brief Menus and menu management
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "evergreen.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

static inline int set_display_name(struct client *client, struct mailbox *mbox)
{
	int res;
	char buf[84];
	int expanded_width = 0;
	char expanded[20] = "";
	char sizebuf[12];
	int width, sizelen;
	int hierarchy = 0;
	const char *leafname, *tmp;

	free_if(mbox->display);

	/* Collapse hierarchy delimiter for subfolders.
	 * Visually, this works great, assuming all subfolders are provided in order. */
	tmp = leafname = mbox->name;
	while (*tmp) {
		if (*tmp == client->delimiter) {
			hierarchy++;
			leafname = tmp + 1;
		}
		tmp++;
	}
	if (!*leafname) {
		client_warning("Mailbox name '%s' ends in hierarchy delimiter?\n", mbox->name);
		return -1;
	}

	if (COLS >= MIN_COLS_FOR_EXPANDED_LIST_INFO) {
		/* If we have enough space, also include the total message count */
		expanded_width = snprintf(expanded, sizeof(expanded), "[%d]", mbox->total);
	}

	if (mbox->unseen) {
		snprintf(buf, sizeof(buf), "%s%.*s%s (%d)", mbox->flags & IMAP_MAILBOX_MARKED ? "*" : " ", hierarchy, SPACES, leafname, mbox->unseen);
	} else {
		snprintf(buf, sizeof(buf), "%s%.*s%s", " ", hierarchy, SPACES, leafname);
	}

	if (mbox->size == 0) {
		sizebuf[0] = '\0';
		sizelen = 0;
	} else if (mbox->size < 1000) {
		sizelen = snprintf(sizebuf, sizeof(sizebuf), " [%luB]", mbox->size);
	} else if (SIZE_KB(mbox->size) < 1000) {
		sizelen = snprintf(sizebuf, sizeof(sizebuf), " [%luK]", SIZE_KB(mbox->size));
	} else {
		sizelen = snprintf(sizebuf, sizeof(sizebuf), " [%luM]", SIZE_MB(mbox->size));
	}

	width = LIST_PANE_WIDTH - sizelen - expanded_width;
	/* Right-align the size, if present */
	res = asprintf(&mbox->display, "%-*s%s%s", width, buf, expanded, sizebuf);
	return res < 0 ? -1 : 0;
}

int create_folder_items(struct client *client)
{
	int i;

	/* Generate folder listing of mailboxes */
	client->folders.items = calloc(client->num_mailboxes + 1, sizeof(ITEM*));
	if (!client->folders.items) {
		return -1;
	}
	client->folders.n = client->num_mailboxes;
	for (i = 0; i < client->num_mailboxes; i++) {
		/* Construct the display name now, as opposed to during LIST,
		 * since we might update its properties during runtime without redoing LIST. */
		if (set_display_name(client, &client->mailboxes[i])) {
			return -1;
		}
		client->folders.items[i] = new_item(client->mailboxes[i].display, "");
		if (!client->folders.items[i]) {
			client_error("Failed to create item %d", i);
			/* Leaks, but we're exiting */
			return -1;
		}
		if (client->mailboxes[i].flags & IMAP_MAILBOX_NOSELECT) {
			item_opts_off(client->folders.items[i], O_SELECTABLE); /* Don't allow selection of NoSelect mailboxes */
		}
		set_item_userptr(client->folders.items[i], &client->mailboxes[i]); /* Store mailbox as callback data */
	}
	client->folders.items[client->folders.n] = NULL; /* Array must be NULL terminated */
	return 0;
}

void free_folder_items(struct client *client)
{
	int i;

	if (client->folders.items) {
		for (i = 0; i < client->folders.n; i++) {
			if (client->folders.items[i]) {
				free_item(client->folders.items[i]);
			}
			free_if(client->mailboxes[i].display);
		}
		free(client->folders.items);
		client->folders.items = NULL;
	}
	client->folders.n = 0;
}

static int setup_menu(struct client *client, ITEM **items, MENU **restrict menuptr, WINDOW *win, int height, int width)
{
	MENU *menu;

	assert(items != NULL);
	if (!*items) {
		client_error("Item list is empty?");
		return -1;
	}

	menu = new_menu(items);
	if (!menu) {
		client_error("Failed to create menu");
		return -1;
	/* These must hold or post_menu will return E_NOT_CONNECTED */
	} else if (!menu->items) {
		client_error("Menu has no items?");
		return -1;
	}

	set_menu_win(menu, win);
	/* We can't seem to use wbkgd here to set the colors,
	 * so do that manually for each item instead. */
	set_menu_sub(menu, derwin(win, height, width, 0, 0));
	set_menu_format(menu, height, 1); /* rows, cols (of options) */
	set_menu_mark(menu, ""); /* No need for a mark, whatever's selected is already highlighted */
	*menuptr = menu;
	return 0;
}

int create_folder_menu(struct client *client)
{
	if (client->folders.n == 0) {
		client_debug(1, "Can't create empty menu");
		return 0;
	}
	if (setup_menu(client, client->folders.items, &client->folders.menu, client->win_folders, LIST_PANE_HEIGHT, LIST_PANE_WIDTH)) {
		return -1;
	}
	return 0;
}

void cleanup_folder_menu(struct client *client)
{
	if (client->folders.menu) {
		unpost_menu(client->folders.menu);
		free_menu(client->folders.menu);
		client->folders.menu = NULL;
	}
}

static inline void format_subject(char *restrict buf, size_t len, int width, const char *s)
{
	if (!s) {
		*buf = '\0';
		return;
	}
	if (!strncasecmp(s, "Re: ", 4)) {
		s += 4;
	}
	safe_strncpy(buf, s, len);
	if (strlen(buf) > (size_t) width) {
		buf[width - 1] = '.';
		buf[width - 2] = '.';
	}
}

static inline void format_addr(char *restrict buf, size_t len, int width, const char *s)
{
	char *tmp;
	int quotes;
	if (!s) {
		*buf = '\0';
		return;
	}

	/* If begins with a quote, don't copy that */
	quotes = *s == '"';
	safe_strncpy(buf, quotes ? s + 1 : s, len);

	/* If name <addr>, just keep the name */
	if (*buf != '<') {
		tmp = strchr(buf, '<');
		if (tmp > buf) {
			tmp--;
			*tmp = '\0';
		}
	}
	if (strlen(buf) > (size_t) width) {
		buf[width - 1] = '.';
		buf[width - 2] = '.';
	}

	if (quotes) {
		/* If surrounded by quotes, strip em */
		tmp = strchr(buf, '"');
		if (tmp) {
			char *tmp2 = tmp + 1;
			if (!*tmp2) {
				*tmp = '\0';
			}
		}
	}
}

static inline void format_mpane_date(struct tm *tm, time_t now, char *buf, size_t len)
{
	time_t msgtime = mktime(tm);
	time_t diff = now - msgtime; /* The more recent the message, the more specific we should be */
	if (diff >= 0 && diff < 3600 * 18) {
		/* Within past 23 hours, don't display date */
		strftime(buf, len, "%I:%M:%S %P", tm); /* HH:MM:SS AA = 11 */
	} else if (diff >= 0 && diff < 3600 * 24 * 364) {
		/* Within past year, don't display year */
		strftime(buf, len, "%m/%d %H:%M", tm); /* mm/dd HH:MM = 11 */
	} else {
		/* In the future, or longer ago than a year */
		strftime(buf, len, "%m/%d/%g %H", tm); /* mm/dd/yy HH = 11 */
	}
}

static inline int fmt_msg(struct message *msg, time_t now, int maxseqlen, int maxuidlen)
{
	int res;
	int widths[5] = {0, 0, 22, 21, 0}; /* Safe for 80 columns */
	char date[12], received[13];
	char subject[84];
	char from[84];
	char sizebuf[16]; /* Could be 6, and no more than 6 is needed, larger to silence snprintf truncation warnings */
	int baselen;
	char seqbuf[10] = "", uidbuf[10] = "";
	int sequidlen;

	free_if(msg->display);

	/* We need to format a single line, within the limitations of COLS.
	 * Use progressive enhancement based on how much space we have. */

	if (msg->size < 1000) {
		snprintf(sizebuf, sizeof(sizebuf), "%3luB", msg->size);
	} else if (SIZE_KB(msg->size) < 1000) {
		snprintf(sizebuf, sizeof(sizebuf), "%3luK", SIZE_KB(msg->size));
	} else {
		if (SIZE_MB(msg->size) > 999) { /* Yeah, right... */
			snprintf(sizebuf, sizeof(sizebuf), ">1KM");
		} else {
			snprintf(sizebuf, sizeof(sizebuf), "%3luK", SIZE_MB(msg->size));
		}
	}

	format_mpane_date(&msg->date, now, date, sizeof(date));

	/* If we have room: seqno, UID... received date */
	baselen = 64;
	sequidlen = maxseqlen + maxuidlen + 2; /* Spaces on each side */
	if (MAIN_PANE_WIDTH > baselen + sequidlen) {
		snprintf(seqbuf, sizeof(seqbuf), " %u", msg->seqno);
		snprintf(uidbuf, sizeof(uidbuf), " %u", msg->uid);
		widths[0] = maxseqlen + 1; /* Don't make the seqno column any longer than total # of messages in mailbox. */
		widths[1] = maxuidlen + 1; /* Don't make the UID column any longer than UIDNEXT */
		baselen += sequidlen;
	}

	if (MAIN_PANE_WIDTH > baselen) {
		int x, extra = MAIN_PANE_WIDTH - baselen;
		if (extra > 512) {
			extra = 512; /* Huh? */
		}
		/* Distribute the extra space amongst Subject and From.
		 * If we have enough room, add a column for Received timestamp (INTERNALDATE). */
		if (MAIN_PANE_WIDTH >= 106) {
			extra -= 12;
			widths[4] = 12;
			format_mpane_date(&msg->intdate, now, received, sizeof(received));
			received[sizeof(received) - 2] = ' '; /* Space before next column */
		}
		x = extra / 2;
		widths[2] += x;
		extra -= x;
		widths[3] += extra;
	}

	/* Importance, Flags, Sequence Number, UIDNEXT, Subject, From, Date, Size */
	/* The format itself eats up 21 characters, without the widths[]. */
	format_subject(subject, sizeof(subject), widths[2], msg->subject);
	format_addr(from, sizeof(from), widths[3], msg->from);
	res = asprintf(&msg->display, "%1c%1c%*.*s%*.*s %-*.*s %-*.*s %*.*s%11.11s %4.4s",
		msg->flags & IMAP_MESSAGE_FLAG_DELETED ? 'T': msg->flags & IMAP_MESSAGE_FLAG_FLAGGED ? 'F' : msg->importance > 5 ? '!' : ' ',
		msg->flags & IMAP_MESSAGE_FLAG_SEEN ? ' ' : msg->flags & IMAP_MESSAGE_FLAG_RECENT ? '%' : '*',
		widths[0], widths[0], seqbuf,
		widths[1], widths[1], uidbuf,
		widths[2], widths[2], subject,
		widths[3], widths[3], from,
		widths[4], widths[4], received,
		date,
		sizebuf);
	return res < 0 ? -1 : 0;
}

/*! \brief Strip characters that curses will not print in a menu title, such as Unicode */
static void sanitize_for_curses(char *s)
{
	while (*s) {
		if (!isprint(*s) || *s >= 128) {
			*s = '?';
		}
		s++;
	}
}

int create_message_items(struct client *client)
{
	int i;
	char buf[15];
	int maxseqlen, maxuidlen;
	time_t now;
	struct message *msg;

	if (!num_messages(client)) {
		client_error("Mailbox supposedly has %u msgs?", client->sel_mbox->total);
	}

	assert(num_messages(client) > 0);

	/* Compute values used by each fmt_msg call */
	now = time(NULL);
	/* Give some room for growth, too, so add a few hundred */
	maxseqlen = snprintf(buf, sizeof(buf), "%u", client->sel_mbox->total + 500);
	maxuidlen = snprintf(buf, sizeof(buf), "%u", client->sel_mbox->uidnext + 500);

	/* Generate message pane menu */
	client->message_list.items = calloc(num_messages(client) + 1, sizeof(ITEM*));
	if (!client->message_list.items) {
		return -1;
	}
	client->message_list.n = num_messages(client);
	msg = get_msg(client, 0);
	for (i = 0; i < client->message_list.n; i++) {
		if (fmt_msg(msg, now, maxseqlen, maxuidlen)) {
			return -1;
		}
		sanitize_for_curses(msg->display);
		client->message_list.items[i] = new_item(msg->display, "");
		if (!client->message_list.items[i]) {
			client_error("Failed to create item %d: %s", i, msg->display);
			/* Leaks, but we're exiting */
			return -1;
		}
		set_item_userptr(client->message_list.items[i], msg); /* Store message as callback data */
		msg = msg->next;
	}
	client->message_list.items[client->message_list.n] = NULL; /* Array must be NULL terminated */
	return 0;
}

void free_message_items(struct client *client)
{
	int i;

	if (!client->message_list.items) {
		return;
	}

	assert(num_messages(client) != 0);
#if 0
	/* Not necessarily true, since if we redraw message pane due to EXISTS/EXPUNGE, will be different at this point */
	assert(num_messages(client) == client->message_list.n);
#endif
	for (i = 0; i < client->message_list.n; i++) {
		if (client->message_list.items[i]) {
			free_item(client->message_list.items[i]);
		}
	}
	free(client->message_list.items);
	client->message_list.items = NULL;
	client->message_list.n = 0;
}

int create_messages_menu(struct client *client)
{
	if (client->message_list.n == 0) {
		client_debug(1, "Can't create empty menu");
		return 0;
	}
	if (setup_menu(client, client->message_list.items, &client->message_list.menu, client->win_main, MAIN_PANE_HEIGHT, MAIN_PANE_WIDTH)) {
		return -1;
	}
	return 0;
}

void cleanup_message_menu(struct client *client)
{
	if (client->message_list.menu) {
		unpost_menu(client->message_list.menu);
		free_menu(client->message_list.menu);
		client->message_list.menu = NULL;
	}
}

int get_mailbox_selection(struct client *client, struct pollfd *pfds, struct mailbox **restrict sel_mbox, struct mailbox *default_sel)
{
	ITEM *selection = NULL;
	ITEM **items;
	MENU *menu;
	WINDOW *window;
	int i, res = 0;

	items = calloc(client->num_mailboxes + 1, sizeof(ITEM*));
	if (!items) {
		return -1;
	}
	for (i = 0; i < client->num_mailboxes; i++) {
		/* The display name won't change while the menu is running, so we can reuse that and avoid allocating a string.
		 * We want to use the display name and not the name, since this better visually handles subfolders. */
		items[i] = new_item(client->mailboxes[i].display, "");
		if (!client->folders.items[i]) {
			client_error("Failed to create item %d", i);
			/* Leaks, but we're exiting */
			return -1;
		}
		if (client->mailboxes[i].flags & IMAP_MAILBOX_NOSELECT) {
			item_opts_off(items[i], O_SELECTABLE); /* Don't allow selection of NoSelect mailboxes */
		}
		set_item_userptr(items[i], &client->mailboxes[i]); /* Store mailbox as callback data */
		if (&client->mailboxes[i] == default_sel) {
			/* Override for default preselected item */
			selection = items[i];
		}
	}
	items[client->folders.n] = NULL; /* Array must be NULL terminated */
	if (!default_sel) {
		selection = items[1]; /* items[0] corresponds to the pseudo mailbox for aggregate stats, so skip that one for sure */
	}
	client_set_status_nout(client, "Select destination mailbox");

redraw:
	/* One thing to note is that the folder names will be in the upper left corner,
	 * just like with the folder pane. This means that, visually, this operation
	 * is sometimes akin to just hiding the message pane, which makes it more efficient
	 * from a redraw perspective. */
	window = newwin(LINES - 2, COLS, 1, 0); /* Full screen, minus top and bottom row */

	if (!window) {
		return -1;
	} else if (setup_menu(client, items, &menu, window, LIST_PANE_HEIGHT, COLS)) {
		return -1;
	}

	if (selection) {
		/* Restore selection after window resize */
		set_current_item(menu, selection);
	}

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
			goto done; /* Exit without selection */
		case KEY_RESIZE:
			/* Save selection and restore */
			selection = current_item(menu);
			if (selection == items[0]) {
				selection = items[1];
			}
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
		case KEY_NPAGE:
			menu_driver(menu, REQ_SCR_DPAGE);
			wrefresh(window);
			break;
		case KEY_PPAGE:
			menu_driver(menu, REQ_SCR_UPAGE);
			wrefresh(window);
			break;
		case KEY_ENTER:
			selection = current_item(menu);
			*sel_mbox = item_userptr(selection);
			if ((*sel_mbox)->flags & IMAP_MAILBOX_NOSELECT) {
				*sel_mbox = NULL;
				client_set_status_nout(client, "Can't select this mailbox");
				doupdate();
				break;
			} else if (*sel_mbox == client->sel_mbox) {
				*sel_mbox = NULL;
				client_set_status_nout(client, "Can't select same mailbox");
				doupdate();
				break;
			}
			goto done;
		default:
			beep();
			break;
		}
	}

done:
	/* Clean up */
	unpost_menu(menu);
	free_menu(menu);
	for (i = 0; i < client->num_mailboxes; i++) {
		free_item(items[i]);
	}
	delwin(window);
	return res;
}

int prompt_confirm(struct client *client, struct pollfd *pfds, const char *title, const char *subtitle)
{
	/* There is a dialog library (<dialog.h>, -ldialog), but that adds another layer on top of ncurses,
	 * so just do it using the latter, directly. */
	ITEM *selection = NULL;
	ITEM *items[3];
	MENU *menu;
	WINDOW *window;
	int res = 0;
	int sline, scol;

	items[0] = new_item("  Yes ", "");
	items[1] = new_item("  No  ", "");
	items[2] = NULL; /* Null terminate */

redraw:
	window = newwin(LINES - 2, COLS, 1, 0); /* Full screen, minus top and bottom row */

	if (!window) {
		return -1;
	}

	menu = new_menu(items);
	if (!menu) {
		return -1;
	}

	sline = LINES / 2 - 5;
	if (sline < 1) {
		sline = 1;
	}
	if (title) {
		scol = COLS / 2 - strlen(title) / 2;
		mvwaddstr(window, sline, scol, title);
	}
	if (subtitle) {
		scol = COLS / 2 - strlen(subtitle) / 2;
		mvwaddstr(window, sline + 2, scol, subtitle);
	}

	/* Override defaults, center the menu, and make it stand out more */
	set_menu_sub(menu, derwin(window, 4, 22, sline + 4, COLS / 2 - 11));
	set_menu_format(menu, LIST_PANE_HEIGHT, 2); /* rows, cols (of options) */
	set_menu_mark(menu, "  *  ");

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
			goto done; /* Exit without selection */
		case KEY_RESIZE:
			/* Save selection and restore */
			selection = current_item(menu);
			unpost_menu(menu);
			free_menu(menu);
			delwin(window);
			goto redraw;
		case KEY_RIGHT:
		case KEY_DOWN:
			menu_driver(menu, REQ_NEXT_ITEM);
			wrefresh(window);
			break;
		case KEY_LEFT:
		case KEY_UP:
			menu_driver(menu, REQ_PREV_ITEM);
			wrefresh(window);
			break;
		case '\n':
		case KEY_ENTER:
			selection = current_item(menu);
			if (selection == items[0]) {
				res = 1;
			}
			goto done;
		default:
			beep();
			break;
		}
	}

done:
	/* Clean up */
	unpost_menu(menu);
	free_menu(menu);
	free_item(items[0]);
	free_item(items[1]);
	delwin(window);
	client_debug(5, "Confirmation result: %d", res);
	return res;
}
