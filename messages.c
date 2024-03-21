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
 * \brief Messages container and message operations
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "evergreen.h"

#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <assert.h>

/* Some parameters are no longer used, since they were used
 * when the entire list of messages was allocated with a single calloc call.
 * This has since been rewritten to use linked lists, for flexibility
 * in inserting or deleting messages into the container without having
 * to rebuild the entire list, which reduces the number of fetchlist
 * operations we need to do, reducing bandwidth consumption and speeding
 * up responsiveness.
 */

int init_messages(struct client *client, int num_msgs)
{
	(void) num_msgs;
	client->messages.mhead.next = &client->messages.mhead;
	client->messages.mhead.prev = &client->messages.mhead; /* Make this a doubly linked list */
	client->messages.mhead.seqno = 0;
	client->messages.mhead.uid = 0;
	client->messages.num_messages = 0;
	return 0;
}

uint32_t num_messages(struct client *client)
{
	return client->messages.num_messages;
}

struct message *next_message(struct message *msg)
{
	struct message *next = msg->next;
	if (next->uid == 0) {
		return NULL;
	}
	return next;
}

struct message *new_message(struct client *client, int index, int seqno)
{
	struct message *end, *msg = calloc(1, sizeof(struct message));

	if (unlikely(!msg)) {
		return NULL;
	}

	msg->index = index;
	msg->seqno = seqno;
	msg->next = NULL;
	msg->prev = NULL;

	/* Insert after last element */
	end = client->messages.mhead.prev;
	insque(msg, end);

	client->messages.num_messages++;
	return msg;
}

#define MSG_SEEN(m) (msg->flags & IMAP_MESSAGE_FLAG_SEEN)

void mark_message_unseen(struct mailbox *mbox, struct message *msg)
{
	if (MSG_SEEN(msg)) {
		mbox->unseen++;
		msg->flags &= ~IMAP_MESSAGE_FLAG_SEEN;
	}
}

void mark_message_seen(struct mailbox *mbox, struct message *msg)
{
	if (!MSG_SEEN(msg)) {
		mbox->unseen--;
		msg->flags |= IMAP_MESSAGE_FLAG_SEEN;
	}
}

void mark_message_read(struct mailbox *mbox, struct message *msg)
{
	if (msg->flags & IMAP_MESSAGE_FLAG_RECENT) {
		if (!--mbox->recent) {
			/* If no recent messages are left, the mailbox should not be marked anymore */
			mbox->flags &= ~IMAP_MAILBOX_MARKED;
		}
		msg->flags &= ~IMAP_MESSAGE_FLAG_RECENT;
	}
	mark_message_seen(mbox, msg);
}

static void increment_stats(struct mailbox *mbox, struct message *msg)
{
	mbox->size += msg->size;
	mbox->total++;
	mbox->recent++;
	if (!(msg->flags & IMAP_MESSAGE_FLAG_SEEN)) {
		mbox->unseen++;
	}
}

static void decrement_stats(struct mailbox *mbox, struct message *msg)
{
	mbox->size -= msg->size;
	mbox->total--;
	mark_message_read(mbox, msg);
}

static inline void destroy_cached_message(struct message *msg)
{
	free_if(msg->from);
	free_if(msg->subject);
	free_if(msg->display);
}

static void free_message(struct client *client, struct message *msg)
{
	destroy_cached_message(msg);
	remque(msg);
	free(msg);
	client->messages.num_messages--;
}

void delete_message(struct client *client, struct message *msg)
{
	decrement_stats(client->sel_mbox, msg);
	free_message(client, msg);
}

int handle_message_op(struct client *client, struct pollfd *pfds, struct message *msg, struct message_data *mdata, int c)
{
	int res, cur;
	char statusbuf[96];
	struct message *next;
	struct mailbox *destmbox = client->cpmv_mbox;

	/* Mailbox/message options */
	switch (c) {
	case 'U': /* Mark unread and return */
	case 'u': /* Mark unread */
		if (MSG_SEEN(msg)) {
			if (client_idle_stop(client) || client_store_seen(client, -1, msg)) {
				return -1;
			}
			mark_message_unseen(client->sel_mbox, msg);
			client->mailboxes[0].unseen++; /* This is the aggregate pseudo mailbox */
			display_mailbox_info(client); /* Update permanent status bar before setting status, since it will clear the whole line */
			client_set_status_nout(client, "Marked as unread");
		} else {
			client_set_status_nout(client, "Already marked as unread");
			beep();
			return 0; /* No need to redraw anything, just update the status message */
		}
		return c == 'U' ? 2 : 1; /* Need to toggle seen in message pane, and update stats for mailbox in folder pane */
	case 's': /* Mark seen */
		if (!MSG_SEEN(msg)) {
			if (client_idle_stop(client) || client_store_seen(client, +1, msg)) {
				return -1;
			}
			mark_message_seen(client->sel_mbox, msg);
			client->mailboxes[0].unseen--;
			display_mailbox_info(client); /* Update permanent status bar before setting status, since it will clear the whole line */
			client_set_status_nout(client, "Marked as read");
		} else {
			client_set_status_nout(client, "Already marked as read");
			beep();
			return 0; /* No need to redraw anything, just update the status message */
		}
		return 1; /* Need to toggle seen in message pane, and update stats for mailbox in folder pane */
	case 'F': /* Toggle flagged/unflagged */
		cur = msg->flags & IMAP_MESSAGE_FLAG_FLAGGED ? 1 : 0;
		if (client_idle_stop(client) || client_store_flagged(client, cur ? -1 : +1, msg)) {
			return -1;
		}
		msg->flags ^= IMAP_MESSAGE_FLAG_FLAGGED; /* Toggle */
		/* Permanent status bar has not changed */
		client_set_status_nout(client, cur ? "Unflagged message" : "Flagged message");
		return 1; /* Need to toggle seen in message pane (folder pane technically hasn't changed, for this specific case) */
	case 'r': /* Reply */
		res = reply(client, pfds, msg, mdata, 0);
		if (res < 0) {
			return res;
		}
		break;
	case 'R': /* Reply All */
		res = reply(client, pfds, msg, mdata, 1);
		if (res < 0) {
			return res;
		}
		break;
	case 'f': /* Forward */
		res = forward(client, pfds, msg, mdata);
		if (res < 0) {
			return res;
		}
		break;
	case 'c': /* Copy to mailbox */
		/* Make the default (preselected item) wherever we last moved/copied something. */
		SUB_MENU_PRE;
		res = get_mailbox_selection(client, pfds, &destmbox, client->cpmv_mbox);
		SUB_MENU_POST_NORESIZE;
		/* Fall through */
	case 'C': /* Copy to last dest mailbox */
		if (!destmbox) {
			client_set_status_nout(client, "No target mailbox for copy");
			beep();
			return 1; /* Need to redraw message pane at this point */
		}
		if (client_idle_stop(client) || client_copy(client, msg, destmbox->name)) {
			return -1;
		}
		increment_stats(destmbox, msg);
		increment_stats(&client->mailboxes[0], msg); /* Unlike move, which is a net zero change in aggregate stats, this increases them */
		/* Unlike move, we don't unlink the message from the current mailbox, we keep it here */
		client->cpmv_mbox = destmbox; /* If succeeded, save for next time */
		snprintf(statusbuf, sizeof(statusbuf), "Copied to %s", destmbox->name);
		/* This mailbox has not been modified, no need to update permanent status bar */
		client_set_status_nout(client, statusbuf);
		break;
	case 'm': /* Move to mailbox */
		SUB_MENU_PRE;
		res = get_mailbox_selection(client, pfds, &destmbox, client->cpmv_mbox);
		SUB_MENU_POST_NORESIZE;
		/* Fall through */
	case 'M': /* Move to last dest mailbox */
		if (!destmbox) {
			client_set_status_nout(client, "No target mailbox for move");
			beep();
			return 1; /* Need to redraw message pane at this point */
		}
		if (client_idle_stop(client) || client_move(client, msg, destmbox->name)) {
			return -1;
		}
		increment_stats(destmbox, msg);
		next = msg->next;
		delete_message(client, msg); /* Unlike copy, purge the message from the current mailbox */
		resequence_messages(next); /* Renumber all higher sequenced numbers */
		client->cpmv_mbox = destmbox; /* If succeeded, save for next time */
		snprintf(statusbuf, sizeof(statusbuf), "Moved to %s", destmbox->name);
		display_mailbox_info(client); /* Update permanent status bar before setting status, since it will clear the whole line */
		client_set_status_nout(client, statusbuf);
		break;
	case 'l': /* Display last dest mailbox in status bar */
		if (client->cpmv_mbox) {
			char statusmsg[128];
			snprintf(statusmsg, sizeof(statusmsg), "Last dst: %s", client->cpmv_mbox->name);
			client_set_status_nout(client, statusmsg);
		} else {
			client_set_status_nout(client, "No last dst");
		}
		return 0; /* Don't need to redraw anything */
	case 'j': /* Move to junk */
		if (!client->junk_mbox) {
			client_set_status_nout(client, "Can't auto-determine junk mailbox");
			beep();
			return 0;
		} else if (client->junk_mbox == client->sel_mbox) {
			client_set_status_nout(client, "Already in junk");
			beep();
			return 0;
		}
		if (client_idle_stop(client) || client_move(client, msg, client->junk_mbox->name)) {
			return -1;
		}
		increment_stats(client->junk_mbox, msg);
		next = msg->next;
		delete_message(client, msg); /* Unlike copy, purge the message from the current mailbox */
		resequence_messages(next); /* Renumber all higher sequenced numbers */
		/* Do not overwrite client->cpmv_mbox for junk/trash */ 
		snprintf(statusbuf, sizeof(statusbuf), "Moved to %s", client->junk_mbox->name);
		display_mailbox_info(client); /* Update permanent status bar before setting status, since it will clear the whole line */
		client_set_status_nout(client, statusbuf);
		break;
	case 't': /* Move to trash */
	case KEY_DL:
		if (!client->trash_mbox) {
			client_set_status_nout(client, "Can't auto-determine trash mailbox");
			beep();
			return 0;
		} else if (client->trash_mbox == client->sel_mbox) {
			client_set_status_nout(client, "Already in trash");
			beep();
			return 0;
		}
		if (client_idle_stop(client) || client_move(client, msg, client->trash_mbox->name)) {
			return -1;
		}
		increment_stats(client->trash_mbox, msg);
		next = msg->next;
		delete_message(client, msg); /* Unlike copy, purge the message from the current mailbox */
		resequence_messages(next); /* Renumber all higher sequenced numbers */
		/* Do not overwrite client->cpmv_mbox for junk/trash */ 
		snprintf(statusbuf, sizeof(statusbuf), "Moved to %s", client->trash_mbox->name);
		display_mailbox_info(client); /* Update permanent status bar before setting status, since it will clear the whole line */
		client_set_status_nout(client, statusbuf);
		break;
	default:
		/* This function must not be called for other options */
		assert(0);
		return -1;
	}

	/* Success, but redraw since stuff changed.
	 * In all cases, both the message and folder panes have chaned. */
	return 2;
}

int handle_emptytrash(struct client *client)
{
	struct message *msg;
	int i, num_msgs = num_messages(client);

	if (!num_msgs) {
		/* Nothing to do */
		client_set_status_nout(client, "Mailbox empty");
		return 0;
	}

	if (client->sel_mbox != client->trash_mbox) {
		/* Don't allow users to accidentally empty a folder that's not a trash mailbox,
		 * particularly as this operation is allowed from the top-level menu at any time */
		client_set_status_nout(client, "Not a trash mailbox");
		return 0;
	}

	/* STORE 1:* +FLAGS \\Deleted */
	if (client_idle_stop(client) || client_store(client, +1, NULL, IMAP_MESSAGE_FLAG_DELETED)) {
		return -1;
	}

	msg = get_msg(client, 0);
	for (i = 0; i < num_msgs; i++, msg = msg->next) {
		msg->flags |= IMAP_MESSAGE_FLAG_DELETED;
	}

	client_set_status_nout(client, "Marked all messages for deletion");
	return 0;
}

int handle_expunge(struct client *client, struct pollfd *pfds)
{
	struct message *msg;
	static char subtitle[196];
	int deleted = 0;
	int i, res, num_msgs = num_messages(client);

	if (!num_msgs) {
		/* Nothing to do */
		client_set_status_nout(client, "Mailbox empty, nothing to expunge");
		return 0;
	}

	/* Always prompt for confirmation, since we don't know how many messages in this mailbox
	 * have the \\Deleted flag set. We can check the flags of messages currently in memory,
	 * but messages "out of view" of the current menu, we won't know about.
	 * Therefore, always assume this could potentially be a destructive action.
	 *
	 * In theory, we could query the IMAP server to see how many messages in this entire mailbox
	 * have the \\Deleted flag set.
	 *
	 * That said, a good chunk of the time, messages with this flag probably *are* in view,
	 * and we should confirm that, too. */
	msg = get_msg(client, 0);
	for (i = 0; i < num_msgs; i++, msg = msg->next) {
		if (msg->flags & IMAP_MESSAGE_FLAG_DELETED) {
			deleted++;
		}
	}

	snprintf(subtitle, sizeof(subtitle), "\\Deleted flag set on %d+ message%s (possibly more)! Really expunge?", deleted, deleted == 1 ? "" : "s");
	SUB_MENU_PRE;
	res = prompt_confirm(client, pfds, "Expunge Current Mailbox?", subtitle);
	SUB_MENU_POST_NORESIZE;
	if (!res) {
		client_set_status_nout(client, "Expunge cancelled");
		return 0;
	} else {
		if (client_idle_stop(client) || client_expunge(client)) {
			return -1;
		}
		client_set_status_nout(client, "Mailbox expunged");
		/* Since we may have expunged messages we didn't know about, we need to do a STATUS to get back in sync. */
		if (client_status_command(client, client->sel_mbox, NULL)) {
			return -1;
		}
		return 0;
	}
}

#ifdef DEBUG_MODE
struct message *__get_msg(struct client *client, int index, const char *file, int line)
#else
struct message *__get_msg(struct client *client, int index)
#endif
{
	int i;
	struct message *msg;

	/* The loop invariant could include:
	 * i < client->messages.num_messages
	 * However, since we know that index exists,
	 * we can just make it:
	 * i < index
	 */

	assert(client->messages.num_messages > 0);

	if (index < client->messages.num_messages / 2 + 1) { /* Index 0 should be in this path, and index 1/1 (last of 2 messages) should not be */
		msg = client->messages.mhead.next;
		/* In first half of list */
		for (i = 0; i < index; i++) {
			msg = msg->next;
		}
	} else {
		/* In second half of list, start at the back */
		msg = client->messages.mhead.prev;
		for (i = client->messages.num_messages - 1; i > index; i--) {
			msg = msg->prev;
		}
	}
	if (unlikely(msg == NULL || msg == &client->messages.mhead)) {
		client_error("Invalid message index: %d / %p", index, msg);
		assert(msg != NULL && msg != &client->messages.mhead); /* Crash */
	}
	if (unlikely(msg->index != index)) {
		client_error("Wanted index but got: %d / %d", index, msg->index);
		assert(msg->index == index); /* Crash */
	}
#ifdef DEBUG_MODE
	client_debug(1, "%s:%d - Found message index %d", file, line, index);
#endif
	return msg;
}

struct message *get_msg_by_seqno(struct client *client, uint32_t seqno)
{
	/* Since we don't know where it is, not much point in calling find_message_by_seqno and then get_msg */
	int i;
	struct message *msg;

	assert(client->messages.num_messages > 0);

	if (seqno < client->start_seqno - FETCHLIST_INTERVAL / 2) {
		msg = client->messages.mhead.next;
		/* In first half of list */
		for (i = 0; i < client->messages.num_messages; i++) {
			if (msg->seqno == seqno) {
				break;
			}
			msg = msg->next;
		}
	} else {
		/* In second half of list, start at the back */
		msg = client->messages.mhead.prev;
		for (i = client->messages.num_messages - 1; i > 0; i--) {
			if (msg->seqno == seqno) {
				break;
			}
			msg = msg->prev;
		}
	}
	assert(msg != NULL);
	if (unlikely(msg->seqno != seqno)) {
		client_warning("Message with seqno %u has seqno %u/%d [%u,%u]?", msg->seqno, seqno, client->sel_mbox->total, client->start_seqno, client->start_seqno + client->message_list.n - 1);
		assert(msg->seqno == seqno);
	}
	return msg;
}

struct message *get_msg_by_uid(struct client *client, uint32_t uid)
{
	/* Since we don't know where it is, not much point in calling find_message_by_seqno and then get_msg */
	int i;
	struct message *msg;

	assert(client->messages.num_messages > 0);

	/* Since UIDs can be all over the place, not really much telling
	 * if it'll be in the first half or the second half.
	 * Just do a linear scan. */

	msg = client->messages.mhead.next;
	for (i = 0; i < client->messages.num_messages; i++, msg = msg->next) {
		if (msg->uid == uid) {
			return msg;
		}
	}

	return NULL;
}

int find_message_by_seqno(struct client *client, uint32_t seqno)
{
	int i;
	struct message *msg = client->messages.mhead.next;
	for (i = 0; i < client->messages.num_messages; i++, msg = msg->next) {
		if (msg->seqno == seqno) {
			return i;
		}
	}
	return -1;
}

int find_message_by_uid(struct client *client, uint32_t uid)
{
	int i;
	struct message *msg = client->messages.mhead.next;
	for (i = 0; i < client->messages.num_messages; i++, msg = msg->next) {
		if (msg->uid == uid) {
			return i;
		}
	}
	return -1;
}

void free_cached_messages(struct client *client)
{
	int i;
	int num_msgs;
	struct message *dead, *msg = client->messages.mhead.next;

	if (!client->messages.num_messages) {
		return;
	}

	num_msgs = client->messages.num_messages; /* Can't use as loop invariant directly since it changes when delete_message is called */
	for (i = 0; i < num_msgs; i++) {
		dead = msg;
		msg = msg->next;
		free_message(client, dead);
	}
	if (unlikely(client->messages.num_messages > 0)) {
		client_error("Still %d messages left", client->messages.num_messages);
	}
	assert(client->messages.num_messages == 0);
}
