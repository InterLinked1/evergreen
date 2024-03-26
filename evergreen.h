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

/* Automatically mark messages as seen when viewed */
#define AUTO_MARK_SEEN

/* Slightly less than 30 minutes, the limit defined by the RFC */
#define MAX_IDLE_POLL_SEC 1740

/* Charset for sending messages */
#define DEST_CHARSET "iso-8859-1"

/* Define for debugging purposes only */
#define DEBUG_MODE

/* Use nonl() for ncurses to help with efficiency some.
 * If you observe ENTER being handled twice, it could be because
 * the terminal driver is passing CR LF, which with default newline cooking,
 * gets converted to a double LF, in which case, make sure this is defined.
 * Regardless, this setting should not hurt, and may make ncurses more efficient. */
#define USE_NONL

/*!
 * \brief Number of message headers to cache at a time and paginate
 * The larger this is, the more messages you can work with at a time,
 * but the more time is required at mailbox selection and periodic
 * rerenders to fetch this many message headers again.
 * In return, more messages can be scrolled at once without
 * having to re-download another set of headers.
 */
#define FETCHLIST_INTERVAL 180

/* Window dimension settings */
#define MIN_COLS_FOR_EXPANDED_LIST_INFO 97
#define LIST_PANE_WIDTH (COLS >= MIN_COLS_FOR_EXPANDED_LIST_INFO ? 26 : 16)

#define MIN_COLS_FOR_EXPANDED_MAILBOX_STATS 97
#define STATUS_BAR_START_COL LIST_PANE_WIDTH + (COLS >= MIN_COLS_FOR_EXPANDED_MAILBOX_STATS ? 45 : 28)

/* No user-servicable parts below this */

#define LIST_PANE_HEIGHT (LINES - 2)
#define MAIN_PANE_WIDTH (COLS - LIST_PANE_WIDTH)
#define MAIN_PANE_HEIGHT LIST_PANE_HEIGHT
#define STATUS_BAR_WIDTH (COLS - STATUS_BAR_START_COL)
#define MESSAGES_PER_SCREEN MAIN_PANE_HEIGHT

#define EVERGREEN_PROGNAME "evergreen"
#define EVERGREEN_VERSION "0.0.1"
#define EVERGREEN_COPYRIGHT "(C) 2024 Naveen Albert"
#define EVERGREEN_CONFIG_FILE ".evergreenrc"
#define EVERGREEN_SOURCE_URL "https://github.com/InterLinked1/evergreen"

#define USER_AGENT EVERGREEN_PROGNAME " " EVERGREEN_VERSION " (" EVERGREEN_SOURCE_URL ")"

#define _GNU_SOURCE /* bzero, insque, remque */
#define _XOPEN_SOURCE /* strptime */
#include <time.h> /* struct tm */

#include <ncurses.h>
#include <menu.h>

#define KEY_ESCAPE 27
#define ctrl(x) ((x) & 0x1f)

/*! \brief If char * is NULL or empty string */
#define strlen_zero(s) ((!s || *s == '\0'))

/*!
 * \brief strlen for constant strings
 * \note sizeof is resolved at compile time, that's why it works
 * \see https://stackoverflow.com/a/5022113
 */
#define STRLEN(s) ( (sizeof(s)/sizeof(s[0])) - sizeof(s[0]) )

#define free_if(x) if (x) { free(x); x = NULL; }
#define REPLACE(var, val) free_if(var); var = strdup(val);

#define APPEND_STR(s, v, len) \
	if (!s) { \
		s = strndup(v, len); \
	} else { \
		size_t origlen = strlen(s); \
		size_t newlen = origlen + len ; \
		char *_re = realloc(s, newlen + 1); \
		if (likely(_re != NULL)) { \
			memcpy(_re + origlen, v, len); \
			_re[newlen] = '\0'; \
			s = _re; \
		} \
	} \

/* Size in common units, rounded up */
#define SIZE_KB(bytes) ((bytes + 1023) / 1024)
#define SIZE_MB(bytes) ((bytes + (1024 * 1024 - 1)) / (1024 * 1024))

#define SPACES "                       "

#define IMAP_CAPABILITY_IDLE (1 << 0)
#define IMAP_CAPABILITY_MOVE (1 << 1)
#define IMAP_CAPABILITY_SORT (1 << 2)
#define IMAP_CAPABILITY_THREAD_REFERENCES (1 << 3)
#define IMAP_CAPABILITY_STATUS_SIZE (1 << 4)
#define IMAP_CAPABILITY_LIST_STATUS (1 << 5)
#define IMAP_CAPABILITY_NOTIFY (1 << 6)
#define IMAP_CAPABILITY_UNSELECT (1 << 7)
#define IMAP_CAPABILITY_QUOTA (1 << 8)

#define IMAP_HAS_CAPABILITY(client, cap) (client->capabilities & (cap))

#define MAILIMAP_ERROR(r) (r != MAILIMAP_NO_ERROR && r != MAILIMAP_NO_ERROR_AUTHENTICATED && r != MAILIMAP_NO_ERROR_NON_AUTHENTICATED)

struct menu {
	MENU *menu;
	ITEM **items;
	int n;		/*!< Number of entries */
};

#define IMAP_MAILBOX_MARKED (1 << 0)
#define IMAP_MAILBOX_NOSELECT (1 << 1)
#define IMAP_MAILBOX_READONLY (1 << 2)
#define IMAP_MAILBOX_NOCHILDREN (1 << 3)
#define IMAP_MAILBOX_HASCHILDREN (1 << 4)
#define IMAP_MAILBOX_DRAFTS (1 << 5)
#define IMAP_MAILBOX_JUNK (1 << 6)
#define IMAP_MAILBOX_SENT (1 << 7)
#define IMAP_MAILBOX_TRASH (1 << 8)

/*! \brief IMAP mailbox */
struct mailbox {
	char *name;			/* Name of mailbox */
	char *display;		/* Display name of mailbox */
	int flags;			/* Mailbox flags */
	uint32_t unseen;	/* UNSEEN */
	uint32_t recent;	/* Number of RECENT messages */
	uint32_t total;		/* Total number of messages */
	size_t size;		/* Total size of mailbox, in bytes */
	uint32_t uidnext;		/* UIDNEXT */
	uint32_t uidvalidity;	/* UIDVALIDITY */
	unsigned int keywords_allowed:1;	/* Keywords allowed (PERMANENTFLAGS returned \* ) */
	int num_keywords;	/* Number of keywords */
	char *keywords[64];	/* Keywords from PERMANENTFLAGS */
};

#define IMAP_MESSAGE_FLAG_RECENT (1 << 0)
#define IMAP_MESSAGE_FLAG_ANSWERED (1 << 1)
#define IMAP_MESSAGE_FLAG_FLAGGED (1 << 2)
#define IMAP_MESSAGE_FLAG_DELETED (1 << 3)
#define IMAP_MESSAGE_FLAG_SEEN (1 << 4)
#define IMAP_MESSAGE_FLAG_DRAFT (1 << 5)

#define NUM_IMAP_MESSAGE_FLAGS 6

enum {
	SECURITY_NONE = 0,
	SECURITY_TLS = 1,
	SECURITY_STARTTLS = 2,
};

#define MAX_KEYWORDS 64

/*! \brief Runtime config */
struct config {
	int imap_port;					/*!< IMAP port */
	int smtp_port;					/*!< SMTP port */
	unsigned int imap_security:2;	/*!< IMAP security */
	unsigned int smtp_security:2;	/*!< SMTP security */
	unsigned int imap_append:1;		/*!< Save sent copies via IMAP APPEND */
	char fromname[84];					/*!< Default name, for From header */
	char fromaddr[84];				/*!< Default email address, for From header */
	char *additional_identities;	/*!< All other email addresses that are "our" identities, as comma-separated list of username@domain or *@domain */
	char imap_hostname[256];		/*!< IMAP hostname */
	char imap_username[48];			/*!< IMAP username */
	char imap_password[64];			/*!< IMAP password */
	char smtp_hostname[256];		/*!< SMTP hostname */
	char smtp_username[48];			/*!< SMTP username */
	char smtp_password[64];			/*!< SMTP password */
	char logfile[256];				/*!< Log file */
};

#define MSG_FETCH_FLAGS (1 << 0)
#define MSG_FETCH_ALL (1 << 1)

#define MBOX_NEED_STATUS (1 << 0) /* Need to issue STATUS */
#define MBOX_NEED_FETCH_FLAGS (1 << 1)
#define MBOX_NEED_FETCH_ALL (1 << 2)
#define MBOX_NEED_FETCH (MBOX_NEED_FETCH_FLAGS | MBOX_NEED_FETCH_ALL)

/*! \brief Message metadata */
struct message {
	struct message *next;	/*!< Linked list next */
	struct message *prev;	/*!< Linked list prev */
	int index;				/*!< Index */
	uint32_t seqno;		/*!< Sequence number */
	uint32_t uid;		/*!< UID */
	size_t size;		/*!< Size */
	struct tm date;		/*!< Sent date */
	struct tm intdate;	/*!< INTERNALDATE */
	int flags;			/*!< Message flags */
	uint64_t keywords;	/*!< Bitmask of keywords */
	int importance;		/*!< Importance */
	char *subject;		/*!< Subject */
	char *from;			/*!< From */
	char *display;		/*!< Menu display */
	int fetchflags;		/*!< Things that need to be fetched for this message */
};

struct attachment {
	struct attachment *next;
	struct attachment *prev;
	const char *name;
	size_t size;
	char data[];
};

/*! \brief Message data */
struct message_data {
	char *msg_body;
	size_t msg_size;
	char *pt_body;
	size_t pt_size;
	char *html_body;
	size_t html_size;
	char *subject;
	char *to;
	char *cc;
	char *bcc; /* Mainly for drafts */
	char *replyto;
	char *inreplyto;
	char *messageid;
	char *references;
	char *headersfmt;
	size_t headersfmtlen;
	unsigned int pt_flowed:1;
	struct tm date; /* Sent date */
	int num_attachments;
	struct attachment *attachments;
};

#define FOCUS_FOLDERS 0
#define FOCUS_MESSAGES 1

#define FOCUSED(client, x) (client->focus == x)

/* Idle updates */
#define REFRESH_FOLDERS (1 << 0)
#define REFRESH_MESSAGE_PANE (1 << 1)
#define REFRESH_ALL (REFRESH_FOLDERS | REFRESH_MESSAGE_PANE_EITHER)

#define IDLE_EXISTS (1 << 0)
#define IDLE_RECENT (1 << 1)
#define IDLE_EXPUNGE (1 << 2)
#define IDLE_FETCH (1 << 3)
#define IDLE_STATUS (1 << 4)
#define IDLE_STATUS_EXISTS (1 << 5) /* Pseudo used to indicate new messages in another folder */

/*! \brief Abstract messages container */
/*! \note This is in the header file so that it can be stack-allocated in the client struct,
 * but this should be considered opaque, outside of messages.c. */
struct messages {
	struct message mhead;		/*!< Linked list head */
	int num_messages;			/*!< Number of cached messages */
};

/*! \brief IMAP client and top-level data structure */
struct client {
	struct mailimap *imap;		/*!< libetpan IMAP client handle */
	int imapfd;					/*!< File descriptor, used for IDLE */
	int capabilities;			/*!< Mask of IMAP capabilities */
	char delimiter;				/*!< IMAP hierarchy delimiter */
	/* ncurses */
	WINDOW *win_header;			/*!< Header */
	WINDOW *win_folders;		/*!< Folders pane */
	WINDOW *win_main;			/*!< Message pane */
	WINDOW *win_footer;			/*!< Footer */
	/* Mailbox data and state */
	struct mailbox *mailboxes;	/*!< Mailboxes array */
	int num_mailboxes;			/*!< Number of mailboxes */
	struct menu folders;
	struct menu message_list;
	unsigned int focus:1;		/*!< Message pane focused (as opposed to folder pane) */
	unsigned int idling:1;		/*!< Currently IMAP idling */
	unsigned int mouse_enable:1;	/*!< Mouse currently enabled? */
	int menu_depth;				/*!< Current depth of menus/submenus */
	int resize_depth;			/*!< Current resize depth */
	time_t idlestart;			/*!< Time IDLE started */
	int refreshflags;			/*!< What needs to be refreshed due to IDLE? */
	int refreshtypes;			/*!< What kinds of things changed during IDLE? */
	/* Selected mailbox */
	struct mailbox *sel_mbox;	/*!< Pointer to selected mailbox */
	struct mailbox *cpmv_mbox;	/*!< Mailbox to which something was last copied or moved */
	struct mailbox *trash_mbox;	/*!< Trash mailbox for selected mailbox */
	struct mailbox *junk_mbox;	/*!< Junk mailbox for selected mailbox */
	struct mailbox *sent_mbox;	/*!< Sent mailbox for selected mailbox */
	struct mailbox *draft_mbox;	/*!< Drafts mailbox for selected mailbox */
	uint32_t start_seqno;		/*!< Sequence number of lowest message currently in memory of message pane menu	*/
	uint32_t end_seqno;			/*!< Sequence number of highest message currently in memory of message pane menu */
	int quota_limit;
	int quota_used;
	struct messages messages;
	struct config *config;
};

#define SENT_MAILBOX(client) (client->sent_mbox ? client->sent_mbox->name : "Sent")
#define DRAFTS_MAILBOX(client) (client->draft_mbox ? client->draft_mbox->name : "Drafts")

#define SUB_MENU_PRE \
	client->menu_depth++; \
	client_debug(6, "Menu depth incremented to %d (resize %d)", client->menu_depth, client->resize_depth);

#define RESIZE_IF_NEEDED(x) \
	if (client->resize_depth > client->menu_depth) { \
		client_debug(6, "Menu depth decremented to %d, need resize (depth %d)", client->menu_depth, client->resize_depth); \
		client->resize_depth--; \
		goto resize; \
	} \

/* At the top-level menu, return 0, for a normal 0 exit code.
 * At all others, return -1, to cause stack to keep unwinding to the top menu.
 *
 * If a resize occured in a submenu, all windows above it need to resize as well,
 * when we get back to them.
 */
#define SUB_MENU_POST \
	client->menu_depth--; \
	if (res < 0) { \
		res = client->menu_depth ? -1 : 0; \
		goto done; \
	} \
	RESIZE_IF_NEEDED(x); \
	client_debug(6, "Menu depth decremented to %d (resize %d)", client->menu_depth, client->resize_depth);

#define SUB_MENU_POST_DELAYRESIZE(flag) \
	client->menu_depth--; \
	if (res < 0) { \
		res = client->menu_depth ? -1 : 0; \
		goto done; \
	} \
	if (client->resize_depth > client->menu_depth) { \
		client_debug(6, "Menu depth decremented to %d, need resize (depth %d)", client->menu_depth, client->resize_depth); \
		client->resize_depth--; \
		flag = 1; \
	} else { \
		client_debug(6, "Menu depth decremented to %d (resize %d)", client->menu_depth, client->resize_depth); \
	}

#define SUB_MENU_POST_NORESIZE \
	if (res < 0) { \
		return client->menu_depth ? -1 : 0; \
	} \
	client->resize_depth--; \
	client->menu_depth--; \
	client_debug(6, "Menu depth decremented to %d (resize %d)", client->menu_depth, client->resize_depth);

/* === Logging === */

#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_NOTICE 2
#define LOG_DEBUG 3

/* Note: Log messages should not end in a newline */

void __attribute__ ((format (printf, 7, 8))) __client_log(struct client *client, int loglevel, int level, const char *file, int lineno, const char *func, const char *fmt, ...);

#define client_log(loglevel, level, fmt, ...) __client_log(client, loglevel, level, __FILE__, __LINE__, __func__, fmt, ## __VA_ARGS__)

#define client_debug(level, fmt, ...) __client_log(NULL, LOG_DEBUG, level, __FILE__, __LINE__, __func__, fmt, ## __VA_ARGS__)
#define client_status(fmt, ...) client_log(LOG_NOTICE, 0, fmt, ## __VA_ARGS__)
#define client_notice(fmt, ...) client_log(LOG_NOTICE, 0, fmt, ## __VA_ARGS__)
#define client_error(fmt, ...) client_log(LOG_ERROR, 0, "ERROR: "fmt, ## __VA_ARGS__)
#define client_warning(fmt, ...) client_log(LOG_WARNING, 0, "WARNING: " fmt, ## __VA_ARGS__)

#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)

void safe_strncpy(char *restrict dst, const char *restrict src, size_t size);

/*! === General functions === */

struct pollfd;

enum help_types {
	HELP_GLOBAL = (1 << 0),
	HELP_MAIN = (1 << 1),
	HELP_VIEWER = (1 << 2),
	HELP_EDITOR = (1 << 3),
};

int show_help_menu(struct client *client, struct pollfd *pfds, enum help_types);

void format_size(size_t size, char *restrict buf, size_t len);

/*! \brief Set or update the permanent status bar displaying mailbox stats */
void display_mailbox_info(struct client *client);

/*!
 * \brief Set the transient status message
 * \note doupdate() must be called for the display to updated
 */
void client_set_status_nout(struct client *client, const char *s);

/*!
 * \brief Poll for terminal input, while handling IDLE updates
 * \param client
 * \param pfds
 * \param menuvisible Whether the message pane is currently visible (at top level menu)
 * \param mouse_events Mouse events to accept (0 for none)
 * \retval -1 on error
 * \return character read from terminal
 */
int __poll_input(struct client *client, struct pollfd *pfds, int submenu, mmask_t mouse_events);

#define poll_input(client, pfds, submenu) __poll_input(client, pfds, submenu, 0)

/* === IMAP functions === */

/*! \brief Disconnect and destroy IMAP client */
void client_destroy(struct client *client);

/*! \brief Connect to IMAP server */
int client_connect(struct client *client, struct config *config);

/*! \brief Log in to IMAP server */
int client_login(struct client *client, struct config *config);

/*! \brief IMAP LIST */
int client_list(struct client *client);

/*! \brief IMAP STATUS */
int client_status_command(struct client *client, struct mailbox *mbox, char *restrict list_status_resp);

/*! \brief IMAP SELECT */
int client_select(struct client *client, struct mailbox *mbox);

/*! \brief Associate a keyword with a message */
void message_add_keyword(struct mailbox *mbox, struct message *msg, const char *keyword);

/*! \brief IMAP FETCH header list */
int client_fetchlist(struct client *client);

/*!
 * \brief IMAP FETCH message
 * \param client
 * \param msg
 * \param[out] mdata. mdata->msg_body is non-NULL on success and must be freed using free()
 * \retval 0 on success, -1 on failure
 */
int client_fetch(struct client *client, struct message *msg, struct message_data *restrict mdata);

/*!
 * \brief Parse a raw RFC822 message received using client_fetch
 * \param mdata
 * \param parse_headers 1 first time parsing, 0 any subsequent times
 * \param html Request HTML body, if available, over plain text
 * \retval 0 on success, -1 on failure
 */
int client_fetch_mime(struct message_data *restrict mdata, int parse_headers, int html);

/*! * \brief Clean up message_data, called after client_fetch / client_fetch_mime */
void client_cleanup_message(struct message_data *restrict mdata);

/*! \brief Start idling */
int client_idle_start(struct client *client);

/*! \brief Stop idling */
int client_idle_stop(struct client *client);

/*! \brief Process data received during IDLE */
int process_idle(struct client *client);

/*!
 * \brief Resequence messages
 * \param msg The message starting from which message numbers should be decremented by 1
 */
void resequence_messages(struct message *msg);

/*!
 * \brief Add or remove an flag from a message (no keywords allowed)
 * \param client
 * \param sign 1 to store flag, -1 to remove flag
 * \param msg. Single message, or if NULL, 1:* will be used as the sequence.
 * \param flags
 */
int client_store(struct client *client, int sign, struct message *msg, int flags);

/*!
 * \brief Add or remove an flag from a message (no keywords allowed)
 * \param client
 * \param sign 1 to store flag, -1 to remove flag
 * \param msg. Single message, or if NULL, 1:* will be used as the sequence.
 * \param keyword Keyword to store
 */
int client_store_keyword(struct client *client, int sign, struct message *msg, const char *keyword);

/*! \brief IMAP COPY */
int client_copy(struct client *client, struct message *msg, const char *newmbox);

/*! \brief IMAP MOVE */
int client_move(struct client *client, struct message *msg, const char *newmbox);

/*! \brief IMAP EXPUNGE */
int client_expunge(struct client *client);

/*!
 * \brief IMAP APPEND
 * \param client
 * \param mailbox Mailbox to which to append message
 * \param flags Bitmask of IMAP_MESSAGE_FLAG_SEEN | IMAP_MESSAGE_FLAG_DRAFT
 * \param msg Message body
 * \param len Message length
 * \note Setting date and flags not currently supported by this function. INTERNALDATE will be current time.
 */
int client_append(struct client *client, const char *mailbox, int flags, const char *msg, size_t len);

/*!
 * \brief Add or remove the \Seen flag from a message.
 * \param client
 * \param uid
 * \param sign 1 to store flag, -1 to remove flag
 */
#define client_store_seen(client, sign, msg) client_store(client, sign, msg, IMAP_MESSAGE_FLAG_SEEN)

#define client_store_deleted(client, msg) client_store(client, +1, msg, IMAP_MESSAGE_FLAG_DELETED)

#define client_store_flagged(client, sign, msg) client_store(client, sign, msg, IMAP_MESSAGE_FLAG_FLAGGED)

#define client_store_answered(client, sign, msg) client_store(client, sign, msg, IMAP_MESSAGE_FLAG_ANSWERED)
#define client_mark_answered(client, msg) client_store_answered(client, +1, msg)

/* RFC822 messages */

#define SET_ERROR(fmt, ...) \
	client_debug(1, fmt, ## __VA_ARGS__); \
	snprintf(msgc->error, sizeof(msgc->error), fmt, ## __VA_ARGS__)

struct message_constructor {
	char *subject;
	char *from;
	char *to;
	char *cc;
	char *bcc;
	char *replyto;
	const char *inreplyto; /* Just a pointer to data allocated elsewhere */
	char *references;
	char **attachments;
	char *body;
	size_t bodylen;
	char error[256];
};

/*! \brief Like strsep, but for a list of email addresses (separated by , or ; ) */
char *addr_sep(char **restrict addr);

/*!
 * \brief Create an RFC822 message
 * \param msgc
 * \param[out] len The length of the message
 * \return NULL on failure
 * \return RFC822 message as NUL-terminated string on success
 */
char *create_email_message(struct message_constructor *msgc, size_t *restrict len);

/* === SMTP === */

int smtp_send(struct client *client, struct message_constructor *msgc, const char *body, size_t len);

/* === Messages functions === */

/*! \brief Initialize messages container */
int init_messages(struct client *client, int num_msgs);

/*! \brief Get number of messages in messages container */
uint32_t num_messages(struct client *client);

/*!
 * \brief Get the next message after the provided message
 * \note Messages are stored as a doubly linked list, so following msg->next will recurse forever.
 *       msg->next must not be used as a loop invariant; instead use this function, which returns
 *       NULL at end of list, or use a count of the number of messages to break the loop.
 */
struct message *next_message(struct message *msg);

/*! \brief Allocate a new message and link it to the messages container */
struct message *new_message(struct client *client, int index, int seqno);

/*! \brief Mark message as unseen, updating mailbox stats */
void mark_message_unseen(struct mailbox *mbox, struct message *msg);

/*! \brief Mark message as seen, updating mailbox stats */
void mark_message_seen(struct mailbox *mbox, struct message *msg);

/*! \brief Mark message as seen and not recent, updating mailbox stats */
void mark_message_read(struct mailbox *mbox, struct message *msg);

/*!
 * \brief Manually adjust stats for a mailbox by a message's size
 * \param mbox Mailbox to which message was added
 * \param size Size of message
 * \param unseen Whether message is not \Seen
 */
void increment_stats_by_size(struct mailbox *mbox, size_t size, int unseen);

/*!
 * \brief Handle a general message operation
 * \param client
 * \param pfds
 * \param msg
 * \param mdata. Optional, if available, please provide it. Otherwise, will be constructed from msg.
 * \param c Option selected (must be a valid general message operation option)
 * \retval -1 on failure
 * \retval 0 on success, and message may continue being displayed, if active
 * \retval 1 on success, and message may continue being displayed, if active. Message pane and folder pane need redraw.
 * \retval 2 on success, and message should no longer be displayed, if active. Message pane and folder pane need redraw.
 */
int handle_message_op(struct client *client, struct pollfd *pfds, struct message *msg, struct message_data *mdata, int c);

/*! \brief Mark all messages in a trash mailbox for deletion */
int handle_emptytrash(struct client *client);

/*! \brief Expunge current mailbox */
int handle_expunge(struct client *client, struct pollfd *pfds);

/*!
 * \brief Remove and destroy a particular message, updating mailbox stats
 * \note This does not automatically resequence messages if needed. Save msg->next and call resequence_messages on that afterwards if needed.
 */
void delete_message(struct client *client, struct message *msg);

/*!
 * \brief Get a message by its index in the current message list
 * \param client
 * \param index Message index
 * \return message, if exists
 * \warning This function is not safe to use if index is not known to be a valid index
            This function is not saved to use if the messages container has changed since the index was known to be valid.
 * \warning Do not call this function in a loop, since that will turn a linear operation into a quadratic one.
 *          Instead, use msg->next to get the next message (but use a counter for the loop invariant)
 */

#ifdef DEBUG_MODE
#define get_msg(client, index) __get_msg(client, index, __FILE__, __LINE__)
struct message *__get_msg(struct client *client, int index, const char *file, int line);
#else
#define get_msg(client, index) __get_msg(client, index)
struct message *__get_msg(struct client *client, int index);
#endif

/*! \brief Same as get_msg, but get message by sequence number, rather than index in the current message pane window */
struct message *get_msg_by_seqno(struct client *client, uint32_t seqno);

/*! \brief Get a message by UID. Unlike get_msg and get_msg_by_seqno, this is safe to use even if the message does not exist, and may return NULL. */
struct message *get_msg_by_uid(struct client *client, uint32_t uid);

/*!
 * \brief Get a message index by its sequence number
 * \param client
 * \param seqno Sequence number
 * \return index number on success
 * \retval -1 if not found
 */
int find_message_by_seqno(struct client *client, uint32_t seqno);

/*!
 * \brief Get a message index by its UID
 * \param client
 * \param uid UID
 * \return index number on success
 * \retval -1 if not found
 */
int find_message_by_uid(struct client *client, uint32_t uid);

/*! \brief Free cached messages */
void free_cached_messages(struct client *client);

/* === Message Viewer === */

int next_n_quotes(const char *s, int n);

enum view_message_type {
	VIEW_MESSAGE_PT = 0,
	VIEW_MESSAGE_HTML = 1,
	VIEW_MESSAGE_SOURCE = 2,
	VIEW_MESSAGE_EMPTY = 3,
};

/*! \brief Convert HTML message body to plaintext representation */
int convert_html_to_pt(struct client *client, struct message_data *mdata);

/*! \brief Construct a message_data from a message */
int construct_message_data(struct client *client, struct message *msg, struct message_data *restrict mdata, enum view_message_type *restrict mtype);

/*! \brief Display and page an email message (either plain text, HTML, or message source) */
int view_message(struct client *client, struct pollfd *pfds, struct message *msg);

/* === Message Editor === */

/*! \brief Reply to an existing message */
int reply(struct client *client, struct pollfd *pfds, struct message *msg, struct message_data *mdata, int replyall);

/*! \brief Forward a message */
int forward(struct client *client, struct pollfd *pfds, struct message *msg, struct message_data *mdata);

/*! \brief Edit an existing message */
int edit_message(struct client *client, struct pollfd *pfds, struct message *msg);

/*! \brief Compose a new message */
int editor(struct client *client, struct pollfd *pfds);

/* === Menu functions === */

/*! \brief Create folder pane items */
int create_folder_items(struct client *client);

/*! \brief Free folder pane items */
void free_folder_items(struct client *client);

/*! \brief Create folder pane menu */
int create_folder_menu(struct client *client);

/*! \brief Clean up folder pane menu */
void cleanup_folder_menu(struct client *client);

/*! \brief Completely redraw folder pane menu */
int redraw_folder_pane(struct client *client);

/*! \brief Create message pane items */
int create_message_items(struct client *client);

/*! \brief Free message pane items */
void free_message_items(struct client *client);

/*! \brief Create message pane menu */
int create_messages_menu(struct client *client);

/*! \brief Clean up message pane menu */
void cleanup_message_menu(struct client *client);

/*! \brief Get mailbox selection for submenus */
int get_mailbox_selection(struct client *client, struct pollfd *pfds, struct mailbox **restrict sel_mbox, struct mailbox *default_sel);

/*!
 * \brief Prompt for confirmation
 * \param client
 * \param pfds
 * \param title Optional menu title
 * \param subtitle Optional menu subtitle
 * \retval 1 Yes
 * \retval 0 Cancel/escape/No
 * \retval -1 error
 */
int prompt_confirm(struct client *client, struct pollfd *pfds, const char *title, const char *subtitle);
