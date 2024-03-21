# evergreen

*evergreen* is a terminal mail user agent (mail client) that operates *online only* (interacting with the IMAP server for all operations, as opposed to doing anything to messages offline).

This overcomes the limitations of many traditional terminal mail clients, like mutt, that are fundamentally incapable of operating online-only.

## Why Another Mail Client?

Many people have asked me `??????` when I've told them I was working on writing a terminal mail client. Why not use mutt?

The main reason I wrote evergreen was there were no existing mail clients I could find that were suitable for my BBS. Because the mail client would only connect to the local IMAP server, there was no need to cache anything locally, and indeed, since mail is already, in fact, stored locally, this would be duplicating mail already on disk, so entirely unwanted.

`mutt` cannot do this, since it is designed to work with a variety of protocols (not just IMAP, but also POP3, maildir, mbox, etc.) and its common engine requires that it have all the headers in a mailbox before it will let the user interact with it.

For example, if you open a mailbox with 100,000 messages in `mutt`, it will *download all 100,000 message headers* before it will let you do anything with that mailbox, even if you just want to look at, say, the last 20 messages.

evergreen is different. It operates online only, just like most webmail applications, so it only downloads a few "pages" of headers at a time, making it fast and responsive, no matter how large your mailboxes are.
evergreen does not cache anything locally. This makes it suitable for use in embedded client applications, where you want to control what evergreen connects to and prevent it from storing anything to disk.

Because of the design of the client, it will obviously not work at all without a persistent IMAP connection to your mail server. If you need that capability, there are a number of other fine clients that already exist that will suit your needs better.

## Design Philosophy

I spent some time looking for existing options that would work; I was looking for a mail client that would:

* Not save anything on disk
* Be able to accept configuration entirely from the command line and not solely via a configuration file stored on disk
* Be suitable for use in restricted environments, preventing the user from interacting with the rest of the system, if needed
* Be able to load a subset of messages instantly, regardless of mailbox size
* Support IDLE for immediate message notifications

In other words, I wanted a mail client that could be launched as a door from my BBS that would let users check their local BBS mail (via IMAP), and when they were finished, the mail client would leave behind absolutely no trace of it being used - nothing saved or read from disk.

`mutt` was immediately ruled out since it's not capable of operating online only. `alpine` works better, but it still didn't fully satisfy what I was looking for. So, in the end, I ended up writing my own mail client that catered to the requirements of how I would be using it, first and foremost. It works online (and only online), and it is suitable for use in restricted environments, since it can be launched in a way that prevents the user from interacting with the file system at all, and without allowing them to change any of the connection settings.

## Building

*evergreen* requires a modified version of the `libetpan` library, which can be installed using this script: https://github.com/InterLinked1/lbbs/blob/master/scripts/libetpan.sh

After you have that installed, you can simply run `make` and then `make install`.

## Configuration

*evergreen* may be configured in one of two ways - you can use a configuration file (`.evergreenrc`), or you can pass settings in as command-line arguments, depending on what works better for your use case. Basic configuration may also be done at runtime in the program, per-session, but most settings cannot be configured this way.

## Usage

`evergreen` is designed to be fairly intuitive to users of traditional graphical mail clients. The folder pane appears on the left, showing all mailboxes, and the message list pane appears on the right. Messaging viewing and editing take up the entire screen. A status bar at the bottom indicates currently relevant information, in all cases.

At any time, you can press `?` for help showing current key bindings for tasks that are currently relevant (except when editing, which requires pressing `ESC` first).
