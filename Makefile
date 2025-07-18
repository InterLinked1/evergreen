#
# evergreen - online only terminal mail user agent
#
# Copyright (C) 2024, Naveen Albert
#
# Naveen Albert <bbs@phreaknet.org>
#

CC		= gcc
CFLAGS = -Wall -Werror -Wunused -Wextra -Wmaybe-uninitialized -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-format-attribute -Wnull-dereference -Wformat=2 -Wshadow -Wsizeof-pointer-memaccess -std=gnu99 -pthread -O3 -g -Wstack-protector -fno-omit-frame-pointer -fwrapv -fPIC -D_FORTIFY_SOURCE=2
EXE		= evergreen
RM		= rm -f
INSTALL = install
LIBS    = -lncurses -lmenu -lform -L/usr/local/lib -Wl,-rpath=/usr/local/lib/ -letpan
NCURSES_FLAGS=$(shell pkg-config --cflags ncurses)
ETPAN_FLAGS=-I/usr/local/include

MAIN_SRC := $(wildcard *.c)
MAIN_OBJ = $(MAIN_SRC:.c=.o)

$(EXE): $(MAIN_OBJ)
	$(CC) $(CFLAGS) -Wl,--export-dynamic -o $(EXE) *.o $(LIBS)

%.o : %.c
	$(CC) $(CFLAGS) -c -funsigned-char -Wno-format-y2k $(NCURSES_FLAGS) $(ETPAN_FLAGS) $^

anyascii.o : anyascii.c
	$(CC) $(CFLAGS) -c -Wno-unterminated-string-initialization $^

evergreen.o : evergreen.c
	$(CC) $(CFLAGS) -c -funsigned-char -fno-stack-protector -Wno-format-y2k $(NCURSES_FLAGS) $(ETPAN_FLAGS) $^

install:
	$(INSTALL) -m  755 $(EXE) "/usr/bin"

clean :
	$(RM) *.i *.o $(EXE)

.PHONY: clean
