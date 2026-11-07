CC ?= cc
CPPFLAGS ?= -D_POSIX_C_SOURCE=200809L
CFLAGS ?= -std=c17 -O2 -Wall -Wextra -Wpedantic
LDLIBS ?= -lcrypto

.PHONY: all clean

all: file-manager

file-manager: src/main.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f file-manager