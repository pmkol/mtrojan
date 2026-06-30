CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c99
CPPFLAGS ?= -Iinclude
AR ?= ar
LDLIBS ?=

LIB = libmtrojan.a
OBJS = src/mtrojan.o
TEST = tests/test_protocol

.PHONY: all test clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

src/mtrojan.o: src/mtrojan.c include/mtrojan.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TEST): tests/test_protocol.c $(LIB) include/mtrojan.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) $(LDLIBS) -o $@

test: $(TEST)
	./$(TEST)

clean:
	rm -f $(OBJS) $(LIB) $(TEST)
