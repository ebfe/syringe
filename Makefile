CC = clang

CFLAGS ?= -g
CFLAGS += -std=c99 -pedantic -pipe
CFLAGS += -Wall -Wextra
CFLAGS += -D_DEFAULT_SOURCE

LDFLAGS = -ldl

TARGETS = syringe helloworld.so

all: $(TARGETS)

syringe: syringe.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

helloworld.so: helloworld.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^

depend:
	makedepend -- $(CFLAGS) $(CPPFLAGS) -- -Y *.c

tags:
	ctags -R .

clean:
	@-rm $(TARGETS) *.o *~ core

.PHONY: all clean depend tags

# DO NOT DELETE
