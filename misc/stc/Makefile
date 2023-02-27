CFLAGS += -pedantic -pedantic-errors -Werror -Wall -Wextra -fsanitize=undefined

CFLAGS += -I$(HDRDIR)/include
LDFLAGS += -L$(HDRDIR)/src

LDLIBS += -lm -lpthread -lhdr_histogram

all: stc

stc: stc.c

run:
	LD_LIBRARY_PATH=$(HDRDIR)/src ./stc $(hostname)

clean:
	rm -f stc
