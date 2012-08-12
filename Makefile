HAMMER = ../hammer
CFLAGS = -I$(HAMMER)/src `pkg-config glib-2.0 --cflags` $(EXTRA_CFLAGS)
LDFLAGS = -L$(HAMMER)/src
LDLIBS = -lhammer `pkg-config glib-2.0 --libs` -lm

all: src/message.o message

clean:
	rm -f message.o message
