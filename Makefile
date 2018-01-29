CFLAGS=-MMD -Wall
LDLIBS=-loath

OBJS=oath-exec.o

all: oath-exec

DEPEND=$(OBJS:.o=.d)
-include $(DEPEND)

oath-exec: $(OBJS)

clean:
	rm -f $(OBJS) oath-exec

.PHONY: all clean
