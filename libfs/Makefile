# Target library
lib := libfs.a

all: $(lib)

## TODO: Phase 1
targets := libfs.a
obs     := fs.o disk.o

CC      := gcc
CFLAGS  := -Wall -Wextra -Werror  -MMD
# debug: CFLAGS += -g

all: $(targets)

deps := $(pathsubst %.o,%.d,$(objs))
-include $(deps)

# -r if the library already exists, replace old files
# -c create the library if it doesn't exist
# -s create a sorted index of the library
libfs.a: $(obs)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(targets) $(objs) $(deps)