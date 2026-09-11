# Build the demonstration laboratory with ASan and UBSan enabled.
#
# Do not use this in production.  These programs are deliberately broken.

CC ?= clang
CFLAGS ?= -g -O1 -fno-omit-frame-pointer -Wall -Wextra \
          -fsanitize=address,undefined
LDFLAGS ?= -fsanitize=address,undefined

BINARIES = heap_overflow stack_overflow global_overflow \
           use_after_free double_free null_deref \
           oob_read signed_overflow memory_leak

.PHONY: all clean

all: $(BINARIES)

%: %.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BINARIES)
