CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2

TARGET = test_syscalls
SRC = test_syscalls.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
