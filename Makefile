CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2

TARGET = test_syscalls
SRC = test_syscalls.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)

test:
	python3 -m unittest discover tests -v

.PHONY: all clean test
