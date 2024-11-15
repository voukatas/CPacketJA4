CC = gcc -std=gnu11
CFLAGS = -Iunity -Iinclude -Wall -Wextra -Werror -g -O0
OPTIMIZED_FLAGS = -Iinclude -Wall -Wextra -Werror -O2 -s -pthread -DNDEBUG
LDFLAGS = -lpcap -lssl -lcrypto

UNITY_SRC = unity/unity.c

SRC_FILES = $(wildcard src/*.c)
TESTS = test_payloads
TARGET = c_packet_ja4

$(TARGET): $(SRC_FILES)
	$(CC) $(CFLAGS) $^ -o $(TARGET) $(LDFLAGS)

test_payloads: tests/test_payloads.c $(UNITY_SRC) src/c_packet_ja4.c
	$(CC) $(CFLAGS) -DTESTING $^ -o $@ $(LDFLAGS)

.PHONY: test
test: $(TESTS)
	./$(TESTS)

.PHONY: clean
clean:
	rm -f $(TARGET) $(TESTS)

