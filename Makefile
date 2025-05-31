# Makefile for packet analyzer program

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap -lrt

TARGET = packet_analyzer
SRCS = main.c packet_parser.c
OBJS = $(SRCS:.c=.o)

TEST_TARGET = test_parser
TEST_SRCS = test_parser.c packet_parser.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(OBJS) $(TEST_OBJS)

.PHONY: all test clean