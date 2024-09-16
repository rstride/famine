CC = gcc
AS = as
CFLAGS = -Wall -Wextra -Werror -g
ASFLAGS = -g

TARGET = famine

C_SRCS = $(wildcard src/*.c)
ASM_SRCS = $(wildcard src/*.s)

C_OBJS = $(C_SRCS:.c=.o)
ASM_OBJS = $(ASM_SRCS:.s=.o)
OBJS = $(C_OBJS) $(ASM_OBJS)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.s
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

test: $(TARGET)
	./test/script.sh

test_count_infected: $(TARGET)
	./test/count_infected.sh

test_poc_packer: $(TARGET)
	$(CC) -o test/poc_packer test/poc_packer.c
	./test/poc_packer

clean_tests:
	rm -f test/poc_packer

.PHONY: all clean test test_count_infected test_poc_packer clean_tests