CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Ikyber/ref
TARGET = test_utility.out
KYBER_DIR = kyber/ref
KYBER_SOURCES = $(wildcard $(KYBER_DIR)/*.c)
KYBER_OBJECTS = $(KYBER_SOURCES:.c=.o)
MY_OBJECTS = kyber_utility.o test_utility.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(MY_OBJECTS) $(KYBER_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

kyber_utility.o: kyber_utility.c kyber_utility.h
	$(CC) $(CFLAGS) -c kyber_utility.c -o $@

test_utility.o: test_utility.c kyber_utility.h
	$(CC) $(CFLAGS) -c test_utility.c -o $@

# Компиляция Kyber файлов в их собственной директории
$(KYBER_DIR)/%.o: $(KYBER_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(MY_OBJECTS) $(KYBER_OBJECTS)
