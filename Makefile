CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Ikyber/ref -Imbedtls/include
KYBER_DIR = kyber/ref
KYBER_SOURCES = $(wildcard $(KYBER_DIR)/*.c)
KYBER_OBJECTS = $(KYBER_SOURCES:.c=.o)
MBEDTLS_DIR = mbedtls
LDFLAGS = -L$(MBEDTLS_DIR)/build/library -lmbedcrypto -lmbedtls -lmbedx509
MY_OBJECTS = kyber_utility.o utility_cli.o

# Кроссплатформенные настройки
ifeq ($(OS),Windows_NT)
    # Windows
    TARGET = utility_cli.exe
    RM = powershell -Command "Remove-Item -ErrorAction Ignore"
else
    # Linux/MacOS
    TARGET = utility_cli.out
    RM = rm -f
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(MY_OBJECTS) $(KYBER_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

kyber_utility.o: kyber_utility.c kyber_utility.h
	$(CC) $(CFLAGS) -c kyber_utility.c -o $@

utility_cli.o: utility_cli.c kyber_utility.h
	$(CC) $(CFLAGS) -c utility_cli.c -o $@

# Компиляция Kyber файлов в их собственной директории
$(KYBER_DIR)/%.o: $(KYBER_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
ifeq ($(OS),Windows_NT)
#    @echo "Cleaning for Windows..."
#    @powershell -Command "if (Test-Path '$(TARGET)') { Remove-Item '$(TARGET)' }"
	@powershell -Command "if (Test-Path 'kyber_utility.o') { Remove-Item 'kyber_utility.o' }"
	@powershell -Command "if (Test-Path 'utility_cli.o') { Remove-Item 'utility_cli.o' }"
	@powershell -Command "if (Test-Path '$(KYBER_DIR)\*.o') { Remove-Item '$(KYBER_DIR)\*.o' }"
else
#    @echo "Cleaning for Linux..."
#    $(RM) $(TARGET)
	$(RM) $(MY_OBJECTS)
	$(RM) $(KYBER_OBJECTS)
endif
