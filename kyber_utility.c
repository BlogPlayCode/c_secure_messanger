#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Подключаем заголовочные файлы из репозитория Kyber
#include "kyber/ref/api.h"
#include "kyber/ref/params.h"
#include "kyber/ref/verify.h"

// Реализация Base64-энкодера (простая версия для вывода 32-байтного секрета)
static const char *base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const unsigned char *input, size_t input_len, char *output) {
    size_t i = 0, j = 0;
    while (i < input_len) {
        uint32_t octet_a = i < input_len ? input[i++] : 0;
        uint32_t octet_b = i < input_len ? input[i++] : 0;
        uint32_t octet_c = i < input_len ? input[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = base64_alphabet[(triple >> 3 * 6) & 0x3F];
        output[j++] = base64_alphabet[(triple >> 2 * 6) & 0x3F];
        output[j++] = base64_alphabet[(triple >> 1 * 6) & 0x3F];
        output[j++] = base64_alphabet[(triple >> 0 * 6) & 0x3F];
    }

    // Добавляем паддинг
    size_t pad = (3 - input_len % 3) % 3;
    while (pad--) {
        output[--j] = '=';
    }

    output[j] = '\0';
}

// Вспомогательная функция для записи бинарных данных в файл
int write_to_file(const char *filename, const unsigned char *data, size_t len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    return (written == len) ? 0 : -1;
}

// Вспомогательная функция для чтения бинарных данных из файла
int read_from_file(const char *filename, unsigned char *data, size_t len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return -1;
    size_t read = fread(data, 1, len, fp);
    fclose(fp);
    return (read == len) ? 0 : -1;
}

// Функция 1: Генерация пары ключей и сохранение в файлы
void generate_keys(const char *pub_file, const char *priv_file) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    if (crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "Ошибка генерации ключей\n");
        return;
    }
    if (write_to_file(pub_file, pk, CRYPTO_PUBLICKEYBYTES) != 0) {
        fprintf(stderr, "Ошибка записи в %s\n", pub_file);
    }
    if (write_to_file(priv_file, sk, CRYPTO_SECRETKEYBYTES) != 0) {
        fprintf(stderr, "Ошибка записи в %s\n", priv_file);
    }
}

// Функция 2: Вычисление общего секрета и шифра по публичному ключу
void generate_secret_and_cipher(const char *pub_file, const char *secret_file, const char *cipher_file) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    if (read_from_file(pub_file, pk, CRYPTO_PUBLICKEYBYTES) != 0) {
        fprintf(stderr, "Ошибка чтения %s\n", pub_file);
        return;
    }
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss[CRYPTO_BYTES];
    if (crypto_kem_enc(ct, ss, pk) != 0) {
        fprintf(stderr, "Ошибка энкапсуляции\n");
        return;
    }
    if (write_to_file(secret_file, ss, CRYPTO_BYTES) != 0) {
        fprintf(stderr, "Ошибка записи в %s\n", secret_file);
    }
    if (write_to_file(cipher_file, ct, CRYPTO_CIPHERTEXTBYTES) != 0) {
        fprintf(stderr, "Ошибка записи в %s\n", cipher_file);
    }
}

// Функция 3: Вычисление общего секрета по шифру и приватному ключу
void compute_secret(const char *cipher_file, const char *priv_file, const char *secret_file) {
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    if (read_from_file(cipher_file, ct, CRYPTO_CIPHERTEXTBYTES) != 0) {
        fprintf(stderr, "Ошибка чтения %s\n", cipher_file);
        return;
    }
    if (read_from_file(priv_file, sk, CRYPTO_SECRETKEYBYTES) != 0) {
        fprintf(stderr, "Ошибка чтения %s\n", priv_file);
        return;
    }
    unsigned char ss[CRYPTO_BYTES];
    if (crypto_kem_dec(ss, ct, sk) != 0) {
        fprintf(stderr, "Ошибка декапсуляции\n");
        return;
    }
    if (write_to_file(secret_file, ss, CRYPTO_BYTES) != 0) {
        fprintf(stderr, "Ошибка записи в %s\n", secret_file);
    }
}

// Функция 4: Сравнение двух секретов
void compare_secrets(const char *secret1, const char *secret2) {
    unsigned char ss1[CRYPTO_BYTES];
    unsigned char ss2[CRYPTO_BYTES];
    if (read_from_file(secret1, ss1, CRYPTO_BYTES) != 0) {
        fprintf(stderr, "Ошибка чтения %s\n", secret1);
        return;
    }
    if (read_from_file(secret2, ss2, CRYPTO_BYTES) != 0) {
        fprintf(stderr, "Ошибка чтения %s\n", secret2);
        return;
    }
    if (verify(ss1, ss2, CRYPTO_BYTES) == 0) {
        printf("Секреты совпадают\n");
    } else {
        printf("Секреты НЕ совпадают\n");
    }
}

// Функция 5: Вывод Base64 от секрета
void print_base64_secret(const char *secret_file) {
    unsigned char ss[CRYPTO_BYTES];
    if (read_from_file(secret_file, ss, CRYPTO_BYTES) != 0) {
        fprintf(stderr, "Ошибка чтения %s\n", secret_file);
        return;
    }
    char base64[ ((CRYPTO_BYTES + 2) / 3) * 4 + 1 ];
    base64_encode(ss, CRYPTO_BYTES, base64);
    printf("Base64 секрета: %s\n", base64);
}

// Вспомогательная функция для помощи
void print_help() {
    printf("Использование: ./program <команда>\n");
    printf("0 - Помощь\n");
    printf("1 - Генерация ключей (использует Alice-pub.key и Alice-priv.key)\n");
    printf("2 - Генерация секрета и шифра Боба (использует Alice-pub.key, Bob-secret.sec, Bob-cipher.cip)\n");
    printf("3 - Вычисление секрета Алисы (использует Bob-cipher.cip, Alice-priv.key, Alice-secret.sec)\n");
    printf("4 - Сравнение секретов (использует Bob-secret.sec и Alice-secret.sec)\n");
    printf("5 - Вывод Base64 от секрета (использует Alice-secret.sec или Bob-secret.sec, здесь Alice-secret.sec)\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_help();
        return 1;
    }

    int cmd = atoi(argv[1]);

    switch (cmd) {
        case 0:
            print_help();
            break;
        case 1:
            generate_keys("Alice-pub.key", "Alice-priv.key");
            break;
        case 2:
            generate_secret_and_cipher("Alice-pub.key", "Bob-secret.sec", "Bob-cipher.cip");
            break;
        case 3:
            compute_secret("Bob-cipher.cip", "Alice-priv.key", "Alice-secret.sec");
            break;
        case 4:
            compare_secrets("Bob-secret.sec", "Alice-secret.sec");
            break;
        case 5:
            print_base64_secret("Alice-secret.sec");
            break;
        default:
            print_help();
            break;
    }

    return 0;
}
