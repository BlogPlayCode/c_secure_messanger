#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Подключаем заголовочные файлы из репозитория Kyber (официальный: https://github.com/pqcrystals/kyber)
#include "kyber/ref/api.h"
#include "kyber/ref/params.h"
#include "kyber/ref/verify.h"

// Подключаем заголовочные файлы из репозитория Mbed TLS для AES (официальный: https://github.com/Mbed-TLS/mbedtls, безопасная реализация для коммерческого использования)
#include "mbedtls/include/mbedtls/aes.h"
#include "mbedtls/include/mbedtls/gcm.h"

// Объявляем randombytes из Kyber для генерации случайных байтов (используется для IV в AES)
extern void randombytes(unsigned char *out, size_t outlen);

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
// @param filename Имя файла для записи
// @param data Данные для записи
// @param len Длина данных
// @return 0 при успехе, -1 при ошибке
int write_to_file(const char *filename, const unsigned char *data, size_t len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    return (written == len) ? 0 : -1;
}

// Вспомогательная функция для чтения бинарных данных из файла фиксированной длины
// @param filename Имя файла для чтения
// @param data Буфер для данных
// @param len Ожидаемая длина
// @return 0 при успехе, -1 при ошибке
int read_from_file(const char *filename, unsigned char *data, size_t len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return -1;
    size_t read = fread(data, 1, len, fp);
    fclose(fp);
    return (read == len) ? 0 : -1;
}

// Вспомогательная функция для чтения всего файла в память
// @param filename Имя файла
// @param data Указатель на выделенную память (освобождается вызывающим)
// @param len Указатель на длину данных
// @return 0 при успехе, -1 при ошибке IO, -2 при ошибке выделения памяти
int read_whole_file(const char *filename, unsigned char **data, size_t *len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    *len = ftell(fp);
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    *data = malloc(*len);
    if (!*data) {
        fclose(fp);
        return -2;
    }
    size_t read_bytes = fread(*data, 1, *len, fp);
    fclose(fp);
    if (read_bytes != *len) {
        free(*data);
        return -1;
    }
    return 0;
}

// Функция 1: Генерация пары ключей Kyber-768 и сохранение в файлы
// @param pub_file Имя файла для публичного ключа
// @param priv_file Имя файла для приватного ключа
// @return 0 при успехе, 1 при ошибке записи, 2 при ошибке генерации
int generate_keys(const char *pub_file, const char *priv_file) {
    unsigned char pk[KYBER_PUBLICKEYBYTES];
    unsigned char sk[KYBER_SECRETKEYBYTES];
    if (pqcrystals_kyber768_ref_keypair(pk, sk) != 0) {
        fprintf(stderr, "Key pair generation error\n");
        return 2;
    }
    if (write_to_file(pub_file, pk, KYBER_PUBLICKEYBYTES) != 0) {
        fprintf(stderr, "Write error: %s\n", pub_file);
        return 1;
    }
    if (write_to_file(priv_file, sk, KYBER_SECRETKEYBYTES) != 0) {
        fprintf(stderr, "Write error: %s\n", priv_file);
        return 1;
    }
    return 0;
}

// Функция 2: Вычисление общего секрета и шифра по публичному ключу Kyber-768
// @param pub_file Имя файла с публичным ключом
// @param secret_file Имя файла для сохранения секрета
// @param cipher_file Имя файла для сохранения шифра
// @return 0 при успехе, 1 при ошибке IO, 2 при ошибке инкапсуляции
int generate_secret_and_cipher(const char *pub_file, const char *secret_file, const char *cipher_file) {
    unsigned char pk[KYBER_PUBLICKEYBYTES];
    if (read_from_file(pub_file, pk, KYBER_PUBLICKEYBYTES) != 0) {
        fprintf(stderr, "Read error: %s\n", pub_file);
        return 1;
    }
    unsigned char ct[KYBER_CIPHERTEXTBYTES];
    unsigned char ss[KYBER_SSBYTES];
    if (pqcrystals_kyber768_ref_enc(ct, ss, pk) != 0) {
        fprintf(stderr, "Encaps error\n");
        return 2;
    }
    if (write_to_file(secret_file, ss, KYBER_SSBYTES) != 0) {
        fprintf(stderr, "Write error: %s\n", secret_file);
        return 1;
    }
    if (write_to_file(cipher_file, ct, KYBER_CIPHERTEXTBYTES) != 0) {
        fprintf(stderr, "Write error: %s\n", cipher_file);
        return 1;
    }
    return 0;
}

// Функция 3: Вычисление общего секрета по шифру и приватному ключу Kyber-768
// @param cipher_file Имя файла с шифром
// @param priv_file Имя файла с приватным ключом
// @param secret_file Имя файла для сохранения секрета
// @return 0 при успехе, 1 при ошибке IO, 2 при ошибке декапсуляции
int compute_secret(const char *cipher_file, const char *priv_file, const char *secret_file) {
    unsigned char ct[KYBER_CIPHERTEXTBYTES];
    unsigned char sk[KYBER_SECRETKEYBYTES];
    if (read_from_file(cipher_file, ct, KYBER_CIPHERTEXTBYTES) != 0) {
        fprintf(stderr, "Read error: %s\n", cipher_file);
        return 1;
    }
    if (read_from_file(priv_file, sk, KYBER_SECRETKEYBYTES) != 0) {
        fprintf(stderr, "Read error: %s\n", priv_file);
        return 1;
    }
    unsigned char ss[KYBER_SSBYTES];
    if (pqcrystals_kyber768_ref_dec(ss, ct, sk) != 0) {
        fprintf(stderr, "Decaps error\n");
        return 2;
    }
    if (write_to_file(secret_file, ss, KYBER_SSBYTES) != 0) {
        fprintf(stderr, "Write error: %s\n", secret_file);
        return 1;
    }
    return 0;
}

// Функция 4: Сравнение двух секретов из файлов
// @param secret1 Имя первого файла с секретом
// @param secret2 Имя второго файла с секретом
// @return 'm' если совпадают, 'n' если нет, 'e' при ошибке чтения
char compare_secrets(const char *secret1, const char *secret2) {
    unsigned char ss1[KYBER_SSBYTES];
    unsigned char ss2[KYBER_SSBYTES];
    if (read_from_file(secret1, ss1, KYBER_SSBYTES) != 0) {
        fprintf(stderr, "Read error: %s\n", secret1);
        return 'e';
    }
    if (read_from_file(secret2, ss2, KYBER_SSBYTES) != 0) {
        fprintf(stderr, "Read error: %s\n", secret2);
        return 'e';
    }
    if (verify(ss1, ss2, KYBER_SSBYTES) == 0) {
        return 'm';
    } else {
        return 'n';
    }
}

// Функция 5: Вывод Base64-кодированного секрета из файла
// @param secret_file Имя файла с секретом
// @return Указатель на malloc-выделенную строку Base64 или "error" при ошибке (освобождается вызывающим)
char* base64_secret(const char *secret_file) {
    unsigned char ss[KYBER_SSBYTES];
    if (read_from_file(secret_file, ss, KYBER_SSBYTES) != 0) {
        fprintf(stderr, "Read error: %s\n", secret_file);
        return "error";
    }
    char* base64 = malloc((((KYBER_SSBYTES+2)/3)*4+1) * sizeof(char));
    base64_encode(ss, KYBER_SSBYTES, base64);
    return base64;
}

// Функция 6: Шифрование строки с помощью AES-256-GCM с сохранением в файл
// Использует аутентифицированное шифрование для безопасности (IV + tag + ciphertext)
// @param plaintext Строка для шифрования (null-terminated)
// @param output_file Имя файла для сохранения зашифрованных данных
// @param key_file Имя файла с ключом (ровно 32 байта)
// @return 0 при успехе, 1 при ошибке IO, 2 при ошибке шифрования, 3 при ошибке выделения памяти
int aes_encrypt(const char *plaintext, const char *output_file, const char *key_file) {
    size_t plaintext_len = strlen(plaintext);
    unsigned char key[32];
    if (read_from_file(key_file, key, 32) != 0) {
        fprintf(stderr, "Read error: %s\n", key_file);
        return 1;
    }
    unsigned char iv[12];
    randombytes(iv, 12);
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        fprintf(stderr, "AES setkey error\n");
        mbedtls_gcm_free(&ctx);
        return 2;
    }
    unsigned char *ciphertext = malloc(plaintext_len);
    if (!ciphertext) {
        fprintf(stderr, "Malloc error\n");
        mbedtls_gcm_free(&ctx);
        return 3;
    }
    unsigned char tag[16];
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len, iv, 12, NULL, 0,
                                    (const unsigned char *)plaintext, ciphertext, 16, tag);
    if (ret != 0) {
        fprintf(stderr, "AES encrypt error\n");
        free(ciphertext);
        mbedtls_gcm_free(&ctx);
        return 2;
    }
    FILE *fp = fopen(output_file, "wb");
    if (!fp) {
        fprintf(stderr, "Write error: %s\n", output_file);
        free(ciphertext);
        mbedtls_gcm_free(&ctx);
        return 1;
    }
    if (fwrite(iv, 1, 12, fp) != 12 ||
        fwrite(tag, 1, 16, fp) != 16 ||
        fwrite(ciphertext, 1, plaintext_len, fp) != plaintext_len) {
        fprintf(stderr, "Write error: %s\n", output_file);
        fclose(fp);
        free(ciphertext);
        mbedtls_gcm_free(&ctx);
        return 1;
    }
    fclose(fp);
    free(ciphertext);
    mbedtls_gcm_free(&ctx);
    return 0;
}

// Функция 7: Расшифровка AES-256-GCM из файла по ключу с возвратом строки
// Ожидает формат: IV (12 байт) + tag (16 байт) + ciphertext
// @param input_file Имя файла с зашифрованными данными
// @param key_file Имя файла с ключом (ровно 32 байта)
// @return Указатель на malloc-выделенную расшифрованную строку (null-terminated) или NULL при ошибке (освобождается вызывающим)
char *aes_decrypt(const char *input_file, const char *key_file) {
    unsigned char key[32];
    if (read_from_file(key_file, key, 32) != 0) {
        fprintf(stderr, "Read error: %s\n", key_file);
        return NULL;
    }
    unsigned char *data;
    size_t data_len;
    if (read_whole_file(input_file, &data, &data_len) != 0) {
        fprintf(stderr, "Read error: %s\n", input_file);
        return NULL;
    }
    if (data_len < 12 + 16) {
        fprintf(stderr, "Invalid file size: %s\n", input_file);
        free(data);
        return NULL;
    }
    unsigned char *iv = data;
    unsigned char *tag = data + 12;
    unsigned char *ciphertext = data + 12 + 16;
    size_t ciphertext_len = data_len - 12 - 16;
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        fprintf(stderr, "AES setkey error\n");
        free(data);
        mbedtls_gcm_free(&ctx);
        return NULL;
    }
    unsigned char *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        fprintf(stderr, "Malloc error\n");
        free(data);
        mbedtls_gcm_free(&ctx);
        return NULL;
    }
    ret = mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len, iv, 12, NULL, 0, tag, 16, ciphertext, plaintext);
    if (ret != 0) {
        fprintf(stderr, "AES decrypt error\n");
        free(plaintext);
        free(data);
        mbedtls_gcm_free(&ctx);
        return NULL;
    }
    char *result = malloc(ciphertext_len + 1);
    if (!result) {
        fprintf(stderr, "Malloc error\n");
        free(plaintext);
        free(data);
        mbedtls_gcm_free(&ctx);
        return NULL;
    }
    memcpy(result, plaintext, ciphertext_len);
    result[ciphertext_len] = '\0';
    free(plaintext);
    free(data);
    mbedtls_gcm_free(&ctx);
    return result;
}
