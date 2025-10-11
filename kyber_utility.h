#ifndef KYBER_UTILITY_H
#define KYBER_UTILITY
#include <stdlib.h>

void base64_encode(const unsigned char *input, size_t input_len, char *output);
int write_to_file(const char *filename, const unsigned char *data, size_t len);
int read_from_file(const char *filename, unsigned char *data, size_t len);

// Функция 1: Генерация пары ключей и сохранение в файлы
int generate_keys(const char *pub_file, const char *priv_file);

// Функция 2: Вычисление общего секрета и шифра по публичному ключу
int generate_secret_and_cipher(const char *pub_file, const char *secret_file, const char *cipher_file);

// Функция 3: Вычисление общего секрета по шифру и приватному ключу
int compute_secret(const char *cipher_file, const char *priv_file, const char *secret_file);

// Функция 4: Сравнение двух секретов
char compare_secrets(const char *secret1, const char *secret2);

// Функция 5: Вывод Base64 от секрета
char* base64_secret(const char *secret_file);

// Функция 6: Шифрование строки с помощью AES-256-GCM с сохранением в файл
int aes_encrypt(const char *plaintext, const char *output_file, const char *key_file);

// Функция 7: Расшифровка AES-256-GCM из файла по ключу с возвратом строки
char* aes_decrypt(const char *input_file, const char *key_file);

#endif
