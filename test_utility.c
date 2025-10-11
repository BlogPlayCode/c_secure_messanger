#include "kyber_utility.h"
#include <stdio.h>
#include <string.h>

// Вспомогательная функция для помощи

void print_help() {
    printf("0 - Help\n");
    printf("1 Alice-pub.key Alice-priv.key - Alice key pair generation\n");
    printf("2 Alice-pub.key Bob-secret.sec Bob-cipher.cip - Bob secret and cipher generation\n");
    printf("3 Bob-cipher.cip Alice-priv.key Alice-secret.sec - Alice secret calculation\n");
    printf("4 Bob-secret.sec Alice-secret.sec - Secrets compare\n");
    printf("5 X-secret.sec - Print Base64 of the secret\n");
    printf("6 \"plaintext\" output_file key_file - AES-256-GCM encryption\n");
    printf("7 input_file key_file - AES-256-GCM decryption\n");
    printf("\nUsage: utility_cli {function number} {arguments}\n");
}

int main(int argc, char *argv[]) {

    int cmd = 0;
    if (argc < 2) {
        printf("Enter command: ");
        scanf("%d", &cmd);
    } else {
        cmd = atoi(argv[1]);
    }

    switch (cmd) {
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
            char result = compare_secrets("Bob-secret.sec", "Alice-secret.sec");
            if (result == 'm') {
                printf("match\n");
            } else if (result == 'n') {
                printf("not match\n");
            } else {
                printf("error\n");
            }
            break;
        case 5:
            char* result = base64_secret("Alice-secret.sec");
            if (strcmp(result, "error")) {
                printf("error\n");
            } else {
                printf("%s", result);
            }
            break;
        case 6:
            int result = aes_encrypt("test-text", "encrypted.bin", "Alice-secret.sec");
            if (result != 0) {
                printf("error");
                return result;
            }
            break;
        case 7:
            char* result = aes_decrypt("encrypted.bin", "Bob-secret.sec");
            if (result == NULL) {
                printf("error");
                return 1;
            } else {
                printf("%s", result);
                free(result);
            }
            break;
        default:
            print_help();
            break;
    }

    return 0;
}