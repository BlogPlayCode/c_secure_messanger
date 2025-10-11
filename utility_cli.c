#include "kyber_utility.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
        print_help();
        return 1;
    } else {
        cmd = atoi(argv[1]);
    }

    switch (cmd) {
        case 1:
            if (argc < 4) {
                print_help();
                return 1;
            } else {
                int result = generate_keys(argv[2], argv[3]);
                if (result != 0) {
                    printf("error");
                    return result;
                }
            }
            break;
        case 2:
            if (argc < 5) {
                print_help();
                return 1;
            } else {
                int result = generate_secret_and_cipher(argv[2], argv[3], argv[4]);
                if (result != 0) {
                    printf("error");
                    return result;
                }
            }
            break;
        case 3:
            if (argc < 5) {
                print_help();
                return 1;
            } else {
                int result = compute_secret(argv[2], argv[3], argv[4]);
                if (result != 0) {
                    printf("error");
                    return result;
                }
            }
            break;
        case 4:
            if (argc < 4) {
                print_help();
                return 1;
            } else {
                char result = compare_secrets(argv[2], argv[3]);
                if (result == 'm') {
                    printf("match");
                } else if (result == 'n') {
                    printf("not match");
                } else {
                    printf("error");
                    return 1;
                }
            }
            break;
        case 5:
            if (argc < 3) {
                print_help();
                return 1;
            } else {
                char* result = base64_secret(argv[2]);
                if (strcmp(result, "error") == 0) {
                    printf("error");
                    return 1;
                } else {
                    printf("%s", result);
                    free(result);
                }
            }
            break;
        case 6:
            if (argc < 5) {
                print_help();
                return 1;
            } else {
                int result = aes_encrypt(argv[2], argv[3], argv[4]);
                if (result != 0) {
                    printf("error");
                    return result;
                }
            }
            break;
        case 7:
            if (argc < 4) {
                print_help();
                return 1;
            } else {
                char* result = aes_decrypt(argv[2], argv[3]);
                if (result == NULL) {
                    printf("error");
                    return 1;
                } else {
                    printf("%s", result);
                    free(result);
                }
            }
            break;
        default:
            print_help();
            break;
    }

    return 0;
}
