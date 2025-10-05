#include "kyber_utility.h"
#include <stdio.h>


int main(int argc, char *argv[]) {

    int cmd = 0;
    if (argc < 2) {
        printf("Enter command: ");
        scanf("%d", &cmd);
    } else {
        cmd = atoi(argv[1]);
    }

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