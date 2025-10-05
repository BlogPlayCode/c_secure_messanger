#include "kyber_utility.h"


int main(int argc, char *argv[]) {
    // if (argc != 2) {
    //     print_help();
    //     return 1;
    // }

    printf("Enter command: ");
    int cmd = 0; // argv[1]
    scanf("%d", &cmd);

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