/*
 * KMCS demo target: double free.
 * Expected sanitizer: AddressSanitizer: attempting double-free
 * Expected classification: double-free
 * DO NOT DEPLOY.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buffer = (char *)malloc(16);
    if (buffer == NULL) {
        return 1;
    }
    if (getchar() == EOF) {
        free(buffer);
        return 0;
    }
    free(buffer);
    free(buffer);   /* BUG: buffer was already freed */
    return 0;
}
