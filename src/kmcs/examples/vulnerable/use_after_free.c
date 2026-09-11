/*
 * KMCS demo target: use after free.
 * Expected sanitizer: AddressSanitizer: heap-use-after-free
 * Expected classification: use-after-free
 * DO NOT DEPLOY.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buffer = (char *)malloc(16);
    if (buffer == NULL) {
        return 1;
    }
    int c = getchar();
    if (c == EOF) {
        free(buffer);
        return 0;
    }
    buffer[0] = (char)c;
    free(buffer);

    /* BUG: reading from freed memory. */
    volatile char observed = buffer[0];
    return observed;
}
