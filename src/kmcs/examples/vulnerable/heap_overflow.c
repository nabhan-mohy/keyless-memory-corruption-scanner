/*
 * KMCS demo target: heap buffer overflow.
 * Expected sanitizer: AddressSanitizer: heap-buffer-overflow
 * Expected classification: heap-buffer-overflow
 * DO NOT DEPLOY.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buffer = (char *)malloc(8);
    if (buffer == NULL) {
        return 1;
    }
    size_t n = 0;
    int c;
    while ((c = getchar()) != EOF && n < 64) {
        buffer[n++] = (char)c;   /* BUG: buffer holds only 8 bytes */
    }
    free(buffer);
    return 0;
}
