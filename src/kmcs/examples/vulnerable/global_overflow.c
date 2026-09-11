/*
 * KMCS demo target: global buffer overflow.
 * Expected sanitizer: AddressSanitizer: global-buffer-overflow
 * Expected classification: global-buffer-overflow
 * DO NOT DEPLOY.
 */
#include <stdio.h>

static char global_buffer[8];

int main(void) {
    size_t n = 0;
    int c;
    while ((c = getchar()) != EOF && n < 32) {
        global_buffer[n++] = (char)c;   /* BUG: buffer holds only 8 bytes */
    }
    return (int)n;
}
