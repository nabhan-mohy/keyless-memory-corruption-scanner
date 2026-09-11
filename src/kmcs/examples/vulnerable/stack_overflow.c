/*
 * KMCS demo target: stack buffer overflow.
 * Expected sanitizer: AddressSanitizer: stack-buffer-overflow
 * Expected classification: stack-buffer-overflow
 * DO NOT DEPLOY.
 */
#include <stdio.h>

int main(void) {
    char buffer[8];
    size_t n = 0;
    int c;
    while ((c = getchar()) != EOF && n < 32) {
        buffer[n++] = (char)c;   /* BUG: buffer holds only 8 bytes */
    }
    return (int)n;
}
