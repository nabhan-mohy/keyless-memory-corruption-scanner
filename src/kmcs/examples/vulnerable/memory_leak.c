/*
 * KMCS demo target: memory leak.
 * Expected sanitizer: LeakSanitizer: Direct leak
 * Expected classification: memory-leak
 * DO NOT DEPLOY.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buffer = (char *)malloc(64);
    if (buffer == NULL) {
        return 1;
    }
    int c = getchar();
    if (c != EOF) {
        buffer[0] = (char)c;
    }
    /* BUG: buffer is never freed. */
    return 0;
}
