/*
 * KMCS demo target: heap out-of-bounds read.
 * Expected sanitizer: AddressSanitizer: heap-buffer-overflow (READ)
 * Expected classification: heap-buffer-overflow
 * Trigger: input byte in '4'..'9'
 * DO NOT DEPLOY.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *values = (int *)malloc(4 * sizeof(int));
    if (values == NULL) {
        return 1;
    }
    values[0] = 1; values[1] = 2; values[2] = 3; values[3] = 4;

    int c = getchar();
    if (c == EOF) {
        free(values);
        return 0;
    }
    int index = c - '0';
    if (index < 0 || index > 3) {
        index = 0;
    }
    /* BUG: index can be exactly 3, but we increment it before the read. */
    int observed = values[index + 1];  /* OOB when index == 3 */
    free(values);
    return observed;
}
