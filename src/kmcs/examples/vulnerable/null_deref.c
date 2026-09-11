/*
 * KMCS demo target: null pointer dereference.
 * Expected sanitizer: AddressSanitizer: SEGV on unknown address
 * Expected classification: segmentation-fault
 * DO NOT DEPLOY.
 */
#include <stdio.h>

int main(void) {
    int *pointer = NULL;
    if (getchar() == EOF) {
        return 0;
    }
    /* BUG: unconditionally dereferences NULL. */
    return *pointer;
}
