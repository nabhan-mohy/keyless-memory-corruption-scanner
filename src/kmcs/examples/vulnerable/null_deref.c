/*
 * KMCS demo target: null pointer dereference.
 *
 * The pointer is read from a global that the compiler cannot see through,
 * so even at -O1 the dereference is emitted and crashes the process.
 * The bug only triggers when the input contains the byte '!'.
 *
 * DO NOT DEPLOY.
 */
#include <stdio.h>
#include <stdlib.h>

/* Externally visible, not const, not initialised in this translation unit.
 * This prevents the compiler from proving the pointer is NULL at compile
 * time, so it must emit the actual load instruction. */
int *kmcs_null_pointer;

int main(void) {
    int c;
    int trigger = 0;
    while ((c = getchar()) != EOF) {
        if (c == '!') {
            trigger = 1;
        }
    }
    if (!trigger) {
        return 0;
    }
    return *kmcs_null_pointer;   /* BUG: kmcs_null_pointer is NULL */
}
