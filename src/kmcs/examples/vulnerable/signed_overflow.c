/*
 * KMCS demo target: signed integer overflow.
 * Expected sanitizer: UndefinedBehaviorSanitizer: signed integer overflow
 * Expected classification: undefined-behavior
 * DO NOT DEPLOY.
 */
#include <limits.h>
#include <stdio.h>

volatile int sink;

int main(void) {
    int c = getchar();
    if (c == EOF || c <= 0) {
        return 0;
    }
    int x = INT_MAX;
    sink = x + c;   /* BUG: signed overflow for any c > 0 */
    return 0;
}
