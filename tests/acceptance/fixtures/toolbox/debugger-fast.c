#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline,visibility("default"))) int quote_total(int count) {
    return count < 11 ? 13 * count : 8 * count + 21;
}
int main(int argc, char **argv) {
    volatile int count = argc > 1 ? atoi(argv[1]) : 11;
    printf("%d\n", quote_total(count));
    return 0;
}
