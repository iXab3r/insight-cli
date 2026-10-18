#include <stdio.h>

__attribute__((noinline)) int nested_total(int count) {
    if (count <= 0) return 0;
    return nested_total(count - 1) + count;
}

int main(void) {
    printf("%d\n", nested_total(5));
    return 0;
}
