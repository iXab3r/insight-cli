#include <stdio.h>
#include <unistd.h>
#if defined(INSIGHT_WITH_CORE_FOUNDATION)
#include <CoreFoundation/CoreFoundation.h>
#endif
__attribute__((noinline,visibility("default"))) int quote_total(int count) {
    return count < 11 ? 13 * count : 8 * count + 21;
}
int main(void) {
#if defined(INSIGHT_WITH_CORE_FOUNDATION)
    printf("CF=%lu\n", CFGetTypeID(CFSTR("owned-probe")));
#endif
    puts("READY"); fflush(stdout);
    for (int i = 0; i < 600; i++) {
        printf("%d\n", quote_total(i % 15 + 1)); fflush(stdout); usleep(100000);
    }
    return 0;
}
