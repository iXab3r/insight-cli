#if defined(_WIN32)
#define API __declspec(dllexport)
#define NOINLINE __declspec(noinline)
__declspec(dllimport) int upstream_adjust(int value);
#else
#define API __attribute__((visibility("default")))
#define NOINLINE __attribute__((noinline))
extern int upstream_adjust(int value);
#endif
struct PricingRule { int low; int high; int surcharge; };
static NOINLINE int price_from_rule(const struct PricingRule *rule, int count) {
    return count < 11 ? count * rule->low : count * rule->high + rule->surcharge;
}
API int quote_total(int count) {
    const struct PricingRule rule = {13, 8, 21};
    return price_from_rule(&rule, count);
}
#if defined(__APPLE__)
extern int puts(const char *text);
int main(void) { puts("owned native fixture"); return quote_total(4); }
#elif defined(_WIN32)
int main(void) { return upstream_adjust(quote_total(4)); }
#else
int _start(void) { return upstream_adjust(quote_total(4)); }
#endif
