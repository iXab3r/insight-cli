/* Versioned executable oracle. No OS imports, waits or synthetic benchmark delays. */
#ifndef VERSION
#define VERSION 1
#endif
#define EXPORT __declspec(dllexport)
#define NOINLINE __declspec(noinline)
EXPORT volatile const char evidence_config[] = "insight-config-v1.json";
#if VERSION == 1
EXPORT volatile const char evidence_version[] = "business-build-one";
#else
EXPORT volatile const char evidence_version[] = "business-build-two";
#endif
#define CASE(N) EXPORT NOINLINE int case##N(int x) { return x + N + VERSION; }
CASE(1) CASE(2) CASE(3) CASE(4) CASE(5) CASE(6) CASE(7) CASE(8) CASE(9)
CASE(10) CASE(11) CASE(12) CASE(13) CASE(14) CASE(15) CASE(16) CASE(17)
CASE(18) CASE(19) CASE(20) CASE(21) CASE(22) CASE(23) CASE(24) CASE(25)
EXPORT NOINLINE int config_read(unsigned x) { return case1(x) + evidence_config[x & 7]; }
EXPORT NOINLINE unsigned hash_fnv(const unsigned char *s) {
    unsigned h = 2166136261u; while (*s) { h = (h ^ *s++) * 16777619u; } return h;
}
EXPORT NOINLINE unsigned hash_djb(const unsigned char *s) {
    unsigned h = 5381u; while (*s) h = h * 33u + *s++; return h;
}
EXPORT NOINLINE unsigned hash_sdbm(const unsigned char *s) {
    unsigned h = 0; while (*s) { h = *s++ + (h << 6) + (h << 16) - h; } return h;
}
EXPORT int main(void) { return config_read(VERSION); }
