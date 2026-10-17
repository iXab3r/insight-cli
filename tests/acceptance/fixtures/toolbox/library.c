#if defined(_WIN32)
__declspec(dllexport)
#else
__attribute__((visibility("default")))
#endif
int upstream_adjust(int value) { return value + 3; }
