#ifndef __UBIRCH_CLIENT_UTIL_H__
#define __UBIRCH_CLIENT_UTIL_H__

//#define __DEBUG_OUTPUT

#define HEXDUMP(__prefix, __array, __size) {\
    printf("%s", __prefix); \
    size_t __ii; \
    for (__ii = 0; __ii < __size; __ii++) { \
        printf("%02x", *(__array + __ii)); \
    } \
}

#ifdef __DEBUG_OUTPUT
#define DEBUGHEXDUMP(__prefix, __array, __size) { \
    HEXDUMP(__prefix, __array, __size); \
    printf("\n"); \
}

#else
#define DEBUGHEXDUMP(__prefix, __array, __size)
#endif

#endif // __UBIRCH_CLIENT_UTIL_H__
