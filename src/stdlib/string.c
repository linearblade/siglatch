#include <stddef.h>

size_t strlcpy(char *dst, const char *src, size_t dstsize) {
    const char *s = src;
    size_t n = dstsize;

    // Copy as many bytes as will fit
    if (n != 0) {
        while (--n != 0) {
            if ((*dst++ = *s++) == '\0')
                break;
        }
    }

    // If we ran out of space, null-terminate manually
    if (n == 0) {
        if (dstsize != 0)
            *dst = '\0';  // Null-terminate if there's room

        // Finish traversing source to calculate full length
        while (*s++)
            ;
    }

    return (size_t)(s - src - 1);  // Return total length of src
}

#include <stddef.h>

size_t strlcat(char *dst, const char *src, size_t dstsize) {
    size_t dlen = 0;
    const char *s = src;
    char *d = dst;
    size_t n = dstsize;

    // Find end of dst and how much space is left
    while (n-- != 0 && *d != '\0') {
        d++;
        dlen++;
    }

    n = dstsize - dlen;

    if (n == 0)
        return dlen + strlen(src);  // No space left to append

    while (*s != '\0') {
        if (n != 1) {
            *d++ = *s;
            n--;
        }
        s++;
    }

    *d = '\0';

    return dlen + (s - src);  // Total length it *tried* to make
}
