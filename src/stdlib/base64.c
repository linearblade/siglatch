#include "base64.h"

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_len) {
    size_t i = 0, j = 0;
    unsigned char arr_3[3];
    unsigned char arr_4[4];

    if (!input || !output) return -1;

    while (input_len--) {
        arr_3[i++] = *(input++);
        if (i == 3) {
            arr_4[0] = (arr_3[0] & 0xfc) >> 2;
            arr_4[1] = ((arr_3[0] & 0x03) << 4) + ((arr_3[1] & 0xf0) >> 4);
            arr_4[2] = ((arr_3[1] & 0x0f) << 2) + ((arr_3[2] & 0xc0) >> 6);
            arr_4[3] = arr_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                if (j >= output_len - 1) return -1; // overflow
                output[j++] = base64_table[arr_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (size_t k = i; k < 3; k++) arr_3[k] = '\0';

        arr_4[0] = (arr_3[0] & 0xfc) >> 2;
        arr_4[1] = ((arr_3[0] & 0x03) << 4) + ((arr_3[1] & 0xf0) >> 4);
        arr_4[2] = ((arr_3[1] & 0x0f) << 2) + ((arr_3[2] & 0xc0) >> 6);
        arr_4[3] = arr_3[2] & 0x3f;

        for (size_t k = 0; k < i + 1; k++) {
            if (j >= output_len - 1) return -1;
            output[j++] = base64_table[arr_4[k]];
        }

        while (i++ < 3) {
            if (j >= output_len - 1) return -1;
            output[j++] = '=';
        }
    }

    output[j] = '\0'; // Null-terminate
    return (int)j;
}
