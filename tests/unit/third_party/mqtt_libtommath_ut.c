#include "tommath.h"

const unsigned int mock_last_mp_from_ubin_max_sz = 9;
unsigned int       mock_last_mp_from_ubin_idx;
unsigned char     *mock_last_mp_from_ubin_in_data[9];
size_t             mock_last_mp_from_ubin_in_len[9];

int    mock_mp_add_return_val;
size_t mock_mp_ubin_sz_val;

mp_err mp_init(mp_int *a) { return 0; }

mp_err mp_from_ubin(mp_int *out, const unsigned char *buf, size_t size) {
    if (mock_last_mp_from_ubin_max_sz > mock_last_mp_from_ubin_idx) {
        mock_last_mp_from_ubin_in_data[mock_last_mp_from_ubin_idx] = buf;
        mock_last_mp_from_ubin_in_len[mock_last_mp_from_ubin_idx] = size;
        mock_last_mp_from_ubin_idx++;
    }
    return 0;
}

mp_err mp_add(const mp_int *a, const mp_int *b, mp_int *c) { return mock_mp_add_return_val; }

// mp_digit
mp_err mp_add_d(const mp_int *a, mp_digit b, mp_int *c) { return mock_mp_add_return_val; }

size_t mp_ubin_size(const mp_int *a) { return mock_mp_ubin_sz_val; }

mp_err mp_to_ubin(const mp_int *a, unsigned char *buf, size_t maxlen, size_t *written) { return 0; }

void mp_clear(mp_int *a) { return; }
