#include <yyjson.h>

#define MAX_INPUT_SIZE   (256u * 1024u)
#define SMALL_INPUT_SIZE (4096u)

static char *dup_with_padding(const uint8_t *data, size_t size) {
    char *buf = (char *)malloc(size + YYJSON_PADDING_SIZE);
    if (!buf) {
        return NULL;
    }

    memcpy(buf, data, size);
    memset(buf + size, 0, YYJSON_PADDING_SIZE);
    return buf;
}

static size_t next_step(const uint8_t *data,
                        size_t size,
                        size_t read_len,
                        unsigned chunk_mode) {
    if (read_len >= size) {
        return 0;
    }

    /*
     * For small inputs, try every possible chunk boundary.
     * Incremental parsers are often sensitive to token boundaries.
     */
    if (chunk_mode == 0 && size <= SMALL_INPUT_SIZE) {
        return 1;
    }

    /*
     * For larger inputs, use deterministic input-dependent steps.
     * yyjson_incr_read() expects a cumulative length, not a chunk length.
     */
    size_t idx = (read_len + chunk_mode) % size;
    size_t step = 1 + (data[idx] & 0x3F); /* 1..64 bytes */

    if (step > size - read_len) {
        step = size - read_len;
    }

    return step;
}

static void test_with_flags(const uint8_t *data,
                            size_t size,
                            yyjson_read_flag flag,
                            unsigned chunk_mode) {
    char *buf = dup_with_padding(data, size);
    if (!buf) {
        return;
    }

    yyjson_incr_state *state = yyjson_incr_new(buf, size, flag, NULL);
    if (!state) {
        free(buf);
        return;
    }

    size_t read_len = 0;
    yyjson_doc *doc = NULL;
    yyjson_read_err err;

    while (read_len < size) {
        size_t step = next_step(data, size, read_len, chunk_mode);
        if (step == 0) {
            break;
        }

        read_len += step;

        /*
         * While the parser is only allowed to see data[0..read_len),
         * poison the first unavailable byte. This helps expose bugs where
         * the incremental reader accidentally consumes future input.
         *
         * Do not poison buf[size]; the padding area should remain zeroed.
         */
        if (read_len < size) {
            char saved = buf[read_len];
            buf[read_len] = 'X';

            doc = yyjson_incr_read(state, read_len, &err);

            buf[read_len] = saved;
        } else {
            doc = yyjson_incr_read(state, read_len, &err);
        }

        if (doc) {
            yyjson_doc_free(doc);
            break;
        }

        if (err.code != YYJSON_READ_ERROR_MORE) {
            break;
        }
    }

    yyjson_incr_free(state);
    free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_INPUT_SIZE) {
        return 0;
    }

    /*
     * The incremental reader supports standard JSON. Non-standard reader
     * flags such as comments and trailing commas are intentionally omitted.
     *
     * Each call uses a different chunk_mode so the same input is tested
     * against different deterministic chunk-boundary patterns.
     */
    test_with_flags(data, size, YYJSON_READ_NOFLAG, 0);

    test_with_flags(data, size,
	                YYJSON_READ_STOP_WHEN_DONE, 1);

    test_with_flags(data, size,
	                YYJSON_READ_NUMBER_AS_RAW, 2);

    test_with_flags(data, size,
	                YYJSON_READ_BIGNUM_AS_RAW, 3);

    test_with_flags(data, size,
	                YYJSON_READ_INSITU, 4);

    test_with_flags(data, size,
                    YYJSON_READ_INSITU | YYJSON_READ_STOP_WHEN_DONE, 5);

    return 0;
}
