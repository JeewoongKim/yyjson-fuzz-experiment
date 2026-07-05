#include <yyjson.h>

static void run_incr_reader(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return;
    }

    /*
     * Keep this target focused on incremental-reader state transitions.
     * The input is fed to the parser one byte at a time to stress 
     * token-boundary handling.
     */
    yyjson_read_flag flags = 0;

    yyjson_incr_state *state =
        yyjson_incr_new((char *)(void *)data, size, flags, NULL);
    if (state == NULL) {
        return;
    }

    size_t available = 0;

    while (available < size) {
        available++;

        yyjson_read_err err;
        memset(&err, 0, sizeof(err));

        yyjson_doc *doc = yyjson_incr_read(state, available, &err);
        if (doc != NULL) {
            yyjson_doc_free(doc);
            break;
        }

        if (err.code != YYJSON_READ_ERROR_MORE) {
            break;
        }
    }

    yyjson_incr_free(state);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    run_incr_reader(data, size);
    return 0;
}

