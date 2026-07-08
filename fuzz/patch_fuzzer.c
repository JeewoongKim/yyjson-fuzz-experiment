#include <yyjson.h>

#define YYJSON_PATCH_MAX_INPUT_SIZE 8192

static void write_and_free_mut_val(yyjson_mut_val *val) {
    if (val == NULL) {
        return;
    }

    size_t len = 0;
    char *json = yyjson_mut_val_write(val, YYJSON_WRITE_NOFLAG, &len);
    if (json != NULL) {
        free(json);
    }
}

static void run_json_patch(yyjson_doc *base_doc, yyjson_doc *patch_doc) {
    yyjson_val *base_root = yyjson_doc_get_root(base_doc);
    yyjson_val *patch_root = yyjson_doc_get_root(patch_doc);

    if (base_root == NULL || patch_root == NULL) {
        return;
    }

    yyjson_mut_doc *result_doc = yyjson_mut_doc_new(NULL);
    if (result_doc != NULL) {
        yyjson_patch_err err;
        memset(&err, 0, sizeof(err));

        yyjson_mut_val *result =
            yyjson_patch(result_doc, base_root, patch_root, &err);
        write_and_free_mut_val(result);

        yyjson_mut_doc_free(result_doc);
    }

    yyjson_mut_doc *mut_doc = yyjson_mut_doc_new(NULL);
    if (mut_doc != NULL) {
        yyjson_mut_val *base_mut = yyjson_val_mut_copy(mut_doc, base_root);
        yyjson_mut_val *patch_mut = yyjson_val_mut_copy(mut_doc, patch_root);

        if (base_mut != NULL && patch_mut != NULL) {
            yyjson_patch_err err;
            memset(&err, 0, sizeof(err));

            yyjson_mut_val *result =
                yyjson_mut_patch(mut_doc, base_mut, patch_mut, &err);
            write_and_free_mut_val(result);
        }

        yyjson_mut_doc_free(mut_doc);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL ||
        size < sizeof(uint16_t) + 1 ||
        size > YYJSON_PATCH_MAX_INPUT_SIZE) {
        return 0;
    }

    uint16_t split_len_raw;
    memcpy(&split_len_raw, data, sizeof(split_len_raw));

    data += sizeof(split_len_raw);
    size -= sizeof(split_len_raw);

    size_t base_size = split_len_raw % (size + 1);
    size_t patch_size = size - base_size;

    const uint8_t *base_data = data;
    const uint8_t *patch_data = data + base_size;

    yyjson_read_flag flags =
        YYJSON_READ_ALLOW_INVALID_UNICODE |
        YYJSON_READ_ALLOW_COMMENTS;

    yyjson_doc *base_doc =
        yyjson_read_opts((char *)(void *)base_data, base_size, flags, NULL, NULL);
    yyjson_doc *patch_doc =
        yyjson_read_opts((char *)(void *)patch_data, patch_size, flags, NULL, NULL);

    if (base_doc != NULL && patch_doc != NULL) {
        run_json_patch(base_doc, patch_doc);
    }

    yyjson_doc_free(base_doc);
    yyjson_doc_free(patch_doc);

    return 0;
}
