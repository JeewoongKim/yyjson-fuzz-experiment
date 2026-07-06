#include <yyjson.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    // Split the input buffer into two separate documents using the first 2 bytes
    uint16_t split_len_raw;
    memcpy(&split_len_raw, data, sizeof(uint16_t));
    
    data += sizeof(uint16_t);
    size -= sizeof(uint16_t);

    size_t doc1_size = split_len_raw % (size + 1);
    size_t doc2_size = size - doc1_size;

    const uint8_t *doc1_data = data;
    const uint8_t *doc2_data = data + doc1_size;

    // Allow relaxed parsing options to maximize Code Flow Graph (CFG) exploration
    yyjson_read_flag flag = YYJSON_READ_ALLOW_INVALID_UNICODE | YYJSON_READ_ALLOW_COMMENTS;

    yyjson_doc *base_doc = yyjson_read_opts((char *)doc1_data, doc1_size, flag, NULL, NULL);
    yyjson_doc *patch_doc = yyjson_read_opts((char *)doc2_data, doc2_size, flag, NULL, NULL);

    // Test JSON Patch (RFC 6902) and JSON Merge Patch (RFC 7396) APIs
    if (base_doc && patch_doc) {
        yyjson_mut_doc *patched_mut_doc = yyjson_patch(base_doc, patch_doc, NULL);
        if (patched_mut_doc) {
            yyjson_mut_doc_free(patched_mut_doc);
        }

        yyjson_mut_doc *merged_mut_doc = yyjson_merge_patch(base_doc, patch_doc, NULL);
        if (merged_mut_doc) {
            yyjson_mut_doc_free(merged_mut_doc);
        }

        yyjson_mut_doc *base_mut = yyjson_doc_mut_copy(base_doc, NULL);
        if (base_mut) {
            yyjson_mut_merge_patch(base_mut, patch_doc, NULL);
            yyjson_mut_doc_free(base_mut);
        }
        
        yyjson_mut_doc *base_mut2 = yyjson_doc_mut_copy(base_doc, NULL);
        if (base_mut2) {
            yyjson_mut_patch(base_mut2, patch_doc, NULL);
            yyjson_mut_doc_free(base_mut2);
        }
    }

    // Test JSON Pointer (RFC 6901) parsing and traversal
    if (base_doc && doc2_size > 0) {
        yyjson_val *ptr_result = yyjson_ptr_getn(yyjson_doc_get_root(base_doc), (const char *)doc2_data, doc2_size);
        (void)ptr_result;
    }

    if (base_doc) yyjson_doc_free(base_doc);
    if (patch_doc) yyjson_doc_free(patch_doc);

    return 0;
}
