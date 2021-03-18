#include "api_http.h"
#include "ubirch_ed25519.h"

#include <curl/curl.h>

#include "util.h"

extern unsigned char server_pub_key[crypto_sign_PUBLICKEYBYTES];

static int ed25519_backend_response_verifier(const unsigned char *data,
        size_t len, const unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]) {
    return ed25519_verify_key(data, len, signature, server_pub_key);
}

typedef struct {
    msgpack_unpacker* unpacker;
    bool verified;
} response_callback_context_t;

static size_t response_callback(void *data, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    response_callback_context_t* ctx = userp;
    DEBUGHEXDUMP("Received response data:", (unsigned char*)data, realsize);
    DEBUGHEXDUMP("Backend public key:", (unsigned char*)server_pub_key,
            UBIRCH_CLIENT_CONFIG_SERVER_KEY_LENGTH);
    /* verify data */
    if (ubirch_protocol_verify(data, realsize,
                ed25519_backend_response_verifier) == 0) {
        ctx->verified = true;
    }
    /* copy data */
    if (ctx->verified && ctx->unpacker != NULL) {
        msgpack_unpacker *unpacker = ctx->unpacker;

        if (msgpack_unpacker_buffer_capacity(unpacker) < realsize) {
            msgpack_unpacker_reserve_buffer(unpacker, (uint16_t)realsize);
        }
        memcpy(msgpack_unpacker_buffer(unpacker), data, (uint16_t)realsize);
        msgpack_unpacker_buffer_consumed(unpacker, (uint16_t)realsize);
    }
    return realsize;
}


int ubirch_send(const char* url, const unsigned char *data, const size_t len,
        long* http_status, msgpack_unpacker* unpacker) {
    unsigned int ii;
    DEBUGHEXDUMP("Sending UPP:", data, len);

    CURL *curl;
    CURLcode res;

    /* get a curl handle */
    curl = curl_easy_init();

    /* prepare memory for response */
    response_callback_context_t response_context = {
        .unpacker = unpacker,
        .verified = false
    };

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response_context);

        struct curl_slist* hs = NULL;
        hs = curl_slist_append(hs,
                "Content-Type: application/octet-stream");

        // set uuid
        // FIXME: adjust size, remove magic numbers
        char uuid_line[128];
        snprintf(uuid_line, 23, "X-Ubirch-Hardware-Id: ");
        config_get_uuid_string(uuid_line + 22, 128 - 22);
        //printf("%s\n", uuid_line);
        hs = curl_slist_append(hs, uuid_line);

        // set auth token
        // FIXME: adjust size, remove magic numbers
        char auth_token_line[128];
        snprintf(auth_token_line, 22, "X-Ubirch-Credential: ");
        config_get_auth_string(auth_token_line + 21, 128 - 21);
        //printf("%s\n", auth_token_line);
        hs = curl_slist_append(hs, auth_token_line);

        hs = curl_slist_append(hs, "X-Ubirch-Auth-Type: ubirch");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);

        // set data field
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_status);

        /* Check for errors */
        if(res != CURLE_OK) {
            printf("curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    if (response_context.verified || unpacker == NULL) {
        return UBIRCH_SEND_OK;
    } else {
        return UBIRCH_SEND_VERIFICATION_FAILED;
    }
}


int ubirch_parse_backend_response(msgpack_unpacker *unpacker,
        ubirch_protocol* previous_upp, ubirch_response_bin_data_handler handler) {
    // new unpacked result buffer
    msgpack_unpacked result;
    msgpack_unpacked_init(&result);

    int return_value = 0;

    // unpack into result buffer and look for ARRAY
    if (msgpack_unpacker_next(unpacker, &result) == MSGPACK_UNPACK_SUCCESS
            && result.data.type == MSGPACK_OBJECT_ARRAY) {
        // redirect the result to the envelope
        msgpack_object *envelope = result.data.via.array.ptr;
        unsigned int p_version = 0;
        // get the envelope version
        if (envelope->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            p_version = (int) envelope->via.u64;
            //printf("VERSION: %d (variant %d)\n", p_version >> 4U, p_version & 0xfU);
        }
        // get the backend UUID
        if ((++envelope)->type == MSGPACK_OBJECT_BIN) {
            DEBUGHEXDUMP("backend UUID:", (unsigned char*)envelope->via.str.ptr,
                    envelope->via.str.size);
        }
        //printf("uuid type: %d\n", (unsigned int) envelope->type);
        // only continue if the envelope version and variant match
        if (p_version == proto_chained) {
            // previous message signature (from our request message)
            unsigned char* last_signature = previous_upp->data +
                (previous_upp->size - UBIRCH_PROTOCOL_SIGN_SIZE);
            bool last_signature_matches = false;

            size_t last_signature_len = 0;
            if ((++envelope)->type == MSGPACK_OBJECT_BIN) {
                if (envelope->via.str.size == crypto_sign_BYTES) {
                    last_signature_matches = memcmp(last_signature,
                            envelope->via.str.ptr, UBIRCH_PROTOCOL_SIGN_SIZE) == 0;
                }
            }
            // compare the previous signature to the received one
            // only continue, if the signatures match
            if (last_signature_matches && (++envelope)->type
                    == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                //printf("TYPE: %d\n", (unsigned int) envelope->via.u64);
                if (envelope->via.u64 == UBIRCH_PROTOCOL_TYPE_BIN) {
                    if ((unsigned int) (++envelope)->type == MSGPACK_OBJECT_BIN) {
                        if (handler) {
                            handler(envelope->via.str.ptr, envelope->via.str.size);
                        }
                    } else {
                        printf("unexpected packet data type\n");
                        return_value = -1;
                    }
                } else {
                    return_value = -1;
                    printf("message type wrong!\n");
                }
            } else {
                return_value = -1;
                printf("prev signature mismatch or message type wrong!\n");
            }
        } else {
            return_value = -1;
            printf("protocol version mismatch: %d != %d\n", p_version,
                    proto_chained);
        }
    } else {
        return_value = -1;
        printf("empty or broken message not accepted\n");
    }
    msgpack_unpacked_destroy(&result);
    return return_value;
}
