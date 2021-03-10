#ifndef __UBIRCH_CLIENT_API_HTTP_H__
#define __UBIRCH_CLIENT_API_HTTP_H__

#include "ubirch_protocol.h"
#include <msgpack.h>
#include "storage.h"

int ubirch_message(ubirch_protocol* upp, char* data, size_t length);

#define UBIRCH_SEND_OK (0)
#define UBIRCH_SEND_VERIFICATION_FAILED (1)
#define UBIRCH_SEND_ERROR (2)
int ubirch_send(const char* url, const configuration_t* config, const unsigned char *data,
        const size_t len, int* http_status, msgpack_unpacker* unpacker);

typedef void (*ubirch_response_bin_data_handler)(const void* data, const size_t len);
int ubirch_parse_backend_response(msgpack_unpacker *unpacker, ubirch_protocol* previous_upp,
        ubirch_response_bin_data_handler handler);

#endif // __UBIRCH_CLIENT_API_HTTP_H__
