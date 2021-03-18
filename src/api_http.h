#ifndef __UBIRCH_CLIENT_API_HTTP_H__
#define __UBIRCH_CLIENT_API_HTTP_H__

#include "ubirch_protocol.h"
#include <msgpack.h>
#include "storage.h"

/*
 * Send data to the ubirch backend.
 * @param url The backend url.
 * @param data The msgpack encoded data to send.
 * @param len The length of the data packet.
 * @param http_status The http status of the backend response.
 * @param unpacker The msgpack unpacker to feed the response to or NULL in case
 *        you don't expect an answer or you are not interested in it.
 *        Verification is only done if you provide an unpacker.
 * @return UBIRCH_SEND_OK
 *         UBIRCH_SEND_VERIFICATION_FAILED if unpacker is not NULL and verification failed
 *         UBIRCH_SEND_ERROR if any error occured
 */
#define UBIRCH_SEND_OK (0)
#define UBIRCH_SEND_VERIFICATION_FAILED (1)
#define UBIRCH_SEND_ERROR (2)
int ubirch_send(const char* url, const unsigned char *data, const size_t len,
        long* http_status, msgpack_unpacker* unpacker);

/*
 * Callback type for ubirch_parse_backend_response. To be called on binary data.
 *
 * @param data A pointer to the data.
 * @param len Size of data.
 */
typedef void (*ubirch_response_bin_data_handler)(const void* data, const size_t len);

/*
 * Parse a msgpack response that contains a ubirch-protocol message.
 * The function expects
 *      1. proto_chained type
 *      2. matching previous signature with signature of previous UPP
 *      3. payload of binary type UBIRCH_PROTOCOL_TYPE_BIN
 * otherwise it will not call the handler on this binary data.
 *
 * @param unpacker The unpacker holding unparsed data.
 * @param previous_upp A reference to the previous UPP.
 * @param handler A handler for the received payload.
 * @return UBIRCH_PARSE_BACKEND_RESPONSE_OK
 *         UBIRCH_PARSE_BACKEND_RESPONSE_ERROR if any error occured
 */
#define UBIRCH_PARSE_BACKEND_RESPONSE_OK (0)
#define UBIRCH_PARSE_BACKEND_RESPONSE_ERROR (-1)
int ubirch_parse_backend_response(msgpack_unpacker *unpacker, ubirch_protocol* previous_upp,
        ubirch_response_bin_data_handler handler);

#endif // __UBIRCH_CLIENT_API_HTTP_H__
