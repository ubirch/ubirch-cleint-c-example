#ifndef __UBIRCH_CLIENT_STORAGE_H__
#define __UBIRCH_CLIENT_STORAGE_H__

#include <stddef.h>
#include <ubirch_protocol.h>

#define UBIRCH_CLIENT_CONFIG_FILE ".ubirch_config.bin"
#define UBIRCH_CLIENT_PREVIOUS_SIGNATURE_FILE "previous_signature.bin"

/*
 * backend addresses
 */
#if defined(UBIRCH_CLIENT_USE_BACKEND_PROD)
    #define CONFIG_UBIRCH_BACKEND_DATA_URL "https://niomon.prod.ubirch.com/"
    #define CONFIG_UBIRCH_BACKEND_KEY_SERVER_URL "https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack"
#elif defined(UBIRCH_CLIENT_USE_BACKEND_DEV)
    #define CONFIG_UBIRCH_BACKEND_DATA_URL "https://niomon.dev.ubirch.com/"
    #define CONFIG_UBIRCH_BACKEND_KEY_SERVER_URL "https://key.dev.ubirch.com/api/keyService/v1/pubkey/mpack"
#elif defined(UBIRCH_CLIENT_USE_BACKEND_DEMO)
    #define CONFIG_UBIRCH_BACKEND_DATA_URL "https://niomon.demo.ubirch.com/"
    #define CONFIG_UBIRCH_BACKEND_KEY_SERVER_URL "https://key.demo.ubirch.com/api/keyService/v1/pubkey/mpack"
#endif

/*
 * data lengths
 */
#define UBIRCH_CLIENT_CONFIG_UUID_LENGTH (16)
#define UBIRCH_CLIENT_CONFIG_PRIVATE_KEY_LENGTH (64)
#define UBIRCH_CLIENT_CONFIG_PUBLIC_KEY_LENGTH (32)
#define UBIRCH_CLIENT_CONFIG_SERVER_KEY_LENGTH (32)
#define UBIRCH_CLIENT_CONFIG_AUTH_TOKEN_LENGTH (36)
#define UBIRCH_CLIENT_CONFIG_HEAD_LENGTH (1)
#define UBIRCH_CLIENT_CONFIGURATION_SIZE ( \
    UBIRCH_CLIENT_CONFIG_HEAD_LENGTH \
    + UBIRCH_CLIENT_CONFIG_UUID_LENGTH \
    + UBIRCH_CLIENT_CONFIG_PRIVATE_KEY_LENGTH \
    + UBIRCH_CLIENT_CONFIG_PUBLIC_KEY_LENGTH \
    + UBIRCH_CLIENT_CONFIG_SERVER_KEY_LENGTH \
    + UBIRCH_CLIENT_CONFIG_AUTH_TOKEN_LENGTH)

/*
 * Configuration struct type
 */
typedef union {
    struct {
        union {
            struct {
                unsigned char version           :2;
                unsigned char uuid_bit          :1;
                unsigned char private_key_bit   :1;
                unsigned char public_key_bit    :1;
                unsigned char server_key_bit    :1;
                unsigned char auth_token_bit    :1;
                unsigned char __unused__        :1;
            };
            unsigned char config_head[UBIRCH_CLIENT_CONFIG_HEAD_LENGTH];
        };
        unsigned char uuid[UBIRCH_CLIENT_CONFIG_UUID_LENGTH];
        unsigned char private_key[UBIRCH_CLIENT_CONFIG_PRIVATE_KEY_LENGTH];
        unsigned char public_key[UBIRCH_CLIENT_CONFIG_PUBLIC_KEY_LENGTH];
        unsigned char server_key[UBIRCH_CLIENT_CONFIG_SERVER_KEY_LENGTH];
        char auth_token[UBIRCH_CLIENT_CONFIG_AUTH_TOKEN_LENGTH];
    };
    unsigned char buffer[UBIRCH_CLIENT_CONFIGURATION_SIZE];
} configuration_t;

/*
 * write signature to file
 *
 * @param ubirch_protocol* upp
 */
void set_previous_signature(const ubirch_protocol* upp);

/*
 * read previous signature from file or return default start signature
 */
void get_previous_signature(unsigned char* sig);

/*
 * load configuration struct from file
 */
int load_config(void);

/*
 * store configuration struct into file
 */
int store_config(void);

/*
 * returns pointer to static configuration struct
 */
configuration_t* get_config(void);

/*
 * print configuration in readable format
 */
void print_config(void);

/*
 * print previous signature in hex format
 */
void print_previous_signature(void);

/*
 * set uuid to configuration
 *
 * @param char* uuid_string (in hex format? TODO)
 */
int config_set_uuid(const char* uuid_string);

/*
 * get uuid as string
 *
 * @param char* buffer
 * @param size_t size
 */
int config_get_uuid_string(char* buffer, size_t size);

/*
 * set private key to configuration
 *
 * @param char* private_key (in base64 format)
 */
int config_set_private_key(const char* private_key);

/*
 * set public key to configuration
 *
 * @param char* public_key (in base64 format)
 */
int config_set_public_key(const char* public_key);

/*
 * get auth token as base64 string
 *
 * @param char* buffer
 * @param size_t size
 */
int config_get_auth_string(char* buffer, size_t size);

/*
 * set server key to configuration
 *
 * @param char* server_key (in base64 format)
 */
int config_set_server_key(const char* server_key);

/*
 * set auth token to configuration
 *
 * @param char* auth_token (in hex format? TODO)
 */
int config_set_auth_token(const char* auth_token_string);

#endif //__UBIRCH_CLIENT_STORAGE_H__
