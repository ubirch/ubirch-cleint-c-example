#include "storage.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.h"

#include <openssl/evp.h>

/* Configuration struct which is stored into a file in binary format */
static configuration_t configuration = { 0 };

configuration_t* get_config(void) {
    return &configuration;
}

static int encode_base64(const unsigned char* input, int length,
        char* outputbuffer, size_t outputbuffer_size) {
    size_t pl = 4*((length+2)/3);
    if (pl > outputbuffer_size) {
        return -1;
    }
    size_t ol = EVP_EncodeBlock(outputbuffer, input, length);
    if (pl != ol) {
        return -1;
    }
    return 0;
}

static int decode_base64(const char *input, const int length,
        unsigned char* outputbuffer, const size_t outputbuffer_size) {
    size_t pl = 3*length/4;
    // we need a temporary buffer because the EVP_DecodeBlock function padds
    // with zeros up to a multiple of 3
    unsigned char tmpbuffer[66];
    if (pl > sizeof(tmpbuffer)) {
        return -1;
    }
    size_t ol = EVP_DecodeBlock(tmpbuffer, input, length);
    if (pl != ol) {
        return -1;
    }
    memcpy(outputbuffer, tmpbuffer, outputbuffer_size);
    return 0;
}

static int write_data_to_file(const char* filename, const unsigned char* data,
        const size_t len) {
    int filehandle = open (filename, O_RDWR | O_CREAT, 0600);

    if (filehandle == -1) {
        close(filehandle);
        return -1;
    }
    if (write(filehandle, data, len) < 0) {
        close(filehandle);
        return -1;
    }
    close(filehandle);
    return 0;
}

int read_data_from_file(const char* filename, unsigned char* buffer,
        const size_t buffer_size) {
    int filehandle = open (filename, O_RDONLY);
    if (filehandle == -1) {
        close(filehandle);
        return -1;
    }
    if (read(filehandle, buffer, buffer_size) < 0) {
        close(filehandle);
        return -1;
    }
    close(filehandle);
    return 0;
}

void set_previous_signature(const ubirch_protocol* upp) {
    write_data_to_file(UBIRCH_CLIENT_PREVIOUS_SIGNATURE_FILE,
            upp->data + (upp->size - UBIRCH_PROTOCOL_SIGN_SIZE),
            UBIRCH_PROTOCOL_SIGN_SIZE);
}

void get_previous_signature(unsigned char* sig) {
    if (read_data_from_file(UBIRCH_CLIENT_PREVIOUS_SIGNATURE_FILE, sig,
                UBIRCH_PROTOCOL_SIGN_SIZE) != 0) {
        // file does not exist, so set default value
        memset(sig, 0, UBIRCH_PROTOCOL_SIGN_SIZE);
    }
}

int load_config(void) {
    return read_data_from_file(UBIRCH_CLIENT_CONFIG_FILE,
            configuration.buffer, UBIRCH_CLIENT_CONFIGURATION_SIZE);
}

int store_config(void) {
    if (write_data_to_file(UBIRCH_CLIENT_CONFIG_FILE, configuration.buffer,
                UBIRCH_CLIENT_CONFIGURATION_SIZE) != 0) {
        return -1;
    }
    return 0;
}

static int config_set_hex_format(const char* hex_string, unsigned char* buffer,
        size_t buffer_size) {
    // parse hex string AAAAAAAAAAHH!
    //"01234567-89ab-cdef-0123-456789abcdef"
    int len = strlen(hex_string);
    if (len != 36) {
        return -1;
    }
    unsigned int count = 0;
    unsigned int index = 0;
    while (count < 36 && index < buffer_size) {
        if (hex_string[count] == '-') {
            count++;
            continue;
        }
        char byte[3];
        strncpy(byte, hex_string + count, 2);
        byte[2] = '\0';
        buffer[index] = strtol(byte, NULL, 16);
        count = count + 2;
        index++;
    }
    return 0;
}

int config_set_uuid(const char* uuid_string) {
    configuration.uuid_bit = 1;
    return config_set_hex_format(uuid_string, configuration.uuid,
            UBIRCH_CLIENT_CONFIG_UUID_LENGTH);
}

int config_get_uuid_string(char* buffer, size_t size) {
    char format_string[] = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x";
    if (size < sizeof(format_string) + 1) {
        return -1;
    }
    if (configuration.uuid_bit == 1) {
        unsigned char* uuid = configuration.uuid;
        sprintf(buffer, format_string,
                uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5],
                uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11],
                uuid[12], uuid[13], uuid[14], uuid[15]);
    } else {
        return -1;
    }
    return 0;
}

int config_set_private_key(const char* private_key_string) {
    configuration.private_key_bit = 1;
    return decode_base64(private_key_string, strlen(private_key_string),
            configuration.private_key, UBIRCH_CLIENT_CONFIG_PRIVATE_KEY_LENGTH);
}

int config_set_public_key(const char* public_key_string) {
    configuration.public_key_bit = 1;
    return decode_base64(public_key_string, strlen(public_key_string),
            configuration.public_key, UBIRCH_CLIENT_CONFIG_PUBLIC_KEY_LENGTH);
}

int config_set_server_key(const char* server_key_string) {
    configuration.server_key_bit = 1;
    return decode_base64(server_key_string, strlen(server_key_string),
            configuration.server_key, UBIRCH_CLIENT_CONFIG_SERVER_KEY_LENGTH);
}

int config_set_auth_token(const char* auth_token_string) {
    configuration.auth_token_bit = 1;
    // note: store string! It looks like a uuid, but is actually just a string
    memcpy(configuration.auth_token, auth_token_string,
            UBIRCH_CLIENT_CONFIG_AUTH_TOKEN_LENGTH);
    return 0;
}

int config_get_auth_string(char* buffer, size_t size) {
    if (size < 100) { // FIXME
        return -1;
    }
    if (configuration.auth_token_bit == 1) {
        if (encode_base64(configuration.auth_token,
                    UBIRCH_CLIENT_CONFIG_AUTH_TOKEN_LENGTH,
                    buffer, size) != 0) {
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

static void print_config_uuid(void) {
    printf("UUID: ");
    if (configuration.uuid_bit == 1) {
        //char uuidstringbuffer[38];
        char uuidstringbuffer[128];
        if (config_get_uuid_string(uuidstringbuffer, sizeof(uuidstringbuffer))
                == 0) {
            printf("%s\n", uuidstringbuffer);
        } else {
            printf("error printing uuid\n");
        }
    } else {
        printf("value not set\n");
    }
}

static void print_config_authtoken(void) {
    printf("auth token: ");
    if (configuration.auth_token_bit == 1) {
        char buffer[UBIRCH_CLIENT_CONFIG_AUTH_TOKEN_LENGTH + 1];
        memcpy(buffer, configuration.auth_token,
                UBIRCH_CLIENT_CONFIG_AUTH_TOKEN_LENGTH);
        buffer[UBIRCH_CLIENT_CONFIG_AUTH_TOKEN_LENGTH] = '\0';
        printf("%s\n", buffer);
    } else {
        printf("value not set\n");
    }
}

static void print_config_value_base64(const char* name, unsigned char* buffer,
        unsigned char config_bit, size_t size) {
    printf("%s: ", name);
    if (config_bit == 1) {
        char outbuffer[128];
        if (encode_base64(buffer, size, outbuffer, sizeof(outbuffer)) == 0) {
            printf("%s", outbuffer);
        } else {
            printf("could not be decoded");
        }
    } else {
        printf("value not set");
    }
    printf("\n");
}

void print_config(void) {
    // convert configuration values into readable data
    printf("== configuration ==\n");
    print_config_uuid();
    print_config_value_base64("public key", configuration.public_key,
            configuration.public_key_bit,
            UBIRCH_CLIENT_CONFIG_PUBLIC_KEY_LENGTH);
    print_config_value_base64("server key", configuration.server_key,
            configuration.server_key_bit,
            UBIRCH_CLIENT_CONFIG_SERVER_KEY_LENGTH);
    print_config_authtoken();
}

void print_previous_signature(void) {
    printf("== last successfully anchored signature ==\n");
    unsigned char buffer[UBIRCH_PROTOCOL_SIGN_SIZE];
    if (read_data_from_file(UBIRCH_CLIENT_PREVIOUS_SIGNATURE_FILE, buffer,
                UBIRCH_PROTOCOL_SIGN_SIZE) == 0) {
        HEXDUMP("", buffer, UBIRCH_PROTOCOL_SIGN_SIZE);
        printf("\n");
    } else {
        printf("None");
    }
}
