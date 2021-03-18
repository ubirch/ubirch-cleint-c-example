#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <randombytes.h>

#include "ubirch_protocol.h"
#include "ubirch_protocol_kex.h"
#include "ubirch_ed25519.h"
#include <msgpack.h>

#include <curl/curl.h>

#include "storage.h"
#include "api_http.h"
#include "util.h"

#define UBIRCH_CLIENT_NAME "ubirch-client"

#if defined(UBIRCH_CLIENT_USE_BACKEND_PROD)
    #pragma message "Use prod backend."
#elif defined(UBIRCH_CLIENT_USE_BACKEND_DEV)
    #pragma message "Use dev backend."
#elif defined(UBIRCH_CLIENT_USE_BACKEND_DEMO)
    #pragma message "Use demo backend."
#elif defined(UBIRCH_CLIENT_USE_BACKEND_TEST)
    #pragma message "Use test backend."
#else
    #error "No backend specified."
#endif

unsigned char ed25519_secret_key[crypto_sign_SECRETKEYBYTES];
unsigned char ed25519_public_key[crypto_sign_PUBLICKEYBYTES];
unsigned char server_pub_key[crypto_sign_PUBLICKEYBYTES];

void print_help(void) {
    printf("Usage:\n\n"
           "    %s [subcommand] <subsubcommand/value> <value>\n\n"
           "    subcommands:\n"
           "        help                                  Get this help text.\n"
           "        info                                  Get configuration information.\n\n"
           "        config <subsubcommand> <value>        Set configuration values:\n"
           "            uuid <hex uuid>                   Set uuid in hex-uuid-format.\n\n"
           "            privatekey <base64 private key>   Set private key in base64 format,\n"
           "            publickey <base64 public key>     set public key in base64 format,\n"
           "                                              consider using generatekeys subcommand.\n\n"
           "            authtoken <string auth token>     Set auth token as string.\n\n"
           "            serverkey <base64 public key>     Set backend public key in base64 format.\n\n"
           "        generatekeys                          Generate key pair and write it to the configuration.\n"
           "        register                              Register your public key in the backend.\n\n"
           "        send <file>                           Send sha512sum of <file> to backend.\n",
           UBIRCH_CLIENT_NAME);
}

int main(int argc, char* argv[]) {
    if (argc == 2 && strcmp(argv[1], "help") == 0) {
        /* help */
        print_help();
        exit(0);
    } else if (argc == 1) {
        /* wrong usage */
        printf("Wrong usage. Get usage hints: %s help\n", UBIRCH_CLIENT_NAME);
        exit(-1);
    } else if (argc >= 2 && strcmp(argv[1], "config") == 0) {
        /* set configuration values */
        load_config();
        if (argc == 4 && strcmp(argv[2], "uuid") == 0) {
            if (config_set_uuid(argv[3]) != 0) {
                printf("could not set uuid\n");
                exit(-1);
            }
        } else if (argc == 4 && strcmp(argv[2], "authtoken") == 0) {
            if (config_set_auth_token(argv[3]) != 0) {
                printf("could not set auth token\n");
                exit(-1);
            }
        } else if (argc == 4 && strcmp(argv[2], "privatekey") == 0) {
            if (config_set_private_key(argv[3]) != 0) {
                printf("could not set private key\n");
                exit(-1);
            }
        } else if (argc == 4 && strcmp(argv[2], "publickey") == 0) {
            if (config_set_public_key(argv[3]) != 0) {
                printf("could not set public key\n");
                exit(-1);
            }
        } else if (argc == 4 && strcmp(argv[2], "serverkey") == 0) {
            if (config_set_server_key(argv[3]) != 0) {
                printf("could not set server key\n");
                exit(-1);
            }
        } else {
            printf("Wrong usage. Get usage hints: %s help\n", UBIRCH_CLIENT_NAME);
            exit(-1);
        }

        /* write configuration to config file */
        if (store_config() != 0) {
            printf("Error storing configuration to file.\n");
            exit(-1);
        }
        printf("OK\n");
        exit(0);
    } else if (argc == 2 && strcmp(argv[1], "generatekeys") == 0) {
        /* generate new keypair and write it to config file */
        configuration_t* config = get_config();
        crypto_sign_keypair(config->public_key, config->private_key);
        config->public_key_bit = 1;
        config->private_key_bit = 1;
        if (store_config() != 0) {
            printf("Error storing keys to configuration file.\n");
            exit(-1);
        }
        printf("OK\n");
        exit(0);
    }

    /* load configuration from file
     * from this point a valid configuration is required */
    if (load_config() != 0) {
        printf("No configuration present or error loading %s.\n",
                UBIRCH_CLIENT_CONFIG_FILE);
        exit(-1);
    }

    if (argc == 2 && strcmp(argv[1], "info") == 0) {
        /* print out some usefull information */
        printf("== ubirch-client ==\n");
        printf("backend data url: %s\n", CONFIG_UBIRCH_BACKEND_DATA_URL);
        printf("backend key server url: %s\n\n", CONFIG_UBIRCH_BACKEND_KEY_SERVER_URL);
        print_config();
        printf("\n");
        print_previous_signature();
        printf("\n");
        exit(0);
    } else if ((argc == 3 && strcmp(argv[1], "send") == 0)
            || (argc == 2 && strcmp(argv[1], "register") == 0)) {
        /* register your keys or send hash of given file path */

        /* get configuration struct pointer and check if keys are configured */
        configuration_t* config = get_config();
        if (config->public_key_bit == 0 || config->private_key_bit == 0) {
            printf("No key configured.\n");
            exit(-1);
        }

        /* write keys to global arrays as needed by ubirch_protocol-library */
        memcpy(ed25519_secret_key, config->private_key, crypto_sign_SECRETKEYBYTES);
        memcpy(ed25519_public_key, config->public_key, crypto_sign_PUBLICKEYBYTES);
        memcpy(server_pub_key, config->server_key, crypto_sign_PUBLICKEYBYTES);

        /* init UPP */
        ubirch_protocol* upp = ubirch_protocol_new(config->uuid, ed25519_sign);
        msgpack_unpacker* unpacker = NULL;

        bool parse_response_upp = false;

        char url[128]; // FIXME: let preproc specify size!

        if (strcmp(argv[1], "send") == 0) {
            /* calculate sha512sum of file */
            unsigned char sha512sum[64];

            FILE* fileptr = fopen (argv[2], "r");
            if (!fileptr) {
                printf("Unable to open file for hashing.");
                exit(-1);
            }
            mbedtls_sha512_context ctx;
            mbedtls_sha512_init(&ctx);
            mbedtls_sha512_starts(&ctx, 0);
            int c; // int, not char, to handle EOF
            while ((c = fgetc(fileptr)) != EOF) {
                unsigned char val = c;
                mbedtls_sha512_update(&ctx, &val, 1);
            }
            mbedtls_sha512_finish(&ctx, sha512sum);
            if (ferror(fileptr) || !feof(fileptr)) {
                printf("ERROR reading file\n");
            }
            fclose(fileptr);

            printf("Sending sha512 of file\n");
            HEXDUMP("", sha512sum, 64);
            printf("  %s\n", argv[2]);

            /* restore previous signature and fill up UPP */
            get_previous_signature(upp->signature);
            ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN,
                    (const char*)sha512sum, UBIRCH_PROTOCOL_SIGN_SIZE);

            /* initialize unpacker as we expect a response */
            unpacker = msgpack_unpacker_new(128);

            /* set url */
            sprintf(url, CONFIG_UBIRCH_BACKEND_DATA_URL);

            /* we expect a UPP as response */
            parse_response_upp = true;
        } else if (argc == 2 && strcmp(argv[1], "register") == 0) {
            /* UPP with certificate */

            /*
             * FIXME: Don't use registration time! Better store time when key
             *        is written to config file.
             */
            ubirch_key_info info = {};
            info.algorithm = (char *) (UBIRCH_KEX_ALG_ECC_ED25519);
            info.created = (unsigned int) time(NULL);
            memcpy(info.hwDeviceId, config->uuid, UBIRCH_CLIENT_CONFIG_UUID_LENGTH);
            memcpy(info.pubKey, ed25519_public_key, sizeof(ed25519_public_key));
            info.validNotAfter = (unsigned int) (time(NULL) + 31536000);
            info.validNotBefore = (unsigned int) time(NULL);

            ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_REG,
                    (const char *) &info, sizeof(info));

            /* set url */
            sprintf(url, CONFIG_UBIRCH_BACKEND_KEY_SERVER_URL);
        }


        /* send data to backend */
        int http_status = -1;
        int return_value = -1;
        switch (ubirch_send(url, config, upp->data, upp->size, &http_status,
                    unpacker)) {
            case UBIRCH_SEND_OK:
                switch (http_status) {
                    case 200:
                        if (parse_response_upp) {
                            // as we don't do anything with the payload of the
                            // response we pass NULL instead of a callback to
                            // handle it
                            if (ubirch_parse_backend_response(unpacker, upp,
                                        NULL) == 0) {
                                // as we know the UPP was sent to the backend
                                // successfully, we store the UPP's signature
                                // for the next UPP
                                set_previous_signature(upp);
                                return_value = 0;
                            } else {
                                printf("something went wrong...\n");
                            }
                        } else {
                            return_value = 0;
                        }
                        break;
                    default:
                        printf("https status: %d, something went wrong...\n",
                                http_status);
                        break;
                }
                break;
            case UBIRCH_SEND_VERIFICATION_FAILED:
                printf("Response could not be verified...\n");
                break;
        }

        /* cleanup */
        ubirch_protocol_free(upp);
        if (strcmp(argv[1], "send") == 0) {
            msgpack_unpacker_free(unpacker);
        }

        if (return_value == 0) {
            printf("OK\n");
        }
        exit(return_value);
    } else {
        /* wrong usage */
        printf("Wrong usage. Get usage hints: %s help\n", UBIRCH_CLIENT_NAME);
        exit(-1);
    }
}
