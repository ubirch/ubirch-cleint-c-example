# ubirch-client-c-example

This is a minimal example implementation of a ubirch client in C.
It demonstrates how to use the [ubirch-protocol](https://github.com/ubirch/ubirch-protocol)
to anchor hashes of arbitrary files.

## usage of the client

Type `ubirch-client help` to get this help.
```txt
Usage:
    ubirch-client [subcommand] <subsubcommand/value> <value>

    subcommands:
        help                                  Get this help text.
        info                                  Get configuration information.

        config <subsubcommand> <value>        Set configuration values:
            uuid <hex uuid>                   Set uuid in hex-uuid-format.

            privatekey <base64 private key>   Set private key in base64 format,
            publickey <base64 public key>     set public key in base64 format,
                                              consider using generatekeys subcommand.

            authtoken <string auth token>     Set auth token as string.

            serverkey <base64 public key>     Set backend public key in base64 format.

        generatekeys                          Generate key pair.
        register                              Register your public key in the backend.

        send <file>                           Send sha512sum of <file> to backend.
```

If you want to delete the last signature which was anchored successfully
just remove the `previous_signature.bin` file.

> ⚠ Note that the configuration is stored in `.ubirch_config.bin` in binary format.
> So it might not be possible to reuse the config file on different platforms.

> ⚠ Note that `.ubirch_config.bin` and `previous_signature.bin` are stored where you run the command.

## example usage

1. Generate a new **uuid** (e.g. with `uuidgen`). Log into the [ubirch console](https://console.prod.ubirch.com/home) and add a new "Thing" with the **uuid**.
2. Get the password string (aka **authtoken**) from "ThingsSettings" -> apiConfig -> *password*.
3. Configure your client:
    * Set **uuid**: `ubirch-client config 01234567-89ab-cdef-0123-456789abcdef` (replace with your **uuid**).
    * Set **authtoken**: `ubirch-client config fedcba98-7654-3210-fedc-ba9876543210` (replace with your **authtoken**).
    * Generate new key pair: `ubirch-client generatekeys`.
4. Register the keys: `ubirch-client register`. You should now be able to
   find your public key (type `ubirch-client info` to get it) in ubirch console -> Things -> PublicKeys.
5. Anchor the hash of a file of your choise: `ubirch-client send my_file.xyz`.
   If everything everything went ok, the client will let you know.
   Further it will return the **sha512 checksum of your file** in hex format.
   (You can also get the **sha512 checksum of your file** with e.g. `sha512sum <your file>`)
6. To verify that the hash was anchored convert the **sha512 checksum of your file** in base64 format
   (e.g. `echo <sha512 checksum of your file> | xxd -r -p | base64 -w 100`)
   and paste it into the ubirch console -> Verification.


## build

To build the project you need the development files for libcurl and OpenSSL.

```bash
git clone https://github.com/ubirch/ubirch-client-c-example --recursive
cd ubirch-client-c-example
mkdir build && cd build
cmake ..
make
```

If you want to bind the client to the backend in demo or dev stage,
run `cmake` with `-DBACKEND=demo` or `-DBACKEND=dev`.  By default prod stage is used.
