cmake_minimum_required(VERSION 3.0)
project(ubirch-client)

set(BACKEND "prod" CACHE STRING "Backend stage to use.")
set(BACKENDVALUES "prod;demo;dev")
set_property(CACHE BACKEND PROPERTY STRINGS ${BACKENDVALUES})

if (${BACKEND} MATCHES "prod")
    add_definitions(-DUBIRCH_CLIENT_USE_BACKEND_PROD)
elseif (${BACKEND} MATCHES "demo")
    add_definitions(-DUBIRCH_CLIENT_USE_BACKEND_DEMO)
elseif (${BACKEND} MATCHES "dev")
    add_definitions(-DUBIRCH_CLIENT_USE_BACKEND_DEV)
else()
    message(FATAL_ERROR "Unknown backend stage.")
endif()

add_executable (ubirch-client
    src/storage.c
    src/api_http.c
    src/ubirch-client.c)

set(CURL_LIBRARY "-lcurl")
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})
target_link_libraries(ubirch-client ${CURL_LIBRARIES})

set(OpenSSL_LIBRARY "-lssl")
find_package(OpenSSL REQUIRED)
include_directories(${OpenSSL_INCLUDE_DIR})
target_link_libraries(ubirch-client ${OpenSSL_LIBRARIES})
target_link_libraries(ubirch-client "-lcrypto")

# include nacl implementations from ubirch
set(NACL_LIBRARY ubirch-mbed-nacl-cm0)
add_library(libnacl
    ${NACL_LIBRARY}/source/nacl/shared/bigint.c
    ${NACL_LIBRARY}/source/nacl/shared/consts.c
    ${NACL_LIBRARY}/source/nacl/shared/fe25519.c
    ${NACL_LIBRARY}/source/nacl/crypto_hash/sha512.c
    ${NACL_LIBRARY}/source/nacl/crypto_hashblocks/sha512.c
    ${NACL_LIBRARY}/source/nacl/crypto_sign/ed25519.c
    ${NACL_LIBRARY}/source/nacl/crypto_sign/ge25519.c
    ${NACL_LIBRARY}/source/nacl/crypto_sign/sc25519.c
    ${NACL_LIBRARY}/source/nacl/crypto_verify/verify.c
    ${NACL_LIBRARY}/source/randombytes/randombytes_gnu_linux.c)
target_include_directories(libnacl PUBLIC ${NACL_LIBRARY}/source/nacl ${NACL_LIBRARY}/source/randombytes)
target_link_libraries(ubirch-client libnacl)

# msgpack
set(MSGPACK_LIBRARY "msgpack-c")
add_library(libmsgpack
    ${MSGPACK_LIBRARY}/src/objectc.c
    ${MSGPACK_LIBRARY}/src/unpack.c
    ${MSGPACK_LIBRARY}/src/version.c
    ${MSGPACK_LIBRARY}/src/vrefbuffer.c
    ${MSGPACK_LIBRARY}/src/zone.c)
include_directories(${MSGPACK_LIBRARY}/include)
target_link_libraries(ubirch-client libmsgpack)


# include ubirch library
set(UBIRCH_LIBRARY "ubirch-protocol/ubirch")
add_library(libubirch
    ${UBIRCH_LIBRARY}/digest/sha512.c
    ${UBIRCH_LIBRARY}/ubirch_protocol.c
    ${UBIRCH_LIBRARY}/ubirch_protocol_kex.c)
include_directories(${UBIRCH_LIBRARY})
target_link_libraries(ubirch-client libubirch)
