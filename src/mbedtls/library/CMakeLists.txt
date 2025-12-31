option(USE_STATIC_MBEDTLS_LIBRARY "Build Mbed TLS static library." ON)
option(USE_SHARED_MBEDTLS_LIBRARY "Build Mbed TLS shared library." OFF)
option(LINK_WITH_PTHREAD "Explicitly link Mbed TLS library to pthread." OFF)
option(LINK_WITH_TRUSTED_STORAGE "Explicitly link Mbed TLS library to trusted_storage." OFF)

# Set the project root directory if it's not already defined, as may happen if
# the library folder is included directly by a parent project, without
# including the top level CMakeLists.txt.
if(NOT DEFINED MBEDTLS_DIR)
    set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR})
endif()

set(src_crypto
    aes.c
    aesni.c
    aesce.c
    asn1parse.c
    asn1write.c
    base64.c
    bignum.c
    bignum_core.c
    block_cipher.c
    ccm.c
    chacha20.c
    chachapoly.c
    cipher.c
    cipher_wrap.c
    constant_time.c
    cmac.c
    ctr_drbg.c
    des.c
    ecdh.c
    ecdsa.c
    ecp.c
    ecp_curves.c
    entropy.c
    entropy_poll.c
    error.c
    gcm.c
    hkdf.c
    md.c
    md5.c
    oid.c
    pem.c
    pk.c
    pk_ecc.c
    pk_wrap.c
    pkcs12.c
    pkcs5.c
    pkparse.c
    pkwrite.c
    platform.c
    platform_util.c
    poly1305.c
    rsa.c
    rsa_alt_helpers.c
    sha1.c
    sha256.c
    sha512.c
    threading.c
    timing.c
    version.c
)

set(src_x509
    x509.c
    x509_create.c
    x509_crl.c
    x509_crt.c
    x509_csr.c
    x509write.c
    x509write_crt.c
    x509write_csr.c
)

set(src_tls
    net_sockets.c
    ssl_cache.c
    ssl_ciphersuites.c
    ssl_client.c
    ssl_cookie.c
    ssl_debug_helpers_generated.c
    ssl_msg.c
    ssl_ticket.c
    ssl_tls.c
    ssl_tls12_client.c
    ssl_tls12_server.c
)

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
endif(CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_MSVC)
    option(MSVC_STATIC_RUNTIME "Build the libraries with /MT compiler flag" OFF)
    if(MSVC_STATIC_RUNTIME)
        foreach(flag_var
            CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_C_FLAGS_CHECK)
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endforeach(flag_var)
    endif()
endif()

if(WIN32)
    set(libs ${libs} ws2_32 bcrypt)
endif(WIN32)

if(CMAKE_C_COMPILER_ID MATCHES "AppleClang")
    set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
    set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()

if(HAIKU)
    set(libs ${libs} network)
endif(HAIKU)

if(LINK_WITH_PTHREAD)
    set(libs ${libs} ${CMAKE_THREAD_LIBS_INIT})
endif()

if(LINK_WITH_TRUSTED_STORAGE)
    set(libs ${libs} trusted_storage)
endif()

if (NOT USE_STATIC_MBEDTLS_LIBRARY AND NOT USE_SHARED_MBEDTLS_LIBRARY)
    message(FATAL_ERROR "Need to choose static or shared mbedtls build!")
endif(NOT USE_STATIC_MBEDTLS_LIBRARY AND NOT USE_SHARED_MBEDTLS_LIBRARY)

set(mbedtls_target    "${MBEDTLS_TARGET_PREFIX}mbedtls")
set(mbedx509_target   "${MBEDTLS_TARGET_PREFIX}mbedx509")
set(mbedcrypto_target "${MBEDTLS_TARGET_PREFIX}mbedcrypto")

set(mbedtls_target    ${mbedtls_target}    PARENT_SCOPE)
set(mbedx509_target   ${mbedx509_target}   PARENT_SCOPE)
set(mbedcrypto_target ${mbedcrypto_target} PARENT_SCOPE)

if (USE_STATIC_MBEDTLS_LIBRARY)
    set(mbedtls_static_target    ${mbedtls_target})
    set(mbedx509_static_target   ${mbedx509_target})
    set(mbedcrypto_static_target ${mbedcrypto_target})
endif()

set(target_libraries ${mbedcrypto_target} ${mbedx509_target} ${mbedtls_target})

if(USE_STATIC_MBEDTLS_LIBRARY AND USE_SHARED_MBEDTLS_LIBRARY)
    string(APPEND mbedtls_static_target    "_static")
    string(APPEND mbedx509_static_target   "_static")
    string(APPEND mbedcrypto_static_target "_static")

    list(APPEND target_libraries
        ${mbedcrypto_static_target}
        ${mbedx509_static_target}
        ${mbedtls_static_target})
endif()

if(USE_STATIC_MBEDTLS_LIBRARY)
    add_library(${mbedcrypto_static_target} STATIC ${src_crypto})
    set_target_properties(${mbedcrypto_static_target} PROPERTIES OUTPUT_NAME mbedcrypto)
    target_link_libraries(${mbedcrypto_static_target} PUBLIC ${libs})

    add_library(${mbedx509_static_target} STATIC ${src_x509})
    set_target_properties(${mbedx509_static_target} PROPERTIES OUTPUT_NAME mbedx509)
    target_link_libraries(${mbedx509_static_target} PUBLIC ${libs} ${mbedcrypto_static_target})

    add_library(${mbedtls_static_target} STATIC ${src_tls})
    set_target_properties(${mbedtls_static_target} PROPERTIES OUTPUT_NAME mbedtls)
    target_link_libraries(${mbedtls_static_target} PUBLIC ${libs} ${mbedx509_static_target})

    if(GEN_FILES)
        add_dependencies(${mbedcrypto_static_target}
            ${MBEDTLS_TARGET_PREFIX}mbedcrypto_generated_files_target)
        add_dependencies(${mbedtls_static_target}
            ${MBEDTLS_TARGET_PREFIX}mbedtls_generated_files_target)
    endif()
endif(USE_STATIC_MBEDTLS_LIBRARY)

if(USE_SHARED_MBEDTLS_LIBRARY)
    set(CMAKE_LIBRARY_PATH ${CMAKE_CURRENT_BINARY_DIR})
    add_library(${mbedcrypto_target} SHARED ${src_crypto})
    set_target_properties(${mbedcrypto_target} PROPERTIES VERSION 3.6.5 SOVERSION 16)
    target_link_libraries(${mbedcrypto_target} PUBLIC ${libs})

    add_library(${mbedx509_target} SHARED ${src_x509})
    set_target_properties(${mbedx509_target} PROPERTIES VERSION 3.6.5 SOVERSION 7)
    target_link_libraries(${mbedx509_target} PUBLIC ${libs} ${mbedcrypto_target})

    add_library(${mbedtls_target} SHARED ${src_tls})
    set_target_properties(${mbedtls_target} PROPERTIES VERSION 3.6.5 SOVERSION 21)
    target_link_libraries(${mbedtls_target} PUBLIC ${libs} ${mbedx509_target})

    if(GEN_FILES)
        add_dependencies(${mbedcrypto_target}
            ${MBEDTLS_TARGET_PREFIX}mbedcrypto_generated_files_target)
        add_dependencies(${mbedtls_target}
            ${MBEDTLS_TARGET_PREFIX}mbedtls_generated_files_target)
    endif()
endif(USE_SHARED_MBEDTLS_LIBRARY)

foreach(target IN LISTS target_libraries)
    add_library(MbedTLS::${target} ALIAS ${target})  # add_subdirectory support
    # Include public header files from /include and other directories
    # declared by /3rdparty/**/CMakeLists.txt. Include private header files
    # from /library and others declared by /3rdparty/**/CMakeLists.txt.
    # /library needs to be listed explicitly when building .c files outside
    # of /library (which currently means: under /3rdparty).
    target_include_directories(${target}
        PUBLIC $<BUILD_INTERFACE:${MBEDTLS_DIR}/include/>
               $<INSTALL_INTERFACE:include/>
        PRIVATE ${MBEDTLS_DIR}/library/
                # Needed to include psa_crypto_driver_wrappers.h
                ${CMAKE_CURRENT_BINARY_DIR})
    # Pass-through MBEDTLS_CONFIG_FILE and MBEDTLS_USER_CONFIG_FILE
    if(MBEDTLS_CONFIG_FILE)
        target_compile_definitions(${target}
            PUBLIC MBEDTLS_CONFIG_FILE="${MBEDTLS_CONFIG_FILE}")
    endif()
    if(MBEDTLS_USER_CONFIG_FILE)
        target_compile_definitions(${target}
            PUBLIC MBEDTLS_USER_CONFIG_FILE="${MBEDTLS_USER_CONFIG_FILE}")
    endif()
    install(
        TARGETS ${target}
        EXPORT MbedTLSTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endforeach(target)

set(lib_target "${MBEDTLS_TARGET_PREFIX}lib")

add_custom_target(${lib_target} DEPENDS ${mbedcrypto_target} ${mbedx509_target} ${mbedtls_target})
if(USE_STATIC_MBEDTLS_LIBRARY AND USE_SHARED_MBEDTLS_LIBRARY)
    add_dependencies(${lib_target} ${mbedcrypto_static_target} ${mbedx509_static_target} ${mbedtls_static_target})
endif()
