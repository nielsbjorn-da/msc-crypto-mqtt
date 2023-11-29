cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(
  ascon-provider
  VERSION 1.0
  DESCRIPTION "A demonstration of minimum required things for ascon cipher in an OpenSSL 3.0 module, including provider specific error reasons."
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)
add_compile_definitions(AUTHOR="@simon, @niels")

enable_testing()

add_subdirectory(libprov)
include(libprov/cmake/provider.cmake)
setup_provider_openssl()

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/a_params.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/a_params.h
                   COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/libprov/perl/gen_param_LL.pl
                           ${CMAKE_CURRENT_SOURCE_DIR}/a_params.c
                           ${CMAKE_CURRENT_SOURCE_DIR}/a_params.h
                           ${CMAKE_CURRENT_SOURCE_DIR}/ascon_params.dat
                   MAIN_DEPENDENCY ascon_params.dat
                   DEPENDS libprov/perl/gen_param_LL.pl)
include_directories(ascon80pq)
include_directories(ascon128)
include_directories(ascon128a)

set(ascon_source ascon.c a_params.c ascon80pq/printstate.c  ascon128/printstate.c ascon128a/printstate.c)
build_provider(asconprovider "${ascon_source}" libprov ascon80pq, ascon128, ascon128a)


# Testing
get_property(_is_multiconfig GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if (_is_multiconfig)
  set(ASCON_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>")
else()
  set(ASCON_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
unset(_is_multiconfig)
message(STATUS "Determined the build time Ascon provider location to be '${ASCON_MODULE_DIRECTORY}'")

set(TEST_ENVIRONMENT
  "OPENSSL_MODULES=${ASCON_MODULE_DIRECTORY}"
  "OPENSSL_PROGRAM=${OPENSSL_PROGRAM}"
  "OPENSSL_RUNTIME_DIR=${OPENSSL_RUNTIME_DIR}"
  "OPENSSL_LIBRARY_DIR=$<IF:$<BOOL:${WIN32}>,${OPENSSL_RUNTIME_DIR},${OPENSSL_LIBRARY_DIR}>"
  "SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}"
  "PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/t"
  )

add_library(test_common STATIC test_common.c)
target_include_directories(test_common PUBLIC ${OPENSSL_INCLUDE_DIR})

add_executable(test_ascon test_ascon.c)
target_link_libraries(test_ascon
  PRIVATE test_common OpenSSL::Crypto)
add_test(NAME ascon COMMAND test_ascon)
set_tests_properties(ascon PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

add_executable(test_ascon_err
  test_ascon_err.c)
if (MSVC)
  target_link_libraries(test_ascon_err
    PRIVATE test_common OpenSSL::Crypto OpenSSL::applink)
else ()
  target_link_libraries(test_ascon_err
    PRIVATE test_common OpenSSL::Crypto)
endif ()
add_test(NAME ascon_err COMMAND test_ascon_err)
set_tests_properties(ascon_err PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

if (WIN32)
  if (DEFINED OPENSSL_LIBCRYPTO_SHARED)
    cmake_path(GET OPENSSL_LIBCRYPTO_SHARED STEM OPENSSL_LIBCRYPTO_SHARED_NAME)
    add_custom_command(
      TARGET test_ascon POST_BUILD
      COMMAND cmake -E copy
        "${OPENSSL_LIBCRYPTO_SHARED}"
        "${ASCON_MODULE_DIRECTORY}/${OPENSSL_LIBCRYPTO_SHARED_NAME}.dll")
    add_custom_command(
      TARGET test_ascon_err POST_BUILD
      COMMAND cmake -E copy
        "${OPENSSL_LIBCRYPTO_SHARED}"
        "${ASCON_MODULE_DIRECTORY}/${OPENSSL_LIBCRYPTO_SHARED_NAME}.dll")
  endif()
endif()

# Test with OpenSSL, using TAP
if (MSVC)
  set(PROVE prove.bat)
else()
  set(PROVE prove)
endif()
add_test(NAME openssl
  COMMAND ${PROVE} -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/t)
set_tests_properties(openssl PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

# No installation instruction, as this should never be used in production
# If you still want to do so, just copy vigenere.so / vigenere.dll to an
# appropriate location.
