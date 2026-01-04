cmake_minimum_required(VERSION 3.16)
project(sm9jni C)

set(CMAKE_C_STANDARD 11)

# ---------------------------
# GmSSL (v3.1.1)
# ---------------------------
# Pass -DGmSSL_ROOT=... to point to your GmSSL installation/build output.
# Expected layout (typical):
#   ${GmSSL_ROOT}/include/gmssl/sm9.h
#   ${GmSSL_ROOT}/lib/(gmssl.lib|libgmssl.a|gmssl.dll import lib ...)
set(GmSSL_ROOT "" CACHE PATH "GmSSL root directory (contains include/ and lib/)")

# Allow passing JAVA_HOME via -DJAVA_HOME=...
if(NOT DEFINED JAVA_HOME)
  set(JAVA_HOME $ENV{JAVA_HOME})
endif()

if(NOT JAVA_HOME)
  message(FATAL_ERROR "JAVA_HOME is not set. Pass -DJAVA_HOME=... or set environment variable JAVA_HOME")
endif()

message(STATUS "Using JAVA_HOME=${JAVA_HOME}")

set(JNI_INCLUDE_DIR "${JAVA_HOME}/include")
if (WIN32)
  set(JNI_MD_INCLUDE_DIR "${JAVA_HOME}/include/win32")
else()
  set(JNI_MD_INCLUDE_DIR "${JAVA_HOME}/include/linux")
endif()

include_directories(${JNI_INCLUDE_DIR} ${JNI_MD_INCLUDE_DIR})

if (NOT GmSSL_ROOT)
  message(FATAL_ERROR "GmSSL_ROOT is not set. Pass -DGmSSL_ROOT=... (must contain include/ and lib/)")
endif()

message(STATUS "Using GmSSL_ROOT=${GmSSL_ROOT}")

include_directories("${GmSSL_ROOT}/include")

if (WIN32)
  set(_LIB_HINT "${GmSSL_ROOT}/lib" "${GmSSL_ROOT}/bin" "${GmSSL_ROOT}")
else()
  set(_LIB_HINT "${GmSSL_ROOT}/lib" "${GmSSL_ROOT}")
endif()

# GmSSL is OpenSSL-compatible; depending on your build, you may have:
# - gmssl (single lib)
# - crypto/ssl split libs
find_library(GMSSL_LIB NAMES gmssl libgmssl PATHS ${_LIB_HINT} NO_DEFAULT_PATH)
find_library(CRYPTO_LIB NAMES crypto libcrypto PATHS ${_LIB_HINT} NO_DEFAULT_PATH)
find_library(SSL_LIB NAMES ssl libssl PATHS ${_LIB_HINT} NO_DEFAULT_PATH)

add_library(sm9jni SHARED sm9jni.c)

if (GMSSL_LIB)
  target_link_libraries(sm9jni PRIVATE ${GMSSL_LIB})
endif()
if (CRYPTO_LIB)
  target_link_libraries(sm9jni PRIVATE ${CRYPTO_LIB})
endif()
if (SSL_LIB)
  target_link_libraries(sm9jni PRIVATE ${SSL_LIB})
endif()

if (MSVC)
  target_compile_options(sm9jni PRIVATE /W3)
else()
  target_compile_options(sm9jni PRIVATE -Wall -Wextra)
endif()


