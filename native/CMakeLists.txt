cmake_minimum_required(VERSION 3.16)
project(session_manager_native LANGUAGES CXX)

# SDK 只编译自己的原生对象，libssh2 和 Mbed TLS 由宿主最后链接。
foreach(input LIBSSH2_OH_INCLUDE MBEDTLS_OH_INCLUDE)
  if(NOT IS_DIRECTORY "${${input}}")
    message(FATAL_ERROR "Missing verified HAR headers: ${input}")
  endif()
endforeach()
add_library(session_manager_core STATIC
  src/ftps_tls.cpp
  src/napi_init.cpp
  src/ohcrypto_probe.cpp
  src/ssh_napi.cpp
  src/ssh_probe.cpp
  src/ssh_session_manager.cpp)
set_target_properties(session_manager_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(session_manager_core PRIVATE cxx_std_17)
target_include_directories(session_manager_core PRIVATE
  ../library/include "${LIBSSH2_OH_INCLUDE}" "${MBEDTLS_OH_INCLUDE}")
target_compile_options(session_manager_core PRIVATE
  -Wall -Wextra -Werror -Wno-error=unused-command-line-argument
  -fstack-protector-strong "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=.")
