# 宿主引用注册入口时从静态库装入各协议的原生实现。
if(TARGET session-manager-sdk::core)
  return()
endif()
if(NOT OHOS_ARCH STREQUAL "arm64-v8a")
  message(FATAL_ERROR "session-manager-sdk requires arm64-v8a")
endif()
set(_session_archive "${CMAKE_CURRENT_LIST_DIR}/../libs/${OHOS_ARCH}/libsession_manager_core.a")
if(NOT EXISTS "${_session_archive}")
  message(FATAL_ERROR "Missing session-manager-sdk static library")
endif()
add_library(session-manager-sdk::core STATIC IMPORTED GLOBAL)
set_target_properties(session-manager-sdk::core PROPERTIES
  IMPORTED_LOCATION "${_session_archive}"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_LIST_DIR}")
unset(_session_archive)
