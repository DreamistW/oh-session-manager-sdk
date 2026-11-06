#ifndef SESSION_MANAGER_SDK_H
#define SESSION_MANAGER_SDK_H

#include <napi/native_api.h>

// 将 SDK 实现注册到宿主应用的 NAPI 模块。
napi_value RegisterSessionManagerExports(napi_env env, napi_value exports);

#endif
