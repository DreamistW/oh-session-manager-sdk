#include "session-manager-sdk.h"
#include "ohcrypto_probe.h"
#include "ssh_probe.h"
#include "ssh_napi.h"
#include "ftps_tls.h"

#include <hilog/log.h>
#include <napi/native_api.h>

#include <memory>
#include <string>

namespace {

constexpr unsigned int HOMOX_LOG_DOMAIN = 0xD003201;
constexpr const char *HOMOX_LOG_TAG = "HomoxNativeGate";

struct GateWork {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::string result;
};

struct SshGateWork {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::string host;
    uint16_t port = 0;
    std::string result;
};

void ExecuteGate(napi_env env, void *data)
{
    (void)env;
    auto *work = static_cast<GateWork *>(data);
    OH_LOG_Print(LOG_APP, LOG_INFO, HOMOX_LOG_DOMAIN, HOMOX_LOG_TAG, "EXECUTE_BEGIN");
    work->result = homoxterm::RunOhCryptoCompatibilityGate();
    OH_LOG_Print(LOG_APP, LOG_INFO, HOMOX_LOG_DOMAIN, HOMOX_LOG_TAG, "EXECUTE_END");
}

void CompleteGate(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<GateWork> work(static_cast<GateWork *>(data));
    napi_value value = nullptr;
    if (status == napi_ok) {
        napi_create_string_utf8(env, work->result.c_str(), work->result.size(), &value);
        napi_resolve_deferred(env, work->deferred, value);
        OH_LOG_Print(LOG_APP, LOG_INFO, HOMOX_LOG_DOMAIN, HOMOX_LOG_TAG, "%{public}s", work->result.c_str());
    } else {
        const char *message = "OHCRYPTO_GATE_FAIL\nFAIL napi-async-work";
        napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &value);
        napi_reject_deferred(env, work->deferred, value);
        OH_LOG_Print(LOG_APP, LOG_ERROR, HOMOX_LOG_DOMAIN, HOMOX_LOG_TAG, "%{public}s", message);
    }
    napi_delete_async_work(env, work->work);
}

napi_value RunCryptoCompatibilityGate(napi_env env, napi_callback_info info)
{
    (void)info;
    OH_LOG_Print(LOG_APP, LOG_INFO, HOMOX_LOG_DOMAIN, HOMOX_LOG_TAG, "QUEUED");
    auto work = std::make_unique<GateWork>();
    napi_value promise = nullptr;
    napi_value resourceName = nullptr;
    napi_create_promise(env, &work->deferred, &promise);
    napi_create_string_utf8(env, "HomoxCryptoCompatibilityGate", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, nullptr, resourceName, ExecuteGate, CompleteGate, work.get(), &work->work);
    napi_queue_async_work(env, work->work);
    work.release();
    return promise;
}

void ExecuteSshGate(napi_env env, void *data)
{
    (void)env;
    auto *work = static_cast<SshGateWork *>(data);
    work->result = homoxterm::RunLibssh2HandshakeGate(work->host, work->port);
}

void CompleteSshGate(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<SshGateWork> work(static_cast<SshGateWork *>(data));
    napi_value value = nullptr;
    if (status == napi_ok) {
        napi_create_string_utf8(env, work->result.c_str(), work->result.size(), &value);
        napi_resolve_deferred(env, work->deferred, value);
    } else {
        const char *message = "LIBSSH2_HANDSHAKE_FAIL napi-async-work";
        napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &value);
        napi_reject_deferred(env, work->deferred, value);
    }
    napi_delete_async_work(env, work->work);
}

napi_value RunLibssh2HandshakeGate(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] {nullptr, nullptr};
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 2) {
        napi_throw_type_error(env, nullptr, "host and port are required");
        return nullptr;
    }
    size_t hostLength = 0;
    uint32_t port = 0;
    if (napi_get_value_string_utf8(env, argv[0], nullptr, 0, &hostLength) != napi_ok ||
        hostLength == 0 || napi_get_value_uint32(env, argv[1], &port) != napi_ok ||
        port == 0 || port > UINT16_MAX) {
        napi_throw_type_error(env, nullptr, "invalid host or port");
        return nullptr;
    }
    auto work = std::make_unique<SshGateWork>();
    work->host.resize(hostLength);
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, argv[0], work->host.data(), hostLength + 1, &copied) != napi_ok ||
        copied != hostLength) {
        napi_throw_type_error(env, nullptr, "invalid host");
        return nullptr;
    }
    work->port = static_cast<uint16_t>(port);
    napi_value promise = nullptr;
    napi_value resourceName = nullptr;
    napi_create_promise(env, &work->deferred, &promise);
    napi_create_string_utf8(env, "HomoxLibssh2HandshakeGate", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, nullptr, resourceName, ExecuteSshGate, CompleteSshGate,
        work.get(), &work->work);
    napi_queue_async_work(env, work->work);
    work.release();
    return promise;
}

napi_value Init(napi_env env, napi_value exports)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, HOMOX_LOG_DOMAIN, HOMOX_LOG_TAG, "NAPI_INIT");
    napi_property_descriptor descriptors[] = {
        {"runCryptoCompatibilityGate", nullptr, RunCryptoCompatibilityGate, nullptr, nullptr, nullptr,
            napi_default, nullptr},
        {"runLibssh2HandshakeGate", nullptr, RunLibssh2HandshakeGate, nullptr, nullptr, nullptr,
            napi_default, nullptr},
        {"connect", nullptr, homoxterm::ConnectNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"acceptHostKey", nullptr, homoxterm::AcceptHostKeyNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"authenticate", nullptr, homoxterm::AuthenticateNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"keyboardInteractivePrompt", nullptr, homoxterm::KeyboardInteractivePromptNapi,
            nullptr, nullptr, nullptr, napi_default, nullptr},
        {"respondKeyboardInteractive", nullptr, homoxterm::RespondKeyboardInteractiveNapi,
            nullptr, nullptr, nullptr, napi_default, nullptr},
        {"openPty", nullptr, homoxterm::OpenPtyNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"write", nullptr, homoxterm::WriteNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"read", nullptr, homoxterm::ReadNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"resizePty", nullptr, homoxterm::ResizePtyNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"collectRemoteMetrics", nullptr, homoxterm::CollectRemoteMetricsNapi,
            nullptr, nullptr, nullptr, napi_default, nullptr},
        {"reserveMetrics", nullptr, homoxterm::ReserveMetricsNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"cancelMetrics", nullptr, homoxterm::CancelMetricsNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"connectMetrics", nullptr, homoxterm::ConnectMetricsNapi,
            nullptr, nullptr, nullptr, napi_default, nullptr},
        {"disconnectMetrics", nullptr, homoxterm::DisconnectMetricsNapi,
            nullptr, nullptr, nullptr, napi_default, nullptr},
        {"openSftp", nullptr, homoxterm::OpenSftpNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"listDirectory", nullptr, homoxterm::ListDirectoryNapi, nullptr, nullptr, nullptr,
            napi_default, nullptr},
        {"beginScp", nullptr, homoxterm::BeginScpNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stepScp", nullptr, homoxterm::StepScpNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"endScp", nullptr, homoxterm::EndScpNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"readFileChunk", nullptr, homoxterm::ReadFileChunkNapi, nullptr, nullptr, nullptr,
            napi_default, nullptr},
        {"writeFileChunk", nullptr, homoxterm::WriteFileChunkNapi, nullptr, nullptr, nullptr,
            napi_default, nullptr},
        {"createDirectory", nullptr, homoxterm::CreateDirectoryNapi, nullptr, nullptr, nullptr,
            napi_default, nullptr},
        {"listDeleteDirectory", nullptr, homoxterm::ListDeleteDirectoryNapi, nullptr, nullptr, nullptr,
            napi_default, nullptr},
        {"removeEntry", nullptr, homoxterm::RemoveEntryNapi, nullptr, nullptr, nullptr,
            napi_default, nullptr},
        {"disconnect", nullptr, homoxterm::DisconnectNapi, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
    homoxterm::RegisterFtpsTls(env, exports);
    return exports;
}

} // namespace

// 宿主 NAPI 模块使用此入口注册会话和 FTPS 接口。
napi_value RegisterSessionManagerExports(napi_env env, napi_value exports)
{
    return Init(env, exports);
}
