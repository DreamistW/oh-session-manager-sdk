#include "ssh_napi.h"

#include "ssh_session_manager.h"

#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace homoxterm {
namespace {

void SecureClear(std::string &value)
{
    volatile char *cursor = value.empty() ? nullptr : &value[0];
    for (size_t index = 0; index < value.size(); ++index) {
        cursor[index] = 0;
    }
    value.clear();
}

void SecureClear(std::vector<char> &value)
{
    volatile char *cursor = value.empty() ? nullptr : value.data();
    for (size_t index = 0; index < value.size(); ++index) {
        cursor[index] = 0;
    }
    value.clear();
}

struct SensitiveCharBuffer {
    explicit SensitiveCharBuffer(size_t size) : value(size) {}
    ~SensitiveCharBuffer() { SecureClear(value); }
    std::vector<char> value;
};

struct SensitiveAuthentication {
    ~SensitiveAuthentication()
    {
        SecureClear(secret);
        SecureClear(passphrase);
    }

    std::string secret;
    std::string passphrase;
};

struct SessionWork {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::function<NativeResult()> operation;
    NativeResult result;
};

bool ReadString(napi_env env, napi_value value, std::string &output, size_t maximum = 4U * 1024U * 1024U)
{
    size_t length = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok || length > maximum) {
        return false;
    }
    SensitiveCharBuffer buffer(length + 1U);
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, value, buffer.value.data(), buffer.value.size(), &copied) != napi_ok ||
        copied != length) {
        return false;
    }
    output.assign(buffer.value.data(), length);
    return true;
}

bool ReadUint64(napi_env env, napi_value value, uint64_t &output)
{
    double number = 0;
    if (napi_get_value_double(env, value, &number) != napi_ok || number < 0 ||
        number > 9007199254740991.0) {
        return false;
    }
    output = static_cast<uint64_t>(number);
    return static_cast<double>(output) == number;
}

bool ReadBool(napi_env env, napi_value value, bool &output)
{
    return napi_get_value_bool(env, value, &output) == napi_ok;
}

bool ReadBytes(napi_env env, napi_value value, std::vector<uint8_t> &output)
{
    bool isArrayBuffer = false;
    if (napi_is_arraybuffer(env, value, &isArrayBuffer) != napi_ok || !isArrayBuffer) {
        return false;
    }
    void *data = nullptr;
    size_t length = 0;
    if (napi_get_arraybuffer_info(env, value, &data, &length) != napi_ok || length > 256U * 1024U) {
        return false;
    }
    if (length == 0) {
        output.clear();
        return true;
    }
    if (data == nullptr) {
        return false;
    }
    const auto *begin = static_cast<const uint8_t *>(data);
    output.assign(begin, begin + length);
    return true;
}

napi_value TypeError(napi_env env, const char *message)
{
    napi_throw_type_error(env, nullptr, message);
    return nullptr;
}

napi_value NativeError(napi_env env, const std::string &message)
{
    napi_throw_error(env, nullptr, message.c_str());
    return nullptr;
}

void ExecuteSessionWork(napi_env, void *data)
{
    auto *work = static_cast<SessionWork *>(data);
    work->result = work->operation();
}

void CompleteResult(napi_env env, napi_deferred deferred, const NativeResult &result, napi_status status)
{
    napi_value value = nullptr;
    if (status != napi_ok || !result.ok) {
        const std::string message = status == napi_ok ? result.text : "native async work failed";
        napi_value text = nullptr;
        napi_create_string_utf8(env, message.c_str(), message.size(), &text);
        napi_create_error(env, nullptr, text, &value);
        napi_reject_deferred(env, deferred, value);
    } else {
        switch (result.kind) {
            case NativeResultKind::String:
                napi_create_string_utf8(env, result.text.c_str(), result.text.size(), &value);
                break;
            case NativeResultKind::Boolean:
                napi_get_boolean(env, result.integer != 0, &value);
                break;
            case NativeResultKind::Integer:
                napi_create_int64(env, result.integer, &value);
                break;
            case NativeResultKind::Bytes: {
                void *target = nullptr;
                napi_create_arraybuffer(env, result.bytes.size(), &target, &value);
                if (target != nullptr && !result.bytes.empty()) {
                    std::memcpy(target, result.bytes.data(), result.bytes.size());
                }
                break;
            }
        }
        napi_resolve_deferred(env, deferred, value);
    }
}

void CompleteSessionWork(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<SessionWork> work(static_cast<SessionWork *>(data));
    CompleteResult(env, work->deferred, work->result, status);
    napi_delete_async_work(env, work->work);
}

struct MetricsWork {
    napi_threadsafe_function completion = nullptr;
    napi_deferred deferred = nullptr;
    std::function<NativeResult()> operation;
    NativeResult result;
    std::thread worker;
    bool createsConnection = false;
    bool delivered = false;
};

void FinalizeMetricsWork(napi_env, void *data, void *)
{
    std::unique_ptr<MetricsWork> work(static_cast<MetricsWork *>(data));
    if (work->worker.joinable()) { work->worker.join(); }
    if (work->createsConnection && !work->delivered && work->result.ok && work->result.integer > 0) {
        SshSessionManager::Instance().Disconnect(static_cast<uint64_t>(work->result.integer));
    }
}

void CompleteMetricsWork(napi_env env, napi_value, void *context, void *)
{
    auto *work = static_cast<MetricsWork *>(context);
    if (env != nullptr) {
        CompleteResult(env, work->deferred, work->result, napi_ok);
        work->delivered = true;
    }
}

// Metrics must not occupy the shared NAPI async pool while waiting for its own
// session thread. TSFN only delivers completion; all network work stays native.
napi_value QueueMetrics(napi_env env, const char *name, std::function<NativeResult()> operation,
    bool createsConnection = false)
{
    auto work = std::make_unique<MetricsWork>();
    work->operation = std::move(operation);
    work->createsConnection = createsConnection;
    napi_value promise = nullptr;
    napi_value resourceName = nullptr;
    if (napi_create_promise(env, &work->deferred, &promise) != napi_ok ||
        napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resourceName) != napi_ok ||
        napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 1, 1, work.get(),
            FinalizeMetricsWork, work.get(), CompleteMetricsWork, &work->completion) != napi_ok) {
        return TypeError(env, "unable to queue metrics operation");
    }
    MetricsWork *pending = work.release(); // Owned by the TSFN finalizer from here.
    try {
        pending->worker = std::thread([pending]() {
            try { pending->result = pending->operation(); }
            catch (...) { pending->result = NativeResult::Error("metrics operation failed"); }
            pending->operation = nullptr; // Release/zero authentication material before notifying ArkTS.
            napi_call_threadsafe_function(pending->completion, nullptr, napi_tsfn_nonblocking);
            napi_release_threadsafe_function(pending->completion, napi_tsfn_release);
        });
    } catch (...) {
        CompleteResult(env, pending->deferred, NativeResult::Error("metrics worker unavailable"), napi_ok);
        napi_release_threadsafe_function(pending->completion, napi_tsfn_abort);
    }
    return promise;
}

napi_value Queue(napi_env env, const char *name, std::function<NativeResult()> operation)
{
    auto work = std::make_unique<SessionWork>();
    work->operation = std::move(operation);
    napi_value promise = nullptr;
    napi_value resourceName = nullptr;
    if (napi_create_promise(env, &work->deferred, &promise) != napi_ok ||
        napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resourceName) != napi_ok ||
        napi_create_async_work(env, nullptr, resourceName, ExecuteSessionWork, CompleteSessionWork,
            work.get(), &work->work) != napi_ok || napi_queue_async_work(env, work->work) != napi_ok) {
        return TypeError(env, "unable to queue native SSH operation");
    }
    work.release();
    return promise;
}

bool ReadArgs(napi_env env, napi_callback_info info, size_t expected,
    napi_value *arguments)
{
    size_t count = expected;
    return napi_get_cb_info(env, info, &count, arguments, nullptr, nullptr) == napi_ok && count == expected;
}

} // namespace

napi_value ConnectNapi(napi_env env, napi_callback_info info)
{
    napi_value args[3] {};
    size_t count = 3;
    bool legacy = false;
    std::string host;
    uint64_t port = 0;
    if (napi_get_cb_info(env, info, &count, args, nullptr, nullptr) != napi_ok || count < 2 ||
        (count == 3 && !ReadBool(env, args[2], legacy)) || !ReadString(env, args[0], host, 1024U) || host.empty() ||
        !ReadUint64(env, args[1], port) || port == 0 || port > UINT16_MAX) {
        return TypeError(env, "connect requires a valid host and port");
    }
    return Queue(env, "HomoxSshConnect", [host, port, legacy]() {
        return SshSessionManager::Instance().Connect(host, static_cast<uint16_t>(port), legacy);
    });
}

napi_value AcceptHostKeyNapi(napi_env env, napi_callback_info info)
{
    napi_value args[2] {nullptr, nullptr};
    uint64_t id = 0;
    bool accepted = false;
    if (!ReadArgs(env, info, 2, args) || !ReadUint64(env, args[0], id) ||
        !ReadBool(env, args[1], accepted)) {
        return TypeError(env, "acceptHostKey requires sessionId and decision");
    }
    return Queue(env, "HomoxAcceptHostKey", [id, accepted]() {
        return SshSessionManager::Instance().AcceptHostKey(id, accepted);
    });
}

napi_value AuthenticateNapi(napi_env env, napi_callback_info info)
{
    napi_value args[5] {nullptr, nullptr, nullptr, nullptr, nullptr};
    uint64_t id = 0;
    std::string username;
    std::string kind;
    auto sensitive = std::make_shared<SensitiveAuthentication>();
    if (!ReadArgs(env, info, 5, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], username, 1024U) || username.empty() ||
        !ReadString(env, args[2], kind, 64U) || !ReadString(env, args[3], sensitive->secret) ||
        !ReadString(env, args[4], sensitive->passphrase)) {
        return TypeError(env, "authenticate requires sessionId, username, kind, secret and passphrase");
    }
    return Queue(env, "HomoxSshAuthenticate", [id, username, kind, sensitive]() {
        NativeResult result = SshSessionManager::Instance().Authenticate(id, username, kind,
            sensitive->secret, sensitive->passphrase);
        SecureClear(sensitive->secret);
        SecureClear(sensitive->passphrase);
        return result;
    });
}

napi_value KeyboardInteractivePromptNapi(napi_env env, napi_callback_info info)
{
    napi_value args[1] {nullptr};
    uint64_t id = 0;
    if (!ReadArgs(env, info, 1, args) || !ReadUint64(env, args[0], id)) {
        return TypeError(env, "keyboardInteractivePrompt requires sessionId");
    }
    const NativeResult result = SshSessionManager::Instance().KeyboardInteractivePrompt(id);
    if (!result.ok) {
        return NativeError(env, result.text);
    }
    napi_value value = nullptr;
    napi_create_string_utf8(env, result.text.c_str(), result.text.size(), &value);
    return value;
}

napi_value RespondKeyboardInteractiveNapi(napi_env env, napi_callback_info info)
{
    napi_value args[2] {nullptr, nullptr};
    uint64_t id = 0;
    std::string response;
    if (!ReadArgs(env, info, 2, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], response, 64U * 1024U)) {
        SecureClear(response);
        return TypeError(env, "respondKeyboardInteractive requires sessionId and response");
    }
    const NativeResult result = SshSessionManager::Instance().RespondKeyboardInteractive(id, response);
    SecureClear(response);
    if (!result.ok) {
        return NativeError(env, result.text);
    }
    napi_value value = nullptr;
    napi_get_boolean(env, result.integer != 0, &value);
    return value;
}

napi_value OpenPtyNapi(napi_env env, napi_callback_info info)
{
    napi_value args[4] {nullptr, nullptr, nullptr, nullptr};
    uint64_t id = 0;
    uint64_t columns = 0;
    uint64_t rows = 0;
    std::string terminal;
    if (!ReadArgs(env, info, 4, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], terminal, 128U) || !ReadUint64(env, args[2], columns) ||
        !ReadUint64(env, args[3], rows) || columns == 0 || rows == 0 ||
        columns > 10000U || rows > 10000U) {
        return TypeError(env, "openPty requires sessionId, terminalType, columns and rows");
    }
    return Queue(env, "HomoxOpenPty", [id, terminal, columns, rows]() {
        return SshSessionManager::Instance().OpenPty(id, terminal,
            static_cast<uint32_t>(columns), static_cast<uint32_t>(rows));
    });
}

napi_value WriteNapi(napi_env env, napi_callback_info info)
{
    napi_value args[2] {nullptr, nullptr};
    uint64_t id = 0;
    std::vector<uint8_t> bytes;
    if (!ReadArgs(env, info, 2, args) || !ReadUint64(env, args[0], id) || !ReadBytes(env, args[1], bytes)) {
        return TypeError(env, "write requires sessionId and an ArrayBuffer up to 256 KiB");
    }
    return Queue(env, "HomoxSshWrite", [id, bytes = std::move(bytes)]() {
        return SshSessionManager::Instance().Write(id, bytes);
    });
}

napi_value ReadNapi(napi_env env, napi_callback_info info)
{
    napi_value args[2] {nullptr, nullptr};
    uint64_t id = 0;
    uint64_t maximum = 0;
    if (!ReadArgs(env, info, 2, args) || !ReadUint64(env, args[0], id) ||
        !ReadUint64(env, args[1], maximum) || maximum == 0 || maximum > 256U * 1024U) {
        return TypeError(env, "read requires sessionId and a bounded byte count");
    }
    return Queue(env, "HomoxSshRead", [id, maximum]() {
        return SshSessionManager::Instance().Read(id, static_cast<size_t>(maximum));
    });
}

napi_value CollectRemoteMetricsNapi(napi_env env, napi_callback_info info)
{
    napi_value args[1] {nullptr};
    uint64_t id = 0;
    if (!ReadArgs(env, info, 1, args) || !ReadUint64(env, args[0], id)) {
        return TypeError(env, "collectRemoteMetrics requires sessionId");
    }
    return QueueMetrics(env, "HomoxCollectRemoteMetrics", [id]() {
        return SshSessionManager::Instance().CollectRemoteMetrics(id);
    });
}

napi_value ReserveMetricsNapi(napi_env env, napi_callback_info)
{
    const auto result = SshSessionManager::Instance().ReserveMetrics();
    if (!result.ok) { return NativeError(env, result.text); }
    napi_value value = nullptr;
    napi_create_int64(env, result.integer, &value);
    return value;
}

napi_value CancelMetricsNapi(napi_env env, napi_callback_info info)
{
    napi_value args[1] {};
    uint64_t id = 0;
    if (!ReadArgs(env, info, 1, args) || !ReadUint64(env, args[0], id)) {
        return TypeError(env, "cancelMetrics requires sessionId");
    }
    SshSessionManager::Instance().CancelMetrics(id);
    napi_value value = nullptr;
    napi_get_boolean(env, true, &value);
    return value;
}

napi_value ConnectMetricsNapi(napi_env env, napi_callback_info info)
{
    napi_value args[9] {};
    size_t count = 9;
    bool legacy = false;
    std::string host, fingerprint, username, kind;
    uint64_t port = 0, reservedId = 0;
    auto sensitive = std::make_shared<SensitiveAuthentication>();
    if (napi_get_cb_info(env, info, &count, args, nullptr, nullptr) != napi_ok || count < 8 ||
        (count == 9 && !ReadBool(env, args[8], legacy)) || !ReadString(env, args[0], host, 1024U) || host.empty() ||
        !ReadUint64(env, args[1], port) || port == 0 || port > UINT16_MAX ||
        !ReadString(env, args[2], fingerprint, 128U) || fingerprint.empty() ||
        !ReadString(env, args[3], username, 1024U) || username.empty() ||
        !ReadString(env, args[4], kind, 64U) || (kind != "password" && kind != "private-key") ||
        !ReadString(env, args[5], sensitive->secret) || !ReadString(env, args[6], sensitive->passphrase) || !ReadUint64(env, args[7], reservedId) || reservedId == 0) {
        return TypeError(env, "invalid isolated metrics connection arguments");
    }
    return QueueMetrics(env, "HomoxConnectMetrics", [host, port, fingerprint, username, kind, sensitive, reservedId, legacy]() {
        return SshSessionManager::Instance().ConnectMetrics(host, static_cast<uint16_t>(port), fingerprint,
            username, kind, sensitive->secret, sensitive->passphrase, reservedId, legacy);
    }, true);
}

napi_value DisconnectMetricsNapi(napi_env env, napi_callback_info info)
{
    napi_value args[1] {};
    uint64_t id = 0;
    if (!ReadArgs(env, info, 1, args) || !ReadUint64(env, args[0], id)) {
        return TypeError(env, "disconnectMetrics requires sessionId");
    }
    return QueueMetrics(env, "HomoxDisconnectMetrics", [id]() {
        return SshSessionManager::Instance().Disconnect(id);
    });
}

napi_value ResizePtyNapi(napi_env env, napi_callback_info info)
{
    napi_value args[3] {nullptr, nullptr, nullptr};
    uint64_t id = 0;
    uint64_t columns = 0;
    uint64_t rows = 0;
    if (!ReadArgs(env, info, 3, args) || !ReadUint64(env, args[0], id) ||
        !ReadUint64(env, args[1], columns) || !ReadUint64(env, args[2], rows) ||
        columns == 0 || rows == 0 || columns > 10000U || rows > 10000U) {
        return TypeError(env, "resizePty requires sessionId, columns and rows");
    }
    return Queue(env, "HomoxResizePty", [id, columns, rows]() {
        return SshSessionManager::Instance().ResizePty(id,
            static_cast<uint32_t>(columns), static_cast<uint32_t>(rows));
    });
}

napi_value OpenSftpNapi(napi_env env, napi_callback_info info)
{
    napi_value args[1] {nullptr};
    uint64_t id = 0;
    if (!ReadArgs(env, info, 1, args) || !ReadUint64(env, args[0], id)) {
        return TypeError(env, "openSftp requires sessionId");
    }
    return Queue(env, "HomoxOpenSftp", [id]() { return SshSessionManager::Instance().OpenSftp(id); });
}

napi_value ListDirectoryNapi(napi_env env, napi_callback_info info)
{
    napi_value args[2] {nullptr, nullptr};
    uint64_t id = 0;
    std::string path;
    if (!ReadArgs(env, info, 2, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], path, 4096U) || path.empty()) {
        return TypeError(env, "listDirectory requires sessionId and path");
    }
    return Queue(env, "HomoxListDirectory", [id, path]() {
        return SshSessionManager::Instance().ListDirectory(id, path);
    });
}

napi_value ListDeleteDirectoryNapi(napi_env env, napi_callback_info info)
{
    napi_value args[2] {nullptr, nullptr};
    uint64_t id = 0;
    std::string path;
    if (!ReadArgs(env, info, 2, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], path, 4096U) || path.empty() || path.find('\0') != std::string::npos) {
        return TypeError(env, "listDeleteDirectory requires sessionId and a safe path");
    }
    return Queue(env, "HomoxListDeleteDirectory", [id, path]() {
        return SshSessionManager::Instance().ListDirectory(id, path, true);
    });
}

napi_value BeginScpNapi(napi_env env, napi_callback_info info)
{
    napi_value args[4] {};
    uint64_t id = 0, size = 0;
    std::string path;
    bool upload = false;
    if (!ReadArgs(env, info, 4, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], path, 4096) || !ReadBool(env, args[2], upload) || !ReadUint64(env, args[3], size)) {
        return TypeError(env, "Invalid SCP transfer");
    }
    return Queue(env, "HomoxBeginScp", [=]() { return SshSessionManager::Instance().BeginScp(id, path, upload, size); });
}

napi_value StepScpNapi(napi_env env, napi_callback_info info)
{
    napi_value args[3] {};
    uint64_t id = 0, handle = 0, fd = 0;
    if (!ReadArgs(env, info, 3, args) || !ReadUint64(env, args[0], id) ||
        !ReadUint64(env, args[1], handle) || !ReadUint64(env, args[2], fd) || fd > INT32_MAX) {
        return TypeError(env, "Invalid SCP file descriptor");
    }
    return Queue(env, "HomoxStepScp", [=]() { return SshSessionManager::Instance().StepScp(id, handle, static_cast<int>(fd)); });
}

napi_value EndScpNapi(napi_env env, napi_callback_info info)
{
    napi_value args[3] {};
    uint64_t id = 0, handle = 0;
    bool complete = false;
    if (!ReadArgs(env, info, 3, args) || !ReadUint64(env, args[0], id) ||
        !ReadUint64(env, args[1], handle) || !ReadBool(env, args[2], complete)) {
        return TypeError(env, "Invalid SCP completion");
    }
    return Queue(env, "HomoxEndScp", [=]() { return SshSessionManager::Instance().EndScp(id, handle, complete); });
}

napi_value ReadFileChunkNapi(napi_env env, napi_callback_info info)
{
    napi_value args[4] {nullptr, nullptr, nullptr, nullptr};
    uint64_t id = 0;
    uint64_t offset = 0;
    uint64_t maximum = 0;
    std::string path;
    if (!ReadArgs(env, info, 4, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], path, 4096U) || !ReadUint64(env, args[2], offset) ||
        !ReadUint64(env, args[3], maximum) || maximum == 0 || maximum > 256U * 1024U) {
        return TypeError(env, "readFileChunk requires sessionId, path, offset and bounded size");
    }
    return Queue(env, "HomoxReadFileChunk", [id, path, offset, maximum]() {
        return SshSessionManager::Instance().ReadFileChunk(id, path, offset, static_cast<size_t>(maximum));
    });
}

napi_value WriteFileChunkNapi(napi_env env, napi_callback_info info)
{
    napi_value args[5] {nullptr, nullptr, nullptr, nullptr, nullptr};
    uint64_t id = 0;
    uint64_t offset = 0;
    std::string path;
    std::vector<uint8_t> bytes;
    bool truncate = false;
    if (!ReadArgs(env, info, 5, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], path, 4096U) || !ReadUint64(env, args[2], offset) ||
        !ReadBytes(env, args[3], bytes) || !ReadBool(env, args[4], truncate)) {
        return TypeError(env, "writeFileChunk requires sessionId, path, offset, ArrayBuffer and truncate flag");
    }
    return Queue(env, "HomoxWriteFileChunk", [id, path, offset, bytes = std::move(bytes), truncate]() {
        return SshSessionManager::Instance().WriteFileChunk(id, path, offset, bytes, truncate);
    });
}

napi_value CreateDirectoryNapi(napi_env env, napi_callback_info info)
{
    napi_value args[2] {nullptr, nullptr};
    uint64_t id = 0;
    std::string path;
    if (!ReadArgs(env, info, 2, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], path, 4096U) || path.empty() || path == "/" ||
        path.find('\0') != std::string::npos ||
        (path.size() >= 2U && path.compare(path.size() - 2U, 2U, "/.") == 0) ||
        (path.size() >= 3U && path.compare(path.size() - 3U, 3U, "/..") == 0)) {
        return TypeError(env, "createDirectory requires sessionId and a safe path");
    }
    return Queue(env, "HomoxCreateDirectory", [id, path]() {
        return SshSessionManager::Instance().CreateDirectory(id, path);
    });
}

napi_value RemoveEntryNapi(napi_env env, napi_callback_info info)
{
    napi_value args[3] {nullptr, nullptr, nullptr};
    uint64_t id = 0;
    std::string path;
    bool isDirectory = false;
    if (!ReadArgs(env, info, 3, args) || !ReadUint64(env, args[0], id) ||
        !ReadString(env, args[1], path, 4096U) || path.empty() || path == "/" ||
        path.find('\0') != std::string::npos || !ReadBool(env, args[2], isDirectory)) {
        return TypeError(env, "removeEntry requires sessionId, a safe path and directory flag");
    }
    return Queue(env, "HomoxRemoveEntry", [id, path, isDirectory]() {
        return SshSessionManager::Instance().RemoveEntry(id, path, isDirectory);
    });
}

napi_value DisconnectNapi(napi_env env, napi_callback_info info)
{
    napi_value args[1] {nullptr};
    uint64_t id = 0;
    if (!ReadArgs(env, info, 1, args) || !ReadUint64(env, args[0], id)) {
        return TypeError(env, "disconnect requires sessionId");
    }
    return Queue(env, "HomoxSshDisconnect", [id]() {
        return SshSessionManager::Instance().Disconnect(id);
    });
}

} // namespace homoxterm
