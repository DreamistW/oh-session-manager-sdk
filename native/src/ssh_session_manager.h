#ifndef HOMOXTERM_SSH_SESSION_MANAGER_H
#define HOMOXTERM_SSH_SESSION_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>

namespace homoxterm {

enum class NativeResultKind {
    String,
    Boolean,
    Integer,
    Bytes
};

struct NativeResult {
    bool ok = false;
    NativeResultKind kind = NativeResultKind::String;
    std::string text;
    int64_t integer = 0;
    std::vector<uint8_t> bytes;

    static NativeResult Error(const std::string &message);
    static NativeResult String(const std::string &value);
    static NativeResult Boolean(bool value);
    static NativeResult Integer(int64_t value);
    static NativeResult Bytes(std::vector<uint8_t> value);
};

class SshSessionManager {
public:
    static SshSessionManager &Instance();

    NativeResult Connect(const std::string &host, uint16_t port, bool legacy = false);
    NativeResult ReserveMetrics();
    NativeResult CancelMetrics(uint64_t sessionId);
    NativeResult ConnectMetrics(const std::string &host, uint16_t port, const std::string &fingerprint,
        const std::string &username, const std::string &kind, const std::string &secret,
        const std::string &passphrase, uint64_t reservedId = 0, bool legacy = false);
    NativeResult AcceptHostKey(uint64_t sessionId, bool accepted);
    NativeResult Authenticate(uint64_t sessionId, const std::string &username,
        const std::string &kind, const std::string &secret, const std::string &passphrase);
    NativeResult KeyboardInteractivePrompt(uint64_t sessionId);
    NativeResult RespondKeyboardInteractive(uint64_t sessionId, const std::string &response);
    NativeResult OpenPty(uint64_t sessionId, const std::string &terminalType,
        uint32_t columns, uint32_t rows);
    NativeResult Write(uint64_t sessionId, const std::vector<uint8_t> &bytes);
    NativeResult Read(uint64_t sessionId, size_t maximumBytes);
    NativeResult ResizePty(uint64_t sessionId, uint32_t columns, uint32_t rows);
    NativeResult OpenSftp(uint64_t sessionId);
    NativeResult ListDirectory(uint64_t sessionId, const std::string &path, bool forDeletion = false);
    NativeResult BeginScp(uint64_t id, const std::string &path, bool upload, uint64_t size);
    NativeResult StepScp(uint64_t id, uint64_t handle, int fd);
    NativeResult EndScp(uint64_t id, uint64_t handle, bool complete);
    NativeResult ReadFileChunk(uint64_t sessionId, const std::string &path,
        uint64_t offset, size_t maximumBytes);
    NativeResult WriteFileChunk(uint64_t sessionId, const std::string &path,
        uint64_t offset, const std::vector<uint8_t> &bytes, bool truncate);
    NativeResult CreateDirectory(uint64_t sessionId, const std::string &path);
    NativeResult RemoveEntry(uint64_t sessionId, const std::string &path, bool isDirectory);
    NativeResult CollectRemoteMetrics(uint64_t sessionId);
    NativeResult Disconnect(uint64_t sessionId);
    void Shutdown();

private:
    SshSessionManager();
    ~SshSessionManager();
    SshSessionManager(const SshSessionManager &) = delete;
    SshSessionManager &operator=(const SshSessionManager &) = delete;

    class Impl;
    Impl *impl_;
};

} // namespace homoxterm

#endif // HOMOXTERM_SSH_SESSION_MANAGER_H
