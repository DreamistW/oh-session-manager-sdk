#include "ssh_library_lifetime.h"
#include "ssh_session_manager.h"
#include "sftp_delete_policy.h"

#include <libssh2.h>
#include <libssh2_sftp.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace homoxterm {
namespace {

constexpr int OPERATION_TIMEOUT_MS = 15000;
constexpr int INTERACTIVE_WRITE_WAIT_SLICE_MS = 16;
constexpr int KEYBOARD_INTERACTIVE_TIMEOUT_MS = 120000;
constexpr size_t MAX_PENDING_PTY_BYTES = 1024U * 1024U;
constexpr size_t MAX_TRANSFER_CHUNK = 256U * 1024U;
constexpr size_t MAX_KEYBOARD_PROMPT_BYTES = 4096U;
constexpr size_t MAX_KEYBOARD_RESPONSE_BYTES = 64U * 1024U;
constexpr size_t MAX_REMOTE_METRICS_BYTES = 16U * 1024U;
constexpr int REMOTE_METRICS_TIMEOUT_MS = 3000;
constexpr int SSH_KEEPALIVE_SECONDS = 30;
constexpr char REMOTE_METRICS_COMMAND[] =
    "LC_ALL=C; "
    "printf 'system\\t'; uname -srm 2>/dev/null || true; printf '\\n'; "
    "awk 'NR==1 && $1==\"cpu\" { total=0; for(i=2;i<=9;i++) total+=$i; "
    "printf \"cpu\\t%.0f\\t%.0f\\n\", total, ($5+$6) }' /proc/stat 2>/dev/null; "
    "awk '/^MemTotal:/ { total=$2 } /^MemAvailable:/ { available=$2 } "
    "END { if(total!=\"\" && available!=\"\") print \"memory\\t\" total \"\\t\" available }' "
    "/proc/meminfo 2>/dev/null; "
    "awk 'NR>2 { name=$1; gsub(/:/,\"\",name); if(name!=\"lo\") { receive+=$2; transmit+=$10; seen=1 } } "
    "END { if(seen) printf \"network\\t%.0f\\t%.0f\\n\", receive+0, transmit+0 }' /proc/net/dev 2>/dev/null; "
    "awk 'NR==1 { print \"uptime\\t\" int($1) }' /proc/uptime 2>/dev/null; "
    "df -Pk / 2>/dev/null | awk 'NR==2 { print \"root\\t\" $2 \"\\t\" $4 }'";

// 拒绝在连接流程内改密，让 libssh2 将服务端改密请求明确返回为 PASSWORD_EXPIRED。
void DeclinePasswordChange(LIBSSH2_SESSION *, char **newPassword, int *length, void **)
{
    *newPassword = nullptr;
    *length = 0;
}

void SecureClear(std::string &value)
{
    volatile char *cursor = value.empty() ? nullptr : &value[0];
    for (size_t index = 0; index < value.size(); ++index) {
        cursor[index] = 0;
    }
    value.clear();
}

std::string JsonEscape(const std::string &value)
{
    std::ostringstream output;
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': output << "\\\\"; break;
            case '"': output << "\\\""; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (ch < 0x20U) {
                    static constexpr char HEX[] = "0123456789abcdef";
                    output << "\\u00" << HEX[ch >> 4U] << HEX[ch & 0x0fU];
                } else {
                    output << static_cast<char>(ch);
                }
        }
    }
    return output.str();
}

std::string SanitizeKeyboardPrompt(const char *value, size_t length)
{
    std::string output;
    if (value == nullptr || length == 0) {
        return output;
    }
    const size_t accepted = std::min(length, MAX_KEYBOARD_PROMPT_BYTES);
    output.reserve(accepted);
    for (size_t index = 0; index < accepted; ++index) {
        const unsigned char ch = static_cast<unsigned char>(value[index]);
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            output.push_back(' ');
        } else if (ch >= 0x20U && ch != 0x7fU) {
            output.push_back(static_cast<char>(ch));
        }
    }
    return output;
}

std::string Base64(const unsigned char *data, size_t length)
{
    static constexpr char TABLE[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((length + 2U) / 3U) * 4U);
    for (size_t index = 0; index < length; index += 3U) {
        const uint32_t first = data[index];
        const uint32_t second = index + 1U < length ? data[index + 1U] : 0U;
        const uint32_t third = index + 2U < length ? data[index + 2U] : 0U;
        const uint32_t value = (first << 16U) | (second << 8U) | third;
        output.push_back(TABLE[(value >> 18U) & 0x3fU]);
        output.push_back(TABLE[(value >> 12U) & 0x3fU]);
        output.push_back(index + 1U < length ? TABLE[(value >> 6U) & 0x3fU] : '=');
        output.push_back(index + 2U < length ? TABLE[value & 0x3fU] : '=');
    }
    while (!output.empty() && output.back() == '=') {
        output.pop_back();
    }
    return output;
}

std::string SafeMethod(LIBSSH2_SESSION *session, int method)
{
    const char *value = libssh2_session_methods(session, method);
    return value == nullptr ? "unknown" : value;
}

int ConnectSocket(const std::string &host, uint16_t port, const std::atomic<bool> &cancelled)
{
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *addresses = nullptr;
    const std::string service = std::to_string(port);
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses) != 0) {
        return -1;
    }
    int connected = -1;
    for (addrinfo *address = addresses; address != nullptr && !cancelled; address = address->ai_next) {
        int candidate = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (candidate < 0) {
            continue;
        }
        const int flags = fcntl(candidate, F_GETFL, 0);
        if (flags < 0 || fcntl(candidate, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(candidate);
            continue;
        }
        int result = connect(candidate, address->ai_addr, address->ai_addrlen);
        if (result != 0 && errno == EINPROGRESS) {
            pollfd descriptor {candidate, POLLOUT, 0};
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(OPERATION_TIMEOUT_MS);
            do {
                result = poll(&descriptor, 1, 100);
            } while (result == 0 && !cancelled && std::chrono::steady_clock::now() < deadline);
            if (cancelled) { result = -1; }
            int socketError = 0;
            socklen_t errorLength = sizeof(socketError);
            if (result > 0 && getsockopt(candidate, SOL_SOCKET, SO_ERROR,
                &socketError, &errorLength) == 0 && socketError == 0) {
                result = 0;
            } else {
                result = -1;
            }
        }
        if (result == 0 && !cancelled) {
            const int enabled = 1;
            // PTY input is sent in small packets. Do not hold a later key behind
            // an unacknowledged packet while waiting for Nagle/delayed ACK.
            if (setsockopt(candidate, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0) {
                close(candidate);
                continue;
            }
            const int idle = 60;
            const int interval = 15;
            const int probes = 3;
            setsockopt(candidate, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled));
            setsockopt(candidate, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
            setsockopt(candidate, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
            setsockopt(candidate, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes));
            connected = candidate;
            break;
        }
        close(candidate);
    }
    freeaddrinfo(addresses);
    return connected;
}

enum class CommandType {
    Connect,
    AcceptHostKey,
    Authenticate,
    OpenPty,
    Write,
    Read,
    Resize,
    OpenSftp,
    ListDirectory,
    BeginScp,
    StepScp,
    EndScp,
    ReadFileChunk,
    WriteFileChunk,
    CreateDirectory,
    RemoveEntry,
    CollectRemoteMetrics,
    Disconnect
};

struct Command {
    ~Command()
    {
        SecureClear(secret);
        SecureClear(third);
    }

    CommandType type = CommandType::Disconnect;
    std::string first;
    std::string second;
    std::string third;
    std::string secret;
    std::vector<uint8_t> bytes;
    uint64_t firstNumber = 0;
    uint64_t secondNumber = 0;
    bool flag = false;
    std::promise<NativeResult> completion;
};

struct ScpTransfer {
    LIBSSH2_CHANNEL *channel;
    uint64_t remaining;
    bool upload;
    std::string path;
    std::string staging;
};

class NativeSession {
public:
    explicit NativeSession(uint64_t id, bool metricsOnly = false) :
        id_(id), metricsOnly_(metricsOnly), worker_(&NativeSession::WorkerLoop, this) {}

    ~NativeSession()
    {
        Stop();
    }

    NativeResult Invoke(std::unique_ptr<Command> command)
    {
        std::future<NativeResult> future = command->completion.get_future();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return NativeResult::Error("session is closing");
            }
            commands_.push_back(std::move(command));
        }
        condition_.notify_one();
        return future.get();
    }

    bool IsMetricsOnly() const { return metricsOnly_; }

    void CancelMetrics()
    {
        if (metricsOnly_) {
            stopping_ = true;
            condition_.notify_one();
        }
    }

    void Stop()
    {
        bool shouldJoin = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!stopping_) {
                stopping_ = true;
            }
            shouldJoin = worker_.joinable();
        }
        CancelKeyboardInteractive();
        condition_.notify_one();
        if (shouldJoin) {
            worker_.join();
        }
    }

    NativeResult KeyboardInteractivePrompt()
    {
        std::lock_guard<std::mutex> lock(keyboardMutex_);
        if (!keyboardPromptPending_) {
            return NativeResult::String("{\"pending\":false}");
        }
        std::ostringstream output;
        output << "{\"pending\":true,\"sequence\":" << keyboardPromptSequence_
               << ",\"prompt\":\"" << JsonEscape(keyboardPrompt_)
               << "\",\"echo\":" << (keyboardPromptEcho_ ? "true" : "false") << "}";
        return NativeResult::String(output.str());
    }

    NativeResult RespondKeyboardInteractive(const std::string &response)
    {
        if (response.empty()) {
            return NativeResult::Boolean(false);
        }
        if (response.size() > MAX_KEYBOARD_RESPONSE_BYTES) {
            return NativeResult::Error("keyboard-interactive response is too large");
        }
        {
            std::lock_guard<std::mutex> lock(keyboardMutex_);
            if (!keyboardPromptPending_ || keyboardResponseReady_ || keyboardCancelled_ || stopping_) {
                return NativeResult::Boolean(false);
            }
            SecureClear(keyboardResponse_);
            keyboardResponse_ = response;
            keyboardResponseReady_ = true;
        }
        keyboardCondition_.notify_all();
        return NativeResult::Boolean(true);
    }

private:
    static void KeyboardInteractiveCallback(const char *, int, const char *instruction, int instructionLength,
        int promptCount, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
        LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, void **abstract)
    {
        if (abstract == nullptr || *abstract == nullptr || prompts == nullptr || responses == nullptr) {
            return;
        }
        auto *self = static_cast<NativeSession *>(*abstract);
        for (int index = 0; index < promptCount; ++index) {
            responses[index].text = nullptr;
            responses[index].length = 0;
            std::string prompt;
            if (index == 0 && instruction != nullptr && instructionLength > 0) {
                prompt = SanitizeKeyboardPrompt(instruction, static_cast<size_t>(instructionLength));
                if (!prompt.empty()) {
                    prompt.append(" ");
                }
            }
            prompt.append(SanitizeKeyboardPrompt(reinterpret_cast<const char *>(prompts[index].text),
                prompts[index].length));
            if (!self->FillKeyboardInteractiveResponse(prompt, prompts[index].echo != 0, responses[index])) {
                return;
            }
        }
    }

    void PrepareKeyboardInteractive()
    {
        std::lock_guard<std::mutex> lock(keyboardMutex_);
        SecureClear(keyboardPrompt_);
        SecureClear(keyboardResponse_);
        keyboardPromptPending_ = false;
        keyboardPromptEcho_ = false;
        keyboardResponseReady_ = false;
        keyboardCancelled_ = false;
        keyboardTimedOut_ = false;
    }

    void CancelKeyboardInteractive()
    {
        {
            std::lock_guard<std::mutex> lock(keyboardMutex_);
            keyboardCancelled_ = true;
            keyboardPromptPending_ = false;
            keyboardResponseReady_ = false;
            SecureClear(keyboardPrompt_);
            SecureClear(keyboardResponse_);
        }
        keyboardCondition_.notify_all();
    }

    bool FillKeyboardInteractiveResponse(const std::string &prompt, bool echo,
        LIBSSH2_USERAUTH_KBDINT_RESPONSE &response)
    {
        std::unique_lock<std::mutex> lock(keyboardMutex_);
        if (keyboardCancelled_ || stopping_) {
            return false;
        }
        SecureClear(keyboardPrompt_);
        SecureClear(keyboardResponse_);
        keyboardPrompt_ = prompt.empty() ? "Keyboard-interactive response: " : prompt;
        keyboardPromptEcho_ = echo;
        keyboardPromptPending_ = true;
        keyboardResponseReady_ = false;
        ++keyboardPromptSequence_;
        keyboardCondition_.notify_all();
        const bool ready = keyboardCondition_.wait_for(lock,
            std::chrono::milliseconds(KEYBOARD_INTERACTIVE_TIMEOUT_MS), [this]() {
                return keyboardResponseReady_ || keyboardCancelled_ || stopping_;
            });
        if (!ready) {
            keyboardTimedOut_ = true;
        }
        bool accepted = ready && keyboardResponseReady_ && !keyboardCancelled_ && !stopping_ &&
            !keyboardResponse_.empty();
        if (accepted) {
            const size_t length = keyboardResponse_.size();
            char *text = static_cast<char *>(malloc(length + 1U));
            if (text == nullptr) {
                accepted = false;
            } else {
                std::memcpy(text, keyboardResponse_.data(), length);
                text[length] = 0;
                response.text = text;
                response.length = static_cast<unsigned int>(length);
            }
        }
        keyboardPromptPending_ = false;
        keyboardPromptEcho_ = false;
        keyboardResponseReady_ = false;
        SecureClear(keyboardPrompt_);
        SecureClear(keyboardResponse_);
        return accepted;
    }

    bool AuthListContains(const std::string &authList, const std::string &method) const
    {
        size_t start = 0;
        while (start <= authList.size()) {
            const size_t comma = authList.find(',', start);
            const size_t end = comma == std::string::npos ? authList.size() : comma;
            if (authList.compare(start, end - start, method) == 0) {
                return true;
            }
            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1U;
        }
        return false;
    }

    std::vector<std::string> AuthMethodsFor(const std::string &kind, const std::string &authList) const
    {
        std::vector<std::string> methods;
        const auto addIfAllowed = [this, &authList, &methods](const std::string &method) {
            if ((authList.empty() || AuthListContains(authList, method)) &&
                std::find(methods.begin(), methods.end(), method) == methods.end()) {
                methods.push_back(method);
            }
        };
        if (kind == "private-key") {
            addIfAllowed("publickey");
        } else if (kind == "keyboard-interactive") {
            addIfAllowed("keyboard-interactive");
        } else {
            addIfAllowed("password");
        }
        return methods;
    }

    std::string LastError(int operationCode) const
    {
        if (session_ == nullptr) {
            return "SSH session unavailable";
        }
        if (operationCode == LIBSSH2_ERROR_TIMEOUT) {
            return "SSH operation timed out";
        }
        char *message = nullptr;
        int length = 0;
        const int code = libssh2_session_last_error(session_, &message, &length, 0);
        if (code == LIBSSH2_ERROR_TIMEOUT) {
            return "SSH operation timed out";
        }
        std::ostringstream output;
        output << "libssh2 error " << code;
        if (message != nullptr && length > 0) {
            output << ": " << std::string(message, static_cast<size_t>(length));
        }
        return output.str();
    }

    std::string LastError() const
    {
        return lastHandleTimedOut_ ? "SSH operation timed out" : LastError(0);
    }

    std::string LastSftpError(int operationCode = LIBSSH2_ERROR_SFTP_PROTOCOL) const
    {
        if (sftp_ != nullptr && (operationCode == LIBSSH2_ERROR_SFTP_PROTOCOL ||
            libssh2_session_last_errno(session_) == LIBSSH2_ERROR_SFTP_PROTOCOL)) {
            return "SFTP status " + std::to_string(libssh2_sftp_last_error(sftp_));
        }
        return LastError(operationCode);
    }

    bool WaitSocket(const std::chrono::steady_clock::time_point &deadline,
        int maximumWaitMilliseconds = 250)
    {
        if (stopping_ || socket_ < 0 || session_ == nullptr) {
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return false;
        }
        int events = 0;
        const int directions = libssh2_session_block_directions(session_);
        if ((directions & LIBSSH2_SESSION_BLOCK_INBOUND) != 0) {
            events |= POLLIN;
        }
        if ((directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) != 0) {
            events |= POLLOUT;
        }
        if (events == 0) {
            events = POLLIN | POLLOUT;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const int timeout = static_cast<int>(
            std::min<int64_t>(remaining.count(), maximumWaitMilliseconds));
        pollfd descriptor {socket_, static_cast<short>(events), 0};
        return poll(&descriptor, 1, timeout) >= 0;
    }

    template<typename Operation>
    int Repeat(Operation operation)
    {
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(OPERATION_TIMEOUT_MS);
        int result;
        do {
            result = operation();
            if (result == LIBSSH2_ERROR_EAGAIN && !WaitSocket(deadline)) {
                return LIBSSH2_ERROR_TIMEOUT;
            }
        } while (result == LIBSSH2_ERROR_EAGAIN);
        return result;
    }

    template<typename Handle, typename Operation>
    Handle *RepeatHandle(Operation operation)
    {
        lastHandleTimedOut_ = false;
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(OPERATION_TIMEOUT_MS);
        Handle *handle = nullptr;
        do {
            handle = operation();
            if (handle == nullptr && libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN &&
                !WaitSocket(deadline)) {
                lastHandleTimedOut_ = true;
                return nullptr;
            }
        } while (handle == nullptr && libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN);
        return handle;
    }

    void PumpPty()
    {
        if (channel_ == nullptr || connectionLost_ || pendingPty_.size() >= MAX_PENDING_PTY_BYTES) {
            return;
        }
        std::array<char, 16384> buffer {};
        for (;;) {
            const ssize_t count = libssh2_channel_read_ex(channel_, 0, buffer.data(), buffer.size());
            if (count > 0) {
                const size_t available = MAX_PENDING_PTY_BYTES - pendingPty_.size();
                const size_t accepted = std::min<size_t>(static_cast<size_t>(count), available);
                pendingPty_.insert(pendingPty_.end(), buffer.begin(), buffer.begin() + accepted);
                if (accepted < static_cast<size_t>(count)) {
                    break;
                }
                continue;
            }
            if ((count < 0 && count != LIBSSH2_ERROR_EAGAIN) || libssh2_channel_eof(channel_)) {
                connectionLost_ = true;
            }
            break;
        }
    }

    void PumpKeepalive()
    {
        const auto now = std::chrono::steady_clock::now();
        if (!authenticated_ || connectionLost_ || now < nextKeepalive_) {
            return;
        }
        int secondsToNext = SSH_KEEPALIVE_SECONDS;
        const int result = libssh2_keepalive_send(session_, &secondsToNext);
        if (result != 0 && result != LIBSSH2_ERROR_EAGAIN) {
            connectionLost_ = true;
        }
        nextKeepalive_ = now + std::chrono::seconds(result == LIBSSH2_ERROR_EAGAIN ? 1 :
            std::max(1, secondsToNext));
    }

    NativeResult Connect(const Command &command)
    {
        if (session_ != nullptr) {
            return NativeResult::Error("session already connected");
        }
        socket_ = ConnectSocket(command.first, static_cast<uint16_t>(command.firstNumber), stopping_);
        if (stopping_) { return NativeResult::Error("metrics cancelled"); }
        if (socket_ < 0) {
            return NativeResult::Error("TCP connection failed");
        }
        session_ = libssh2_session_init_ex(nullptr, nullptr, nullptr, this);
        if (session_ == nullptr) {
            close(socket_);
            socket_ = -1;
            return NativeResult::Error("libssh2 session initialization failed");
        }
        libssh2_session_set_blocking(session_, 0);
        static constexpr char KEX[] = "curve25519-sha256,curve25519-sha256@libssh.org,"
            "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
            "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
            "diffie-hellman-group14-sha256";
        static constexpr char HOSTKEY[] = "ssh-ed25519,ecdsa-sha2-nistp256,"
            "ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256";
        static constexpr char CIPHER[] = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
            "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr";
        static constexpr char MAC[] = "hmac-sha2-256-etm@openssh.com,"
            "hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512";
        // 旧算法只追加到显式启用兼容模式的会话，现代算法仍优先。
        const std::string kex = command.flag ? std::string(KEX) + ",diffie-hellman-group14-sha1" : KEX;
        const std::string hostkey = command.flag ? std::string(HOSTKEY) + ",ssh-rsa" : HOSTKEY;
        const std::string mac = command.flag ? std::string(MAC) + ",hmac-sha1" : MAC;
        int result = libssh2_session_method_pref(session_, LIBSSH2_METHOD_KEX, kex.c_str());
        result = result == 0 ? libssh2_session_method_pref(session_, LIBSSH2_METHOD_HOSTKEY, hostkey.c_str()) : result;
        result = result == 0 ? libssh2_session_method_pref(session_, LIBSSH2_METHOD_CRYPT_CS, CIPHER) : result;
        result = result == 0 ? libssh2_session_method_pref(session_, LIBSSH2_METHOD_CRYPT_SC, CIPHER) : result;
        result = result == 0 ? libssh2_session_method_pref(session_, LIBSSH2_METHOD_MAC_CS, mac.c_str()) : result;
        result = result == 0 ? libssh2_session_method_pref(session_, LIBSSH2_METHOD_MAC_SC, mac.c_str()) : result;
        result = result == 0 ? libssh2_session_method_pref(session_, LIBSSH2_METHOD_SIGN_ALGO, hostkey.c_str()) : result;
        result = result == 0 ? libssh2_session_method_pref(session_, LIBSSH2_METHOD_COMP_CS, "none") : result;
        result = result == 0 ? libssh2_session_method_pref(session_, LIBSSH2_METHOD_COMP_SC, "none") : result;
        if (result == 0) {
            result = Repeat([this]() { return libssh2_session_handshake(session_, socket_); });
        }
        if (result != 0) {
            return NativeResult::Error(LastError(result));
        }
        const unsigned char *fingerprint = reinterpret_cast<const unsigned char *>(
            libssh2_hostkey_hash(session_, LIBSSH2_HOSTKEY_HASH_SHA256));
        if (fingerprint == nullptr) {
            return NativeResult::Error("server host key fingerprint unavailable");
        }
        if (!command.second.empty() && command.second != "SHA256:" + Base64(fingerprint, 32U)) {
            return NativeResult::Error("metrics host key mismatch");
        }
        const char *algorithm = libssh2_session_methods(session_, LIBSSH2_METHOD_HOSTKEY);
        std::ostringstream output;
        output << "{\"sessionId\":" << id_
               << ",\"fingerprint\":\"SHA256:" << Base64(fingerprint, 32U)
               << "\",\"hostKeyAlgorithm\":\"" << JsonEscape(algorithm == nullptr ? "unknown" : algorithm)
               << "\",\"kex\":\"" << JsonEscape(SafeMethod(session_, LIBSSH2_METHOD_KEX))
               << "\",\"cipher\":\"" << JsonEscape(SafeMethod(session_, LIBSSH2_METHOD_CRYPT_CS))
               << "\",\"mac\":\"" << JsonEscape(SafeMethod(session_, LIBSSH2_METHOD_MAC_CS))
               << "\"}";
        return NativeResult::String(output.str());
    }

    NativeResult Authenticate(Command &command)
    {
        if (session_ == nullptr || !hostKeyAccepted_) {
            SecureClear(command.secret);
            SecureClear(command.third);
            return NativeResult::Error("host key has not been accepted");
        }
        const char *authListRaw = nullptr;
        Repeat([this, &command, &authListRaw]() {
            authListRaw = libssh2_userauth_list(session_, command.first.c_str(),
                static_cast<unsigned int>(command.first.size()));
            return authListRaw == nullptr && libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN ?
                LIBSSH2_ERROR_EAGAIN : 0;
        });
        const std::string authList = authListRaw == nullptr ? "" : authListRaw;
        const std::vector<std::string> methods = AuthMethodsFor(command.second, authList);
        if (methods.empty()) {
            SecureClear(command.secret);
            SecureClear(command.third);
            std::string message = "Authentication method not supported by server";
            if (!authList.empty()) {
                message.append(" | server methods: ").append(authList);
            }
            return NativeResult::Error(message);
        }
        int result = LIBSSH2_ERROR_METHOD_NOT_SUPPORTED;
        std::string attempted;
        for (const std::string &method : methods) {
            if (!attempted.empty()) {
                attempted.append(",");
            }
            attempted.append(method);
            if (method == "password") {
                // 空密码表示尚未提供凭据，服务端允许密码认证时才提示输入。
                if (command.secret.empty()) {
                    if (libssh2_userauth_authenticated(session_) != 0) {
                        result = 0;
                        break;
                    }
                    SecureClear(command.third);
                    return AuthListContains(authList, "password") ? NativeResult::Boolean(false) :
                        NativeResult::Error("Server password authentication is unavailable");
                }
                result = Repeat([this, &command]() {
                    return libssh2_userauth_password_ex(session_, command.first.c_str(),
                        static_cast<unsigned int>(command.first.size()), command.secret.c_str(),
                        static_cast<unsigned int>(command.secret.size()), DeclinePasswordChange);
                });
            } else if (method == "publickey") {
                result = Repeat([this, &command]() {
                    const char *passphrase = command.third.empty() ? nullptr : command.third.c_str();
                    return libssh2_userauth_publickey_frommemory(session_, command.first.c_str(),
                        command.first.size(), nullptr, 0, command.secret.c_str(), command.secret.size(), passphrase);
                });
            } else if (method == "keyboard-interactive") {
                PrepareKeyboardInteractive();
                do {
                    result = libssh2_userauth_keyboard_interactive_ex(session_, command.first.c_str(),
                        static_cast<unsigned int>(command.first.size()), KeyboardInteractiveCallback);
                    if (result == LIBSSH2_ERROR_EAGAIN) {
                        const auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(OPERATION_TIMEOUT_MS);
                        if (!WaitSocket(deadline)) {
                            result = LIBSSH2_ERROR_TIMEOUT;
                        }
                    }
                } while (result == LIBSSH2_ERROR_EAGAIN);
                bool keyboardTimedOut = false;
                {
                    std::lock_guard<std::mutex> lock(keyboardMutex_);
                    keyboardTimedOut = keyboardTimedOut_;
                }
                CancelKeyboardInteractive();
                if (keyboardTimedOut) {
                    SecureClear(command.secret);
                    SecureClear(command.third);
                    return NativeResult::Error("Keyboard-interactive response timed out");
                }
            } else {
                result = LIBSSH2_ERROR_METHOD_NOT_SUPPORTED;
            }
            if (result == 0 && libssh2_userauth_authenticated(session_) != 0) {
                break;
            }
        }
        SecureClear(command.secret);
        SecureClear(command.third);
        if (result != 0 || libssh2_userauth_authenticated(session_) == 0) {
            std::string message = LastError(result);
            if (message == "libssh2 error 0" || message.find("libssh2 error 0:") == 0) {
                message = "Authentication failed";
            }
            if (!authList.empty()) {
                message.append(" | server methods: ").append(authList);
            }
            if (!attempted.empty()) {
                message.append(" | attempted: ").append(attempted);
            }
            return NativeResult::Error(message);
        }
        authenticated_ = true;
        libssh2_keepalive_config(session_, 1, SSH_KEEPALIVE_SECONDS);
        nextKeepalive_ = std::chrono::steady_clock::now() + std::chrono::seconds(SSH_KEEPALIVE_SECONDS);
        return NativeResult::Boolean(true);
    }

    NativeResult OpenPty(const Command &command)
    {
        if (!authenticated_) {
            return NativeResult::Error("session is not authenticated");
        }
        if (channel_ == nullptr) {
            channel_ = RepeatHandle<LIBSSH2_CHANNEL>([this]() { return libssh2_channel_open_session(session_); });
        }
        if (channel_ == nullptr) {
            return NativeResult::Error(LastError());
        }
        const std::string terminal = command.first.empty() ? "xterm-256color" : command.first;
        int result = Repeat([this, &terminal, &command]() {
            return libssh2_channel_request_pty_ex(channel_, terminal.c_str(),
                static_cast<unsigned int>(terminal.size()), nullptr, 0,
                static_cast<int>(command.firstNumber), static_cast<int>(command.secondNumber), 0, 0);
        });
        if (result == 0) {
            result = Repeat([this]() { return libssh2_channel_shell(channel_); });
        }
        if (result != 0) {
            return NativeResult::Error(LastError(result));
        }
        return NativeResult::Boolean(true);
    }

    NativeResult Write(const Command &command)
    {
        if (channel_ == nullptr) {
            return NativeResult::Error("PTY is not open");
        }
        size_t offset = 0;
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(OPERATION_TIMEOUT_MS);
        while (offset < command.bytes.size()) {
            const ssize_t count = libssh2_channel_write_ex(channel_, 0,
                reinterpret_cast<const char *>(command.bytes.data() + offset), command.bytes.size() - offset);
            if (count > 0) {
                offset += static_cast<size_t>(count);
            } else if (count == LIBSSH2_ERROR_EAGAIN &&
                WaitSocket(deadline, INTERACTIVE_WRITE_WAIT_SLICE_MS)) {
                PumpPty();
            } else {
                return NativeResult::Error(count == LIBSSH2_ERROR_EAGAIN ?
                    LastError(LIBSSH2_ERROR_TIMEOUT) : LastError(static_cast<int>(count)));
            }
        }
        return NativeResult::Integer(static_cast<int64_t>(offset));
    }

    NativeResult Read(const Command &command)
    {
        PumpPty();
        if (connectionLost_ && pendingPty_.empty()) {
            return NativeResult::Error("SSH connection closed");
        }
        const size_t count = std::min<size_t>(static_cast<size_t>(command.firstNumber), pendingPty_.size());
        std::vector<uint8_t> output;
        output.reserve(count);
        for (size_t index = 0; index < count; ++index) {
            output.push_back(pendingPty_.front());
            pendingPty_.pop_front();
        }
        return NativeResult::Bytes(std::move(output));
    }

    NativeResult Resize(const Command &command)
    {
        if (channel_ == nullptr) {
            return NativeResult::Error("PTY is not open");
        }
        const int result = Repeat([this, &command]() {
            return libssh2_channel_request_pty_size_ex(channel_,
                static_cast<int>(command.firstNumber), static_cast<int>(command.secondNumber), 0, 0);
        });
        return result == 0 ? NativeResult::Boolean(true) : NativeResult::Error(LastError(result));
    }

    NativeResult CollectRemoteMetrics()
    {
        if (!metricsOnly_) {
            return NativeResult::Error("metrics requires an isolated connection");
        }
        if (!authenticated_) {
            return NativeResult::Error("session is not authenticated");
        }
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(REMOTE_METRICS_TIMEOUT_MS);
        LIBSSH2_CHANNEL *metrics = nullptr;
        do {
            metrics = libssh2_channel_open_session(session_);
            if (metrics == nullptr && libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN) {
                PumpPty();
            }
        } while (metrics == nullptr && libssh2_session_last_errno(session_) == LIBSSH2_ERROR_EAGAIN &&
            WaitSocket(deadline));
        if (metrics == nullptr) {
            return NativeResult::Error(std::chrono::steady_clock::now() >= deadline ?
                "remote metrics timed out" : LastError());
        }
        const auto closeMetrics = [this, metrics]() {
            const auto closeDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
            int result = 0;
            do {
                result = libssh2_channel_close(metrics);
                if (result == LIBSSH2_ERROR_EAGAIN) {
                    PumpPty();
                }
            } while (result == LIBSSH2_ERROR_EAGAIN && WaitSocket(closeDeadline));
            do {
                result = libssh2_channel_free(metrics);
                if (result == LIBSSH2_ERROR_EAGAIN) {
                    PumpPty();
                }
            } while (result == LIBSSH2_ERROR_EAGAIN && WaitSocket(closeDeadline));
        };
        int result = 0;
        do {
            result = libssh2_channel_exec(metrics, REMOTE_METRICS_COMMAND);
            if (result == LIBSSH2_ERROR_EAGAIN) {
                PumpPty();
            }
        } while (result == LIBSSH2_ERROR_EAGAIN && WaitSocket(deadline));
        if (result != 0) {
            closeMetrics();
            return NativeResult::Error(result == LIBSSH2_ERROR_EAGAIN ?
                "remote metrics timed out" : LastError(result));
        }
        std::string output;
        size_t totalRead = 0;
        std::array<char, 4096> buffer {};
        bool complete = false;
        while (!complete && !stopping_ && std::chrono::steady_clock::now() < deadline) {
            bool progressed = false;
            for (int stream = 0; stream <= 1; ++stream) {
                const ssize_t count = libssh2_channel_read_ex(metrics, stream, buffer.data(), buffer.size());
                if (count > 0) {
                    progressed = true;
                    totalRead += static_cast<size_t>(count);
                    if (totalRead > MAX_REMOTE_METRICS_BYTES) {
                        closeMetrics();
                        return NativeResult::Error("remote metrics output is too large");
                    }
                    if (stream == 0) {
                        output.append(buffer.data(), static_cast<size_t>(count));
                    }
                } else if (count < 0 && count != LIBSSH2_ERROR_EAGAIN) {
                    closeMetrics();
                    return NativeResult::Error(LastError(static_cast<int>(count)));
                }
            }
            complete = !progressed && libssh2_channel_eof(metrics) != 0;
            PumpPty();
            if (!complete && !progressed && !WaitSocket(deadline)) {
                break;
            }
        }
        closeMetrics();
        if (!complete) {
            return NativeResult::Error("remote metrics timed out");
        }
        return NativeResult::String(output);
    }

    NativeResult OpenSftp()
    {
        if (!authenticated_) {
            return NativeResult::Error("session is not authenticated");
        }
        if (sftp_ == nullptr) {
            sftp_ = RepeatHandle<LIBSSH2_SFTP>([this]() { return libssh2_sftp_init(session_); });
        }
        if (sftp_ == nullptr) {
            return NativeResult::Error(LastError());
        }
        std::array<char, 4096> home {};
        const ssize_t count = Repeat([this, &home]() {
            return static_cast<int>(libssh2_sftp_realpath(sftp_, ".", home.data(), home.size()));
        });
        return count >= 0 ? NativeResult::String(std::string(home.data(), static_cast<size_t>(count))) :
            NativeResult::Error(LastError(static_cast<int>(count)));
    }

    bool CheckDeleteDirectory(const std::string &path)
    {
        if (path != "/" && !IsSafeSftpDeletePath(path)) {
            return false;
        }
        LIBSSH2_SFTP_ATTRIBUTES attributes {};
        const int statResult = Repeat([this, &path, &attributes]() {
            return libssh2_sftp_lstat(sftp_, path.c_str(), &attributes);
        });
        if (statResult != 0 || (attributes.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) == 0U ||
            !LIBSSH2_SFTP_S_ISDIR(attributes.permissions)) {
            return false;
        }
        std::array<char, 4097> canonical {};
        const int count = Repeat([this, &path, &canonical]() {
            return libssh2_sftp_realpath(sftp_, path.c_str(), canonical.data(), canonical.size());
        });
        return count > 0 && static_cast<size_t>(count) < canonical.size() &&
            std::string(canonical.data(), static_cast<size_t>(count)) == path;
    }

    NativeResult ListDirectory(const Command &command)
    {
        if (sftp_ == nullptr) {
            return NativeResult::Error("SFTP is not open");
        }
        if (command.flag && (!IsSafeSftpDeletePath(command.first) || !CheckDeleteDirectory(command.first))) {
            return NativeResult::Error("SFTP delete directory boundary check failed");
        }
        LIBSSH2_SFTP_HANDLE *directory = RepeatHandle<LIBSSH2_SFTP_HANDLE>([this, &command]() {
            return libssh2_sftp_opendir(sftp_, command.first.c_str());
        });
        if (directory == nullptr) {
            return NativeResult::Error(LastError());
        }
        std::ostringstream json;
        json << '[';
        bool firstEntry = true;
        size_t entryCount = 0;
        for (;;) {
            std::array<char, 4096> name {};
            std::array<char, 4096> longEntry {};
            LIBSSH2_SFTP_ATTRIBUTES attributes {};
            const int count = Repeat([directory, &name, &longEntry, &attributes]() {
                return static_cast<int>(libssh2_sftp_readdir_ex(directory, name.data(), name.size(),
                    longEntry.data(), longEntry.size(), &attributes));
            });
            if (count == 0) {
                break;
            }
            if (count < 0) {
                Repeat([directory]() { return libssh2_sftp_closedir(directory); });
                return NativeResult::Error(LastError(count));
            }
            const std::string entryName(name.data(), static_cast<size_t>(count));
            if (entryName == "." || entryName == "..") {
                continue;
            }
            if (command.flag && (++entryCount > 10000 ||
                !IsSafeSftpDeletePath(command.first + "/" + entryName))) {
                Repeat([directory]() { return libssh2_sftp_closedir(directory); });
                return NativeResult::Error("SFTP delete listing exceeds safe limits");
            }
            if (!firstEntry) {
                json << ',';
            }
            firstEntry = false;
            const bool isDirectory = (attributes.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) != 0U &&
                LIBSSH2_SFTP_S_ISDIR(attributes.permissions);
            const bool isSymbolicLink = (attributes.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) != 0U &&
                LIBSSH2_SFTP_S_ISLNK(attributes.permissions);
            json << "{\"name\":\"" << JsonEscape(entryName) << "\",\"isDirectory\":"
                 << (isDirectory ? "true" : "false") << ",\"isSymbolicLink\":"
                 << (isSymbolicLink ? "true" : "false") << ",\"size\":"
                 << ((attributes.flags & LIBSSH2_SFTP_ATTR_SIZE) != 0U ? attributes.filesize : 0U)
                 << ",\"modified\":"
                 << ((attributes.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) != 0U ? attributes.mtime : 0U)
                 << '}';
        }
        Repeat([directory]() { return libssh2_sftp_closedir(directory); });
        json << ']';
        return NativeResult::String(json.str());
    }

    // 每个传输持有独立的 SCP 通道；文件内容不经过 SFTP。
    NativeResult BeginScp(const Command &command)
    {
        if (!authenticated_ || sftp_ == nullptr || command.first.empty() || command.first.front() != '/' ||
            command.first.find_first_of("\r\n") != std::string::npos || command.first.find(char(0)) != std::string::npos ||
            !IsSafeSftpDeletePath(command.first)) {
            return NativeResult::Error("Invalid SCP path or session");
        }
        if (libssh2_session_flag(session_, LIBSSH2_FLAG_QUOTE_PATHS, 1) != 0) {
            return NativeResult::Error("SCP path quoting unavailable");
        }
        std::string staging;
        if (command.flag) {
            std::array<unsigned char, 16> nonce {};
            if (getentropy(nonce.data(), nonce.size()) != 0) { return NativeResult::Error("SCP temporary name unavailable"); }
            staging = command.first.substr(0, command.first.rfind('/') + 1) + ".homoxterm-upload-";
            static constexpr char HEX[] = "0123456789abcdef";
            for (auto byte : nonce) { staging += HEX[byte >> 4]; staging += HEX[byte & 15]; }
            auto file = RepeatHandle<LIBSSH2_SFTP_HANDLE>([&]() {
                return libssh2_sftp_open(sftp_, staging.c_str(), LIBSSH2_FXF_CREAT | LIBSSH2_FXF_EXCL | LIBSSH2_FXF_WRITE, 0600);
            });
            if (!file) { return NativeResult::Error(LastSftpError()); }
            if (Repeat([&]() { return libssh2_sftp_close_handle(file); }) != 0) {
                UnlinkScpStaging(staging);
                return NativeResult::Error("SCP temporary file unavailable");
            }
        }
        libssh2_struct_stat info {};
        auto channel = RepeatHandle<LIBSSH2_CHANNEL>([&]() {
            return command.flag ? libssh2_scp_send64(session_, staging.c_str(), 0600, command.firstNumber, 0, 0) :
                libssh2_scp_recv2(session_, command.first.c_str(), &info);
        });
        if (!channel) {
            const auto error = NativeResult::Error(LastError());
            UnlinkScpStaging(staging);
            return error;
        }
        const uint64_t handle = nextScpHandle_++;
        scpTransfers_.emplace(handle, ScpTransfer{channel, command.flag ? command.firstNumber :
            static_cast<uint64_t>(info.st_size), command.flag, command.first, staging});
        return NativeResult::Integer(static_cast<int64_t>(handle));
    }

    NativeResult StepScp(const Command &command)
    {
        auto it = scpTransfers_.find(command.firstNumber);
        if (it == scpTransfers_.end()) { return NativeResult::Error("Unknown SCP transfer"); }
        auto &transfer = it->second;
        if (transfer.remaining == 0) { return NativeResult::Integer(0); }
        std::array<char, 64 * 1024> buffer;
        const int fd = static_cast<int>(command.secondNumber);
        const size_t size = std::min<uint64_t>(transfer.remaining, buffer.size());
        const int count = transfer.upload ? static_cast<int>(read(fd, buffer.data(), size)) :
            Repeat([&]() {
                const int n = static_cast<int>(libssh2_channel_read(transfer.channel, buffer.data(), size));
                return n == 0 && !libssh2_channel_eof(transfer.channel) ? LIBSSH2_ERROR_EAGAIN : n;
            });
        if (count <= 0) { return NativeResult::Error("Unexpected end of SCP file"); }
        int offset = 0;
        while (offset < count) {
            const int n = transfer.upload ?
                Repeat([&]() { return static_cast<int>(libssh2_channel_write(transfer.channel,
                    buffer.data() + offset, count - offset)); }) :
                static_cast<int>(write(fd, buffer.data() + offset, count - offset));
            if (n <= 0) { return NativeResult::Error("SCP file write failed"); }
            offset += n;
        }
        transfer.remaining -= count;
        return NativeResult::Integer(count);
    }

    NativeResult EndScp(const Command &command)
    {
        auto it = scpTransfers_.find(command.firstNumber);
        if (it == scpTransfers_.end()) { return NativeResult::Error("Unknown SCP transfer"); }
        const ScpTransfer transfer = it->second;
        scpTransfers_.erase(it);
        auto channel = transfer.channel;
        bool ok = command.flag && transfer.remaining == 0;
        // 文件结束标志和对端确认都是一个零字节，传输方向决定先后顺序。
        char ack = 0;
        auto readAck = [&]() { return Repeat([&]() {
            return static_cast<int>(libssh2_channel_read(channel, &ack, 1)); }) == 1 && ack == 0; };
        auto writeAck = [&]() { return Repeat([&]() {
            return static_cast<int>(libssh2_channel_write(channel, "", 1)); }) == 1; };
        if (ok) { ok = transfer.upload ? (writeAck() && readAck()) : (readAck() && writeAck()); }
        if (ok) { ok = Repeat([&]() { return libssh2_channel_send_eof(channel); }) == 0; }
        if (ok) { ok = Repeat([&]() { return libssh2_channel_wait_eof(channel); }) == 0; }
        const int closed = Repeat([&]() { return libssh2_channel_close(channel); });
        ok = ok && closed == 0 && libssh2_channel_get_exit_status(channel) == 0;
        Repeat([&]() { return libssh2_channel_free(channel); });
        if (ok && transfer.upload) {
            int rc = Repeat([&]() { return libssh2_sftp_posix_rename(sftp_, transfer.staging.c_str(), transfer.path.c_str()); });
            if (rc == LIBSSH2_ERROR_METHOD_NOT_SUPPORTED ||
                (rc == LIBSSH2_ERROR_SFTP_PROTOCOL && libssh2_sftp_last_error(sftp_) == LIBSSH2_FX_OP_UNSUPPORTED)) {
                rc = Repeat([&]() { return libssh2_sftp_rename(sftp_, transfer.staging.c_str(), transfer.path.c_str()); });
            }
            ok = rc == 0;
        }
        if (!ok) { UnlinkScpStaging(transfer.staging); }
        return ok || !command.flag ? NativeResult::Boolean(true) : NativeResult::Error("SCP completion failed");
    }

    void UnlinkScpStaging(const std::string &path)
    {
        if (!path.empty() && sftp_) { Repeat([&]() { return libssh2_sftp_unlink(sftp_, path.c_str()); }); }
    }

    NativeResult ReadFileChunk(const Command &command)
    {
        if (sftp_ == nullptr) {
            return NativeResult::Error("SFTP is not open");
        }
        const size_t requested = std::min<size_t>(static_cast<size_t>(command.secondNumber), MAX_TRANSFER_CHUNK);
        LIBSSH2_SFTP_HANDLE *file = RepeatHandle<LIBSSH2_SFTP_HANDLE>([this, &command]() {
            return libssh2_sftp_open(sftp_, command.first.c_str(), LIBSSH2_FXF_READ, 0);
        });
        if (file == nullptr) {
            return NativeResult::Error(LastSftpError());
        }
        libssh2_sftp_seek64(file, command.firstNumber);
        std::vector<uint8_t> output(requested);
        const int count = Repeat([file, &output]() {
            return static_cast<int>(libssh2_sftp_read(file,
                reinterpret_cast<char *>(output.data()), output.size()));
        });
        Repeat([file]() { return libssh2_sftp_close_handle(file); });
        if (count < 0) {
            return NativeResult::Error(LastSftpError(count));
        }
        output.resize(static_cast<size_t>(count));
        return NativeResult::Bytes(std::move(output));
    }

    NativeResult WriteFileChunk(const Command &command)
    {
        if (sftp_ == nullptr) {
            return NativeResult::Error("SFTP is not open");
        }
        unsigned long flags = LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT;
        if (command.flag) {
            flags |= LIBSSH2_FXF_TRUNC;
        }
        LIBSSH2_SFTP_HANDLE *file = RepeatHandle<LIBSSH2_SFTP_HANDLE>([this, &command, flags]() {
            return libssh2_sftp_open(sftp_, command.first.c_str(), flags,
                LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR);
        });
        if (file == nullptr) {
            return NativeResult::Error(LastSftpError());
        }
        libssh2_sftp_seek64(file, command.firstNumber);
        size_t offset = 0;
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(OPERATION_TIMEOUT_MS);
        while (offset < command.bytes.size()) {
            const ssize_t count = libssh2_sftp_write(file,
                reinterpret_cast<const char *>(command.bytes.data() + offset), command.bytes.size() - offset);
            if (count > 0) {
                offset += static_cast<size_t>(count);
            } else if (count == LIBSSH2_ERROR_EAGAIN && WaitSocket(deadline)) {
                PumpPty();
            } else {
                Repeat([file]() { return libssh2_sftp_close_handle(file); });
                return NativeResult::Error(count == LIBSSH2_ERROR_EAGAIN ?
                    LastError(LIBSSH2_ERROR_TIMEOUT) : LastSftpError(static_cast<int>(count)));
            }
        }
        Repeat([file]() { return libssh2_sftp_close_handle(file); });
        return NativeResult::Integer(static_cast<int64_t>(offset));
    }

    NativeResult RemoveEntry(const Command &command)
    {
        if (sftp_ == nullptr) {
            return NativeResult::Error("SFTP is not open");
        }
        if (!IsSafeSftpDeletePath(command.first)) {
            return NativeResult::Error("Unsafe SFTP delete path");
        }
        const size_t separator = command.first.rfind('/');
        const std::string parent = separator == 0 ? "/" : command.first.substr(0, separator);
        if (!CheckDeleteDirectory(parent) || (command.flag && !CheckDeleteDirectory(command.first))) {
            return NativeResult::Error("SFTP delete boundary check failed");
        }
        const int result = command.flag ? Repeat([this, &command]() {
            return libssh2_sftp_rmdir_ex(sftp_, command.first.c_str(),
                static_cast<unsigned int>(command.first.size()));
        }) : Repeat([this, &command]() {
            return libssh2_sftp_unlink_ex(sftp_, command.first.c_str(),
                static_cast<unsigned int>(command.first.size()));
        });
        return result == 0 ? NativeResult::Boolean(true) : NativeResult::Error(LastError(result));
    }

    NativeResult CreateDirectory(const Command &command)
    {
        if (sftp_ == nullptr) {
            return NativeResult::Error("SFTP is not open");
        }
        const long mode = LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IXGRP |
            LIBSSH2_SFTP_S_IROTH | LIBSSH2_SFTP_S_IXOTH;
        const int result = Repeat([this, &command]() {
            return libssh2_sftp_mkdir_ex(sftp_, command.first.c_str(),
                static_cast<unsigned int>(command.first.size()), mode);
        });
        return result == 0 ? NativeResult::Boolean(true) : NativeResult::Error(LastError(result));
    }

    NativeResult Execute(Command &command)
    {
        switch (command.type) {
            case CommandType::Connect: return Connect(command);
            case CommandType::AcceptHostKey:
                hostKeyAccepted_ = command.flag;
                return NativeResult::Boolean(command.flag);
            case CommandType::Authenticate: return Authenticate(command);
            case CommandType::OpenPty: return OpenPty(command);
            case CommandType::Write: return Write(command);
            case CommandType::Read: return Read(command);
            case CommandType::Resize: return Resize(command);
            case CommandType::OpenSftp: return OpenSftp();
            case CommandType::ListDirectory: return ListDirectory(command);
            case CommandType::BeginScp: return BeginScp(command);
            case CommandType::StepScp: return StepScp(command);
            case CommandType::EndScp: return EndScp(command);
            case CommandType::ReadFileChunk: return ReadFileChunk(command);
            case CommandType::WriteFileChunk: return WriteFileChunk(command);
            case CommandType::CreateDirectory: return CreateDirectory(command);
            case CommandType::RemoveEntry: return RemoveEntry(command);
            case CommandType::CollectRemoteMetrics: return CollectRemoteMetrics();
            case CommandType::Disconnect:
                stopping_ = true;
                return NativeResult::Boolean(true);
        }
        return NativeResult::Error("unknown native session command");
    }

    void Cleanup()
    {
        for (const auto &entry : scpTransfers_) {
            Repeat([&]() { return libssh2_channel_free(entry.second.channel); });
            UnlinkScpStaging(entry.second.staging);
        }
        scpTransfers_.clear();
        CancelKeyboardInteractive();
        if (sftp_ != nullptr) {
            Repeat([this]() { return libssh2_sftp_shutdown(sftp_); });
            sftp_ = nullptr;
        }
        if (channel_ != nullptr) {
            Repeat([this]() { return libssh2_channel_close(channel_); });
            libssh2_channel_free(channel_);
            channel_ = nullptr;
        }
        if (session_ != nullptr) {
            Repeat([this]() { return libssh2_session_disconnect(session_, "HomoXterm disconnect"); });
            libssh2_session_free(session_);
            session_ = nullptr;
        }
        if (socket_ >= 0) {
            close(socket_);
            socket_ = -1;
        }
        pendingPty_.clear();
    }

    void WorkerLoop()
    {
        for (;;) {
            std::unique_ptr<Command> command;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait_for(lock, std::chrono::milliseconds(20), [this]() {
                    return stopping_ || !commands_.empty();
                });
                if (!commands_.empty()) {
                    command = std::move(commands_.front());
                    commands_.pop_front();
                } else if (stopping_) {
                    break;
                }
            }
            if (command != nullptr) {
                NativeResult result = Execute(*command);
                command->completion.set_value(std::move(result));
            }
            PumpPty();
            PumpKeepalive();
            if (stopping_) {
                break;
            }
        }
        Cleanup();
        std::deque<std::unique_ptr<Command>> abandoned;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            abandoned.swap(commands_);
        }
        for (auto &command : abandoned) {
            SecureClear(command->secret);
            SecureClear(command->third);
            command->completion.set_value(NativeResult::Error("session disconnected"));
        }
    }

    uint64_t id_;
    const bool metricsOnly_;
    int socket_ = -1;
    LIBSSH2_SESSION *session_ = nullptr;
    LIBSSH2_CHANNEL *channel_ = nullptr;
    std::unordered_map<uint64_t, ScpTransfer> scpTransfers_;
    uint64_t nextScpHandle_ = 1;
    LIBSSH2_SFTP *sftp_ = nullptr;
    bool hostKeyAccepted_ = false;
    bool authenticated_ = false;
    bool connectionLost_ = false;
    std::chrono::steady_clock::time_point nextKeepalive_ {};
    std::atomic<bool> stopping_ {false};
    bool lastHandleTimedOut_ {false};
    std::deque<uint8_t> pendingPty_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<std::unique_ptr<Command>> commands_;
    std::mutex keyboardMutex_;
    std::condition_variable keyboardCondition_;
    std::string keyboardPrompt_;
    std::string keyboardResponse_;
    uint64_t keyboardPromptSequence_ = 0;
    bool keyboardPromptPending_ = false;
    bool keyboardPromptEcho_ = false;
    bool keyboardResponseReady_ = false;
    bool keyboardCancelled_ = false;
    bool keyboardTimedOut_ = false;
    std::thread worker_;
};

} // namespace

NativeResult NativeResult::Error(const std::string &message)
{
    NativeResult result;
    result.text = message;
    return result;
}

NativeResult NativeResult::String(const std::string &value)
{
    NativeResult result;
    result.ok = true;
    result.text = value;
    return result;
}

NativeResult NativeResult::Boolean(bool value)
{
    NativeResult result;
    result.ok = true;
    result.kind = NativeResultKind::Boolean;
    result.integer = value ? 1 : 0;
    return result;
}

NativeResult NativeResult::Integer(int64_t value)
{
    NativeResult result;
    result.ok = true;
    result.kind = NativeResultKind::Integer;
    result.integer = value;
    return result;
}

NativeResult NativeResult::Bytes(std::vector<uint8_t> value)
{
    NativeResult result;
    result.ok = true;
    result.kind = NativeResultKind::Bytes;
    result.bytes = std::move(value);
    return result;
}

class SshSessionManager::Impl {
public:
    Impl() : initialized_(EnsureSshLibraryInitialized()) {}

    ~Impl()
    {
        Shutdown();
    }

    std::shared_ptr<NativeSession> Find(uint64_t sessionId)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = sessions_.find(sessionId);
        return found == sessions_.end() ? nullptr : found->second;
    }

    NativeResult ReserveMetrics()
    {
        if (!initialized_) { return NativeResult::Error("libssh2 initialization failed"); }
        const uint64_t id = nextId_.fetch_add(1U);
        auto session = std::make_shared<NativeSession>(id, true);
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_.emplace(id, session);
        return NativeResult::Integer(static_cast<int64_t>(id));
    }

    NativeResult Connect(const std::string &host, uint16_t port,
        const std::string &fingerprint = "", bool metricsOnly = false, uint64_t reservedId = 0, bool legacy = false)
    {
        if (!initialized_) {
            return NativeResult::Error("libssh2 global initialization failed");
        }
        const uint64_t id = reservedId == 0 ? nextId_.fetch_add(1U) : reservedId;
        auto session = reservedId == 0 ? std::make_shared<NativeSession>(id, metricsOnly) : Find(id);
        if (session == nullptr || (reservedId != 0 && !session->IsMetricsOnly())) {
            return NativeResult::Error("metrics cancelled");
        }
        if (reservedId == 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            sessions_.emplace(id, session);
        }
        auto command = std::make_unique<Command>();
        command->type = CommandType::Connect;
        command->first = host;
        command->second = fingerprint;
        command->flag = legacy;
        command->firstNumber = port;
        NativeResult result = session->Invoke(std::move(command));
        if (!result.ok) {
            Remove(id);
        } else {
            result.integer = static_cast<int64_t>(id);
        }
        return result;
    }

    NativeResult Invoke(uint64_t id, std::unique_ptr<Command> command)
    {
        auto session = Find(id);
        return session == nullptr ? NativeResult::Error("unknown SSH session") :
            session->Invoke(std::move(command));
    }

    NativeResult KeyboardInteractivePrompt(uint64_t id)
    {
        auto session = Find(id);
        return session == nullptr ? NativeResult::Error("unknown SSH session") :
            session->KeyboardInteractivePrompt();
    }

    NativeResult RespondKeyboardInteractive(uint64_t id, const std::string &response)
    {
        auto session = Find(id);
        return session == nullptr ? NativeResult::Error("unknown SSH session") :
            session->RespondKeyboardInteractive(response);
    }

    NativeResult Remove(uint64_t id)
    {
        std::shared_ptr<NativeSession> session;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto found = sessions_.find(id);
            if (found == sessions_.end()) {
                return NativeResult::Boolean(true);
            }
            session = found->second;
            sessions_.erase(found);
        }
        session->Stop();
        return NativeResult::Boolean(true);
    }

    void Shutdown()
    {
        std::unordered_map<uint64_t, std::shared_ptr<NativeSession>> sessions;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            sessions.swap(sessions_);
        }
        for (auto &entry : sessions) {
            entry.second->Stop();
        }
    }

private:
    bool initialized_ = false;
    std::atomic<uint64_t> nextId_ {1U};
    std::mutex mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<NativeSession>> sessions_;
};

SshSessionManager &SshSessionManager::Instance()
{
    static SshSessionManager manager;
    return manager;
}

SshSessionManager::SshSessionManager() : impl_(new Impl()) {}
SshSessionManager::~SshSessionManager() { delete impl_; }

NativeResult SshSessionManager::Connect(const std::string &host, uint16_t port, bool legacy)
{
    return impl_->Connect(host, port, "", false, 0, legacy);
}

NativeResult SshSessionManager::ReserveMetrics() { return impl_->ReserveMetrics(); }

NativeResult SshSessionManager::CancelMetrics(uint64_t id)
{
    auto session = impl_->Find(id);
    if (session != nullptr) { session->CancelMetrics(); }
    return NativeResult::Boolean(true);
}

NativeResult SshSessionManager::ConnectMetrics(const std::string &host, uint16_t port,
    const std::string &fingerprint, const std::string &username, const std::string &kind,
    const std::string &secret, const std::string &passphrase, uint64_t reservedId, bool legacy)
{
    // Never replay keyboard-interactive responses or authenticate before pinning
    // this second connection to the identity already trusted by the main one.
    if (fingerprint.empty() || (kind != "password" && kind != "private-key")) {
        return NativeResult::Error("metrics authentication is unavailable");
    }
    NativeResult result = impl_->Connect(host, port, fingerprint, true, reservedId, legacy);
    if (!result.ok) { return result; }
    const uint64_t id = static_cast<uint64_t>(result.integer);
    result = AcceptHostKey(id, true);
    if (result.ok) { result = Authenticate(id, username, kind, secret, passphrase); }
    if (result.ok && result.integer == 0) {
        result = NativeResult::Error("metrics password is unavailable");
    }
    if (!result.ok) {
        impl_->Remove(id);
        return result;
    }
    return NativeResult::Integer(static_cast<int64_t>(id));
}

NativeResult SshSessionManager::AcceptHostKey(uint64_t id, bool accepted)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::AcceptHostKey;
    command->flag = accepted;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::Authenticate(uint64_t id, const std::string &username,
    const std::string &kind, const std::string &secret, const std::string &passphrase)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::Authenticate;
    command->first = username;
    command->second = kind;
    command->secret = secret;
    command->third = passphrase;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::KeyboardInteractivePrompt(uint64_t id)
{
    return impl_->KeyboardInteractivePrompt(id);
}

NativeResult SshSessionManager::RespondKeyboardInteractive(uint64_t id, const std::string &response)
{
    return impl_->RespondKeyboardInteractive(id, response);
}

NativeResult SshSessionManager::OpenPty(uint64_t id, const std::string &terminal,
    uint32_t columns, uint32_t rows)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::OpenPty;
    command->first = terminal;
    command->firstNumber = columns;
    command->secondNumber = rows;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::Write(uint64_t id, const std::vector<uint8_t> &bytes)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::Write;
    command->bytes = bytes;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::Read(uint64_t id, size_t maximumBytes)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::Read;
    command->firstNumber = maximumBytes;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::ResizePty(uint64_t id, uint32_t columns, uint32_t rows)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::Resize;
    command->firstNumber = columns;
    command->secondNumber = rows;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::OpenSftp(uint64_t id)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::OpenSftp;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::ListDirectory(uint64_t id, const std::string &path, bool forDeletion)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::ListDirectory;
    command->first = path;
    command->flag = forDeletion;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::BeginScp(uint64_t id, const std::string &path, bool upload, uint64_t size)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::BeginScp;
    command->first = path;
    command->flag = upload;
    command->firstNumber = size;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::StepScp(uint64_t id, uint64_t handle, int fd)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::StepScp;
    command->firstNumber = handle;
    command->secondNumber = fd;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::EndScp(uint64_t id, uint64_t handle, bool complete)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::EndScp;
    command->firstNumber = handle;
    command->flag = complete;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::ReadFileChunk(uint64_t id, const std::string &path,
    uint64_t offset, size_t maximumBytes)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::ReadFileChunk;
    command->first = path;
    command->firstNumber = offset;
    command->secondNumber = maximumBytes;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::WriteFileChunk(uint64_t id, const std::string &path,
    uint64_t offset, const std::vector<uint8_t> &bytes, bool truncate)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::WriteFileChunk;
    command->first = path;
    command->firstNumber = offset;
    command->bytes = bytes;
    command->flag = truncate;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::CreateDirectory(uint64_t id, const std::string &path)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::CreateDirectory;
    command->first = path;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::RemoveEntry(uint64_t id, const std::string &path, bool isDirectory)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::RemoveEntry;
    command->first = path;
    command->flag = isDirectory;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::CollectRemoteMetrics(uint64_t id)
{
    auto command = std::make_unique<Command>();
    command->type = CommandType::CollectRemoteMetrics;
    return impl_->Invoke(id, std::move(command));
}

NativeResult SshSessionManager::Disconnect(uint64_t id)
{
    return impl_->Remove(id);
}

void SshSessionManager::Shutdown()
{
    impl_->Shutdown();
}

} // namespace homoxterm
