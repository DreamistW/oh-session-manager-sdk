#include "ftps_tls.h"

#include <arpa/inet.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/ssl.h>
#include <psa/crypto.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace homoxterm {
namespace {
constexpr napi_type_tag TLS_TAG{0x485846545053544cULL, 0x53434c49454e5431ULL};
using Bytes = std::vector<unsigned char>;

// TLS 使用内存 BIO，TCP 由 ArkTS 管理。控制和数据连接不共享可变的记录层状态。
class FtpsClient {
public:
    FtpsClient()
    {
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&config);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&random);
        mbedtls_ssl_session_init(&ticket);
    }
    ~FtpsClient()
    {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
        mbedtls_ctr_drbg_free(&random);
        mbedtls_entropy_free(&entropy);
        mbedtls_ssl_session_free(&ticket);
    }

    int Start(const std::string &hostname, FtpsClient *parent)
    {
        host = hostname;
        if (psa_crypto_init() != PSA_SUCCESS) { return MBEDTLS_ERR_SSL_INTERNAL_ERROR; }
        int rc = mbedtls_ctr_drbg_seed(&random, mbedtls_entropy_func, &entropy, nullptr, 0);
        if (!rc) { rc = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); }
        if (rc) { return rc; }
        // 系统 CertKit 在握手后、交付明文或发送凭据前验证完整证书链。
        mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &random);
        mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(&config, MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED);
        rc = mbedtls_ssl_setup(&ssl, &config);
        if (!rc) { rc = mbedtls_ssl_set_hostname(&ssl, host.c_str()); }
        if (rc) { return rc; }
        mbedtls_ssl_set_bio(&ssl, this, Send, Receive, nullptr);
        if (parent) {
            if (parent->host != host || !parent->ready) { return MBEDTLS_ERR_SSL_BAD_INPUT_DATA; }
            if (parent->hasTicket) {
                rc = mbedtls_ssl_set_session(&ssl, &parent->ticket);
                if (rc) { return rc; }
                chain = parent->chain;
            }
        }
        return 0;
    }

    int Drive(unsigned operation, const unsigned char *bytes, size_t size, Bytes &plain)
    {
        if (size > 2 * 1024 * 1024) { return MBEDTLS_ERR_SSL_BAD_INPUT_DATA; }
        if (operation == 1) {
            if (!ready || eof) { return MBEDTLS_ERR_SSL_BAD_INPUT_DATA; }
            size_t pos = 0;
            while (pos < size) {
                int n = mbedtls_ssl_write(&ssl, bytes + pos, std::min<size_t>(16384, size - pos));
                if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) { SaveTicket(); continue; }
                if (n <= 0) { return n ? n : MBEDTLS_ERR_SSL_INTERNAL_ERROR; }
                pos += static_cast<size_t>(n);
            }
            return 0;
        }
        if (operation == 2) {
            int rc = 0;
            do {
                rc = ready ? mbedtls_ssl_close_notify(&ssl) : 0;
                if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) { SaveTicket(); }
            } while (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET);
            return rc;
        }
        if (operation != 0) { return MBEDTLS_ERR_SSL_BAD_INPUT_DATA; }
        if (size) { input.insert(input.end(), bytes, bytes + size); }
        if (!ready) {
            int rc;
            do {
                const auto before = input.size();
                rc = mbedtls_ssl_handshake(&ssl);
                if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) { SaveTicket(); }
                if (rc == MBEDTLS_ERR_SSL_WANT_READ && !input.empty() && input.size() < before) { continue; }
                if (rc != MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) { break; }
            } while (true);
            if (rc == MBEDTLS_ERR_SSL_WANT_READ) { return 0; }
            if (rc != 0) { return rc; }
            if (!CapturePeer()) { return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED; }
            ready = true;
            if (mbedtls_ssl_get_version_number(&ssl) == MBEDTLS_SSL_VERSION_TLS1_2) { SaveTicket(); }
        }
        std::array<unsigned char, 16384> fragment;
        while (!eof) {
            const auto before = input.size();
            const int n = mbedtls_ssl_read(&ssl, fragment.data(), fragment.size());
            if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) { SaveTicket(); continue; }
            if (n == MBEDTLS_ERR_SSL_WANT_READ) {
                if (!input.empty() && input.size() < before) { continue; }
                break;
            }
            if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) { eof = true; break; }
            if (n <= 0) { return n ? n : MBEDTLS_ERR_SSL_CONN_EOF; }
            plain.insert(plain.end(), fragment.begin(), fragment.begin() + n);
        }
        return 0;
    }

    Bytes wire;
    std::vector<Bytes> chain;
    bool ready = false;
    bool eof = false;

private:
    void SaveTicket()
    {
        mbedtls_ssl_session_free(&ticket);
        mbedtls_ssl_session_init(&ticket);
        hasTicket = mbedtls_ssl_get_session(&ssl, &ticket) == 0;
    }
    bool CapturePeer()
    {
        const auto *leaf = mbedtls_ssl_get_peer_cert(&ssl);
        if (!leaf) { return !chain.empty(); } // 仅在已认证的控制连接会话恢复时保留证书链
        if (mbedtls_x509_crt_check_extended_key_usage(leaf, MBEDTLS_OID_SERVER_AUTH,
            MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0) { return false; }
        std::array<unsigned char, 16> address {};
        std::string literal = host;
        if (literal.find(':') != std::string::npos) {
            if (literal.front() == '[' && literal.back() == ']') { literal = literal.substr(1, literal.size() - 2); }
            literal = literal.substr(0, literal.find('%'));
        }
        const size_t len = inet_pton(AF_INET, literal.c_str(), address.data()) == 1 ? 4 :
            (inet_pton(AF_INET6, literal.c_str(), address.data()) == 1 ? 16 : 0);
        // CertKit 将 IP 身份交给这里处理，无法解析时必须拒绝，避免只校验证书链。
        if (!len && (host.find(':') != std::string::npos ||
            host.find_first_not_of("0123456789.") == std::string::npos)) { return false; }
        if (len) {
            bool found = false;
            for (auto san = &leaf->subject_alt_names; san; san = san->next) {
                if (san->buf.tag == 0x87 && san->buf.len == len && !memcmp(san->buf.p, address.data(), len)) { found = true; }
            }
            if (!found) { return false; }
        }
        chain.clear();
        for (auto p = leaf; p; p = p->next) { chain.emplace_back(p->raw.p, p->raw.p + p->raw.len); }
        return !chain.empty();
    }
    static int Send(void *ctx, const unsigned char *bytes, size_t size)
    {
        auto &out = static_cast<FtpsClient *>(ctx)->wire;
        out.insert(out.end(), bytes, bytes + size);
        return static_cast<int>(size);
    }
    static int Receive(void *ctx, unsigned char *bytes, size_t size)
    {
        auto &in = static_cast<FtpsClient *>(ctx)->input;
        if (in.empty()) { return MBEDTLS_ERR_SSL_WANT_READ; }
        size_t n = std::min(size, in.size());
        memcpy(bytes, in.data(), n);
        in.erase(in.begin(), in.begin() + n);
        return static_cast<int>(n);
    }

    std::string host;
    Bytes input;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_ssl_session ticket;
    bool hasTicket = false;
};

napi_value Error(napi_env env, int code)
{
    char reason[180] {};
    mbedtls_strerror(code, reason, sizeof(reason));
    napi_throw_error(env, nullptr, reason);
    return nullptr;
}

FtpsClient *GetClient(napi_env env, napi_value obj)
{
    void *ptr = nullptr;
    bool matches = false;
    if (napi_check_object_type_tag(env, obj, &TLS_TAG, &matches) != napi_ok || !matches ||
        napi_unwrap(env, obj, &ptr) != napi_ok) { return nullptr; }
    return static_cast<FtpsClient *>(ptr);
}

napi_value Create(napi_env env, napi_callback_info info)
{
    napi_value args[2] {};
    size_t argc = 2, len = 0;
    std::array<char, 256> host {};
    if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || !argc ||
        napi_get_value_string_utf8(env, args[0], nullptr, 0, &len) != napi_ok || !len || len >= host.size() ||
        napi_get_value_string_utf8(env, args[0], host.data(), host.size(), &len) != napi_ok || strlen(host.data()) != len) {
        return Error(env, MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    auto client = std::make_unique<FtpsClient>();
    auto *parent = argc == 2 ? GetClient(env, args[1]) : nullptr;
    if (argc == 2 && !parent) { return Error(env, MBEDTLS_ERR_SSL_BAD_INPUT_DATA); }
    int rc = client->Start(host.data(), parent);
    if (rc != 0) { return Error(env, rc); }
    napi_value handle;
    if (napi_create_object(env, &handle) != napi_ok || napi_type_tag_object(env, handle, &TLS_TAG) != napi_ok ||
        napi_wrap(env, handle, client.get(), [](napi_env, void *data, void *) { delete static_cast<FtpsClient *>(data); },
            nullptr, nullptr) != napi_ok) { return Error(env, MBEDTLS_ERR_SSL_ALLOC_FAILED); }
    client.release();
    return handle;
}

napi_value Buffer(napi_env env, const Bytes &bytes)
{
    napi_value value;
    void *ptr = nullptr;
    if (napi_create_arraybuffer(env, bytes.size(), &ptr, &value) != napi_ok) { return nullptr; }
    if (!bytes.empty()) { memcpy(ptr, bytes.data(), bytes.size()); }
    return value;
}

napi_value Step(napi_env env, napi_callback_info info)
{
    napi_value args[3] {}, result, value;
    void *bytes = nullptr;
    size_t argc = 3, size = 0;
    uint32_t op = 0;
    if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 3 ||
        napi_get_value_uint32(env, args[1], &op) != napi_ok ||
        napi_get_arraybuffer_info(env, args[2], &bytes, &size) != napi_ok) { return Error(env, MBEDTLS_ERR_SSL_BAD_INPUT_DATA); }
    auto *client = GetClient(env, args[0]);
    if (!client) { return Error(env, MBEDTLS_ERR_SSL_BAD_INPUT_DATA); }
    Bytes plain;
    int rc = client->Drive(op, static_cast<const unsigned char *>(bytes), size, plain);
    if (rc != 0) { return Error(env, rc); }
    napi_create_object(env, &result);
    napi_get_boolean(env, client->ready, &value);
    napi_set_named_property(env, result, "ready", value);
    napi_get_boolean(env, client->eof, &value);
    napi_set_named_property(env, result, "eof", value);
    napi_set_named_property(env, result, "plain", Buffer(env, plain));
    napi_set_named_property(env, result, "wire", Buffer(env, client->wire));
    client->wire.clear();
    return result;
}

napi_value Peer(napi_env env, napi_callback_info info)
{
    napi_value handle, result;
    size_t argc = 1;
    if (napi_get_cb_info(env, info, &argc, &handle, nullptr, nullptr) != napi_ok || argc != 1) {
        return Error(env, MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }
    auto *client = GetClient(env, handle);
    if (!client || !client->ready) { return Error(env, MBEDTLS_ERR_SSL_BAD_INPUT_DATA); }
    napi_create_array_with_length(env, client->chain.size(), &result);
    for (size_t i = 0; i < client->chain.size(); ++i) { napi_set_element(env, result, i, Buffer(env, client->chain[i])); }
    return result;
}
} // namespace

void RegisterFtpsTls(napi_env env, napi_value exports)
{
    napi_property_descriptor methods[] = {
        {"ftpsTlsCreate", nullptr, Create, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"ftpsTlsStep", nullptr, Step, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"ftpsTlsPeer", nullptr, Peer, nullptr, nullptr, nullptr, napi_default, nullptr}
    };
    napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods);
}
} // namespace homoxterm
