#include "ssh_library_lifetime.h"
#include "ssh_probe.h"

#include <libssh2.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <sstream>

namespace homoxterm {
namespace {

constexpr int SOCKET_TIMEOUT_SECONDS = 15;

int ConnectSocket(const std::string &host, uint16_t port)
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
    for (addrinfo *address = addresses; address != nullptr; address = address->ai_next) {
        int candidate = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (candidate < 0) {
            continue;
        }
        timeval timeout {SOCKET_TIMEOUT_SECONDS, 0};
        setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        const int originalFlags = fcntl(candidate, F_GETFL, 0);
        if (originalFlags < 0 || fcntl(candidate, F_SETFL, originalFlags | O_NONBLOCK) != 0) {
            close(candidate);
            continue;
        }
        int connectResult = connect(candidate, address->ai_addr, address->ai_addrlen);
        if (connectResult != 0 && errno == EINPROGRESS) {
            pollfd descriptor {candidate, POLLOUT, 0};
            connectResult = poll(&descriptor, 1, SOCKET_TIMEOUT_SECONDS * 1000);
            int socketError = 0;
            socklen_t errorLength = sizeof(socketError);
            if (connectResult > 0 && getsockopt(candidate, SOL_SOCKET, SO_ERROR,
                &socketError, &errorLength) == 0 && socketError == 0) {
                connectResult = 0;
            } else {
                connectResult = -1;
            }
        }
        if (connectResult == 0) {
            fcntl(candidate, F_SETFL, originalFlags);
            connected = candidate;
            break;
        }
        close(candidate);
    }
    freeaddrinfo(addresses);
    return connected;
}

std::string LastError(LIBSSH2_SESSION *session)
{
    char *message = nullptr;
    int length = 0;
    const int code = libssh2_session_last_error(session, &message, &length, 0);
    std::ostringstream output;
    output << "code=" << code;
    if (message != nullptr && length > 0) {
        output << " message=" << std::string(message, static_cast<size_t>(length));
    }
    return output.str();
}

const char *Method(LIBSSH2_SESSION *session, int type)
{
    const char *value = libssh2_session_methods(session, type);
    return value == nullptr ? "unknown" : value;
}

} // namespace

std::string RunLibssh2HandshakeGate(const std::string &host, uint16_t port)
{
    if (host.empty() || port == 0) {
        return "LIBSSH2_HANDSHAKE_FAIL invalid-endpoint";
    }
    if (!EnsureSshLibraryInitialized()) {
        return "LIBSSH2_HANDSHAKE_FAIL libssh2-init";
    }
    int socketFd = ConnectSocket(host, port);
    if (socketFd < 0) {
        return "LIBSSH2_HANDSHAKE_FAIL tcp-connect";
    }
    LIBSSH2_SESSION *session = libssh2_session_init();
    if (session == nullptr) {
        close(socketFd);
        return "LIBSSH2_HANDSHAKE_FAIL session-init";
    }
    libssh2_session_set_blocking(session, 1);
    libssh2_session_set_timeout(session, SOCKET_TIMEOUT_SECONDS * 1000);
    const char *kex = "curve25519-sha256,curve25519-sha256@libssh.org,"
        "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
        "diffie-hellman-group14-sha256";
    const char *hostkey = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,"
        "ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256";
    const char *cipher = "aes128-ctr,aes192-ctr,aes256-ctr";
    const char *mac = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
        "hmac-sha2-256,hmac-sha2-512";
    int rc = libssh2_session_method_pref(session, LIBSSH2_METHOD_KEX, kex);
    rc = rc == 0 ? libssh2_session_method_pref(session, LIBSSH2_METHOD_HOSTKEY, hostkey) : rc;
    rc = rc == 0 ? libssh2_session_method_pref(session, LIBSSH2_METHOD_CRYPT_CS, cipher) : rc;
    rc = rc == 0 ? libssh2_session_method_pref(session, LIBSSH2_METHOD_CRYPT_SC, cipher) : rc;
    rc = rc == 0 ? libssh2_session_method_pref(session, LIBSSH2_METHOD_MAC_CS, mac) : rc;
    rc = rc == 0 ? libssh2_session_method_pref(session, LIBSSH2_METHOD_MAC_SC, mac) : rc;
    rc = rc == 0 ? libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_CS, "none") : rc;
    rc = rc == 0 ? libssh2_session_method_pref(session, LIBSSH2_METHOD_COMP_SC, "none") : rc;
    if (rc == 0) {
        rc = libssh2_session_handshake(session, socketFd);
    }
    std::ostringstream report;
    if (rc == 0) {
        const unsigned char *fingerprint = reinterpret_cast<const unsigned char *>(
            libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256));
        report << "LIBSSH2_HANDSHAKE_PASS"
               << "\nengine=" << static_cast<int>(libssh2_crypto_engine())
               << "\nkex=" << Method(session, LIBSSH2_METHOD_KEX)
               << "\nhostkey=" << Method(session, LIBSSH2_METHOD_HOSTKEY)
               << "\ncipher-cs=" << Method(session, LIBSSH2_METHOD_CRYPT_CS)
               << "\ncipher-sc=" << Method(session, LIBSSH2_METHOD_CRYPT_SC)
               << "\nmac-cs=" << Method(session, LIBSSH2_METHOD_MAC_CS)
               << "\nmac-sc=" << Method(session, LIBSSH2_METHOD_MAC_SC)
               << "\nfingerprint-sha256=";
        if (fingerprint != nullptr) {
            static constexpr char HEX[] = "0123456789abcdef";
            for (size_t index = 0; index < 32; ++index) {
                report << HEX[fingerprint[index] >> 4U] << HEX[fingerprint[index] & 0x0fU];
            }
        } else {
            report << "unavailable";
        }
        libssh2_session_disconnect(session, "HomoXterm handshake gate complete");
    } else {
        report << "LIBSSH2_HANDSHAKE_FAIL " << LastError(session);
    }
    libssh2_session_free(session);
    close(socketFd);
    return report.str();
}

} // namespace homoxterm
