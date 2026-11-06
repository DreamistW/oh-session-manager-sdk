#ifndef HOMOXTERM_SSH_PROBE_H
#define HOMOXTERM_SSH_PROBE_H

#include <cstdint>
#include <string>

namespace homoxterm {

std::string RunLibssh2HandshakeGate(const std::string &host, uint16_t port);

} // namespace homoxterm

#endif // HOMOXTERM_SSH_PROBE_H
