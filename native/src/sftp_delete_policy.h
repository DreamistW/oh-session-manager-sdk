#ifndef HOMOXTERM_SFTP_DELETE_POLICY_H
#define HOMOXTERM_SFTP_DELETE_POLICY_H

#include <string>

namespace homoxterm {

inline bool IsSafeSftpDeletePath(const std::string &path)
{
    if (path.size() <= 1 || path.size() > 4096 || path.front() != '/' || path.back() == '/') {
        return false;
    }
    size_t start = 1;
    for (size_t index = 1; index <= path.size(); ++index) {
        if (index < path.size()) {
            const unsigned char value = static_cast<unsigned char>(path[index]);
            if (value < 32 || value == 127 || value == '\\') {
                return false;
            }
            if (value != '/') {
                continue;
            }
        }
        const std::string component = path.substr(start, index - start);
        if (component.empty() || component == "." || component == ".." || component.size() > 255) {
            return false;
        }
        start = index + 1;
    }
    return true;
}

} // namespace homoxterm
#endif
