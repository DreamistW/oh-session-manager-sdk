#ifndef SESSION_MANAGER_SSH_LIBRARY_LIFETIME_H
#define SESSION_MANAGER_SSH_LIBRARY_LIFETIME_H

#include <libssh2.h>

// 探针与业务会话共用初始化，避免探针退出时清理活跃会话所用的全局状态。
inline bool EnsureSshLibraryInitialized()
{
    struct Lifetime {
        const bool ready = libssh2_init(0) == 0;
        ~Lifetime()
        {
            if (ready) {
                libssh2_exit();
            }
        }
    };
    static const Lifetime library;
    return library.ready;
}

#endif
