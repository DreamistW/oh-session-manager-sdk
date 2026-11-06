# session-manager-sdk HAR

通过 OHPM 安装 `session-manager-sdk`、`libssh2-oh` 和 `mbedtls-oh` 三个 HAR，
并为宿主模块声明 `ohos.permission.INTERNET`。CMake 从安装后的三个包导入目标。

```cmake
include("${SESSION_SDK_PACKAGE}/include/session-manager-sdk.cmake")
include("${LIBSSH2_OH_PACKAGE}/include/libssh2-oh.cmake")
include("${MBEDTLS_OH_PACKAGE}/include/mbedtls-oh.cmake")
target_link_libraries(your_native_module PRIVATE
  session-manager-sdk::core libssh2-oh::ssh2 mbedtls-oh::tls libace_napi.z.so)
```

在宿主的 `napi_module` 中将初始化回调指向 `RegisterSessionManagerExports`，
并从 ArkTS 加载同名原生模块。原生模块的类型文件可引用
`session-manager-sdk/src/main/ets/native/SessionManagerNativeApi`。

```typescript
import { SshTransport, FtpTransport, TelnetTransport } from 'session-manager-sdk';
import native from 'libyour_native_module.so';

const ssh = new SshTransport(native);
const ftp = new FtpTransport(native);
const telnet = new TelnetTransport();
```

使用 `connect` 传入连接档案、认证材料和主机密钥决策实现。宿主确认 SSH 指纹后才能认证。
按协议使用终端读写、目录和文件操作，结束时调用 `disconnect()`。FTPS 默认使用系统
CA，IP 地址通过证书 iPAddress SAN 校验。包内来源、依赖和文件哈希见
`include/session-manager-sdk-manifest.json`。
