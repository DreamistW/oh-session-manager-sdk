# session-manager-sdk

HarmonyOS 远程会话 HAR，支持 SSH 终端、SFTP、SCP、FTP、显式和隐式 FTPS
及 Telnet。首版支持最低 API 23、目标 API 26、`arm64-v8a`、`2in1`。

## 工程内容

- `library/` 包含 ArkTS 传输接口、原生 CMake 导入目标及注册声明。
- `native/` 包含会话和 TLS 原生实现。
- `dependencies.lock.json` 固定用于编译的 libssh2 和 Mbed TLS HAR。
- `scripts/` 提供原生构建、HAR 打包及发布审计。

## 构建 HAR

配置 API 26 Command Line Tools 环境变量 `DEVECO_CLI_CLT_PATH`，安装 Python 3.11+
和 JDK 21。Windows 还需要支持 `assembleHar` 的 `devecocli`。

```sh
python scripts/build.py
```

脚本下载锁定的 HAR 并校验 SHA-256。可分别通过 `--libssh2` 和 `--mbedtls`
提供相同哈希的本地文件。结果位于 `dist/session-manager-sdk-0.1.1.har`，附 SHA-256 校验文件。

## 安装与接入

下载 [session-manager-sdk](https://github.com/DreamistW/oh-session-manager-sdk/releases/tag/v0.1.1)、
[libssh2-oh](https://github.com/DreamistW/libssh2-oh/releases/tag/v0.1.1) 和
[mbedtls-oh](https://github.com/DreamistW/mbedtls-oh/releases/tag/v0.1.1) 的 HAR。
核对 SHA-256 后在宿主模块目录安装。原生依赖的版本和哈希见 [依赖锁](dependencies.lock.json)。

```sh
ohpm install ./libssh2-oh-0.1.1.har
ohpm install ./mbedtls-oh-0.1.1.har
ohpm install ./session-manager-sdk-0.1.1.har
```

在宿主模块 `module.json5` 的 `module` 对象中声明网络权限。

```json
{
  "requestPermissions": [
    { "name": "ohos.permission.INTERNET" }
  ]
}
```

假设 `CMakeLists.txt` 位于宿主模块的 `src/main/cpp`，`oh_modules` 位于模块根目录。
将三个静态库目标链接进宿主的 NAPI 模块。

```cmake
set(HAR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../oh_modules")
include("${HAR_DIR}/session-manager-sdk/include/session-manager-sdk.cmake")
include("${HAR_DIR}/libssh2-oh/include/libssh2-oh.cmake")
include("${HAR_DIR}/mbedtls-oh/include/mbedtls-oh.cmake")

add_library(session_manager SHARED napi_register.cpp)
target_link_libraries(session_manager PRIVATE
  session-manager-sdk::core libssh2-oh::ssh2 mbedtls-oh::tls libace_napi.z.so)
```

在 `napi_register.cpp` 注册 SDK 的原生方法。模块名 `session_manager` 与
ArkTS 中加载的 `libsession_manager.so` 对应。

```cpp
#include <session-manager-sdk.h>

// 由宿主的 NAPI 模块注册 HAR 提供的会话接口。
static napi_module sessionManagerModule = {
    1, 0, nullptr, RegisterSessionManagerExports, "session_manager", nullptr, {0},
};

extern "C" __attribute__((constructor)) void RegisterSessionManagerModule()
{
    napi_module_register(&sessionManagerModule);
}
```

在宿主模块的 `oh-package.json5` 的 `dependencies` 中添加
`"libsession_manager.so": "file:./src/main/cpp/types/libsession_manager"`。
在该目录创建 `oh-package.json5`，内容为
`{ "name": "libsession_manager.so", "version": "1.0.0", "types": "./index.d.ts" }`。
同目录的 `index.d.ts` 使用 SDK 提供的声明。

```typescript
import { SessionManagerNativeApi } from 'session-manager-sdk/src/main/ets/native/SessionManagerNativeApi';

declare const sessionManagerNative: SessionManagerNativeApi;
export default sessionManagerNative;
```

## 基本功能示例

### 核对主机密钥并打开 SSH 终端

宿主提供 `TransportProfile`，包含会话标识、主机、端口、用户名、协议、
`legacySsh` 和 `endpoint()`。交互终端使用 `SessionProtocol.SSH`，
通常将 `legacySsh` 设为 `false`。示例用可信渠道取得的主机密钥算法和指纹做固定校验。
密码作为参数传入，终端数据交给宿主的输出回调。

```typescript
import native from 'libsession_manager.so';
import {
  CredentialKind, HostKeyDecision, HostKeyRecord, HostKeyVerifier,
  SessionProtocol, SshTransport, TransportCredential, TransportProfile
} from 'session-manager-sdk';

export function makeSshProfile(id: string, host: string, port: number, username: string): TransportProfile {
  return {
    id: id, host: host, port: port, username: username, protocol: SessionProtocol.SSH, legacySsh: false,
    endpoint(): string { return username + '@' + host + ':' + port.toString(); }
  };
}

// 固定校验包含端点、算法和指纹。
class PinnedHostKey implements HostKeyVerifier {
  private readonly expected: HostKeyRecord;

  constructor(expected: HostKeyRecord) {
    this.expected = expected;
  }

  verify(presented: HostKeyRecord): HostKeyDecision {
    const key = this.expected;
    return presented.host === key.host && presented.port === key.port &&
      presented.algorithm === key.algorithm && presented.fingerprint === key.fingerprint ?
      HostKeyDecision.Trusted : HostKeyDecision.Mismatch;
  }

  trust(_presented: HostKeyRecord): void {
    // 固定校验策略的信任记录由调用方提供。
  }
}

export async function openSshTerminal(profile: TransportProfile, expectedKey: HostKeyRecord,
  password: string, onOutput: (text: string) => void): Promise<SshTransport> {
  if (profile.protocol !== SessionProtocol.SSH) { throw new Error('SSH profile required'); }
  const session = new SshTransport(native);
  const credential: TransportCredential = { kind: CredentialKind.Password };
  session.onData = onOutput;
  try {
    const result = await session.connect(new PinnedHostKey(expectedKey), profile, credential, password, '', false);
    if (!result.connected) { throw new Error(result.errorMessage || result.message || 'SSH connection failed'); }
    const command = 'pwd\r';
    const written = await session.writeRaw(command);
    if (written !== command.length) { throw new Error('Short terminal write'); }
    return session;
  } catch (error) {
    session.disconnect();
    throw error instanceof Error ? error : new Error('SSH connection failed');
  }
}
```

`connect` 会先核对主机密钥再认证。若需要首次连接确认，宿主应展示并核实指纹，
再通过自己的信任存储保存。终端关闭时调用 `session.disconnect()`。
宿主可用 `resize(columns, rows)` 同步终端大小。私钥认证使用 `CredentialKind.PrivateKey`，
键盘交互认证通过 `onKeyboardInteractivePrompt` 和 `respondKeyboardInteractive` 接收和回应提示。

### 列出 SFTP 目录

在已认证的 SSH 会话上开启文件通道，再列出远端主目录。
独立 `SessionProtocol.SFTP` 或 `SessionProtocol.SCP` 会话在连接时初始化文件通道。

```typescript
import { RemoteEntry, SshTransport, TransportProfile } from 'session-manager-sdk';

export async function listSftpHome(session: SshTransport, profile: TransportProfile): Promise<RemoteEntry[]> {
  if (!await session.startSftpSession(profile, '')) { throw new Error('SFTP channel unavailable'); }
  const home = await session.primeHomeDirectory();
  return await session.listDirectory(home);
}
```

文件上传使用 `uploadFromFile(localUri, remotePath, onProgress, isCancelled)`，
下载使用 `downloadToFile(remotePath, localUri, onProgress, isCancelled)`。
回调接收累计字节数，返回值表示已传输的字节数。调用方负责选择可访问的本地路径并管理取消状态。

### 通过 FTPS 下载文件

显式 FTPS 使用 `SessionProtocol.FTPS`，通常连接端口 21。隐式 FTPS 使用
`SessionProtocol.FTPSImplicit`，通常连接端口 990。示例使用系统 CA 验证服务器证书。
`hostKeys` 是统一连接签名的参数，FTPS 的服务器身份通过 TLS 证书核对。

```typescript
import native from 'libsession_manager.so';
import { FtpTransport, HostKeyVerifier, SessionProtocol, TransportProfile } from 'session-manager-sdk';

export async function downloadFtps(profile: TransportProfile, hostKeys: HostKeyVerifier,
  password: string, remotePath: string, localUri: string,
  onProgress: (bytesDone: number) => void, isCancelled: () => boolean): Promise<number> {
  if (profile.protocol !== SessionProtocol.FTPS && profile.protocol !== SessionProtocol.FTPSImplicit) {
    throw new Error('FTPS profile required');
  }
  const session = new FtpTransport(native);
  try {
    const result = await session.connect(hostKeys, profile, undefined, password, '', false);
    if (!result.connected) { throw new Error(result.errorMessage || result.message || 'FTPS connection failed'); }
    return await session.downloadToFile(remotePath, localUri, onProgress, isCancelled);
  } finally {
    session.disconnect();
  }
}
```

明文 FTP 选择 `SessionProtocol.FTP`。Telnet 使用 `new TelnetTransport()`，
档案协议为 `SessionProtocol.Telnet`，调用 `connect(hostKeys, profile, undefined, '', '', false)`。
连接后通过 `onData`、`writeRaw()` 和 `resize()` 操作终端，关闭时调用 `disconnect()`。
Telnet 和普通 FTP 都是明文协议。

## GitHub Release

推送 `main` 运行构建并上传 Actions artifact。推送与包版本一致的稳定标签
（例如 `v0.1.1`）发布经过审计的 HAR 与 SHA-256 校验文件。

## 许可

SDK 原创代码使用 Apache-2.0，依赖的 libssh2 和 Mbed TLS 许可随包提供。
