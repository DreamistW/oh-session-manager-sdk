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
提供相同哈希的本地文件。结果位于 `dist/session-manager-sdk-0.1.0.har`，附 SHA-256 校验文件。

## 使用

宿主直接安装本包及依赖锁指定的 libssh2 和 Mbed TLS HAR，通过 CMake 将三者链接进宿主
的 NAPI 模块。ArkTS 从包入口取得对应传输类，向 SSH 和 FTP 实例传入该原生模块。
宿主提供认证材料与 SSH 主机密钥决策。见 [安装和调用示例](library/README.md)。

## GitHub Release

推送 `main` 运行构建并上传 Actions artifact。推送与包版本一致的稳定标签
（例如 `v0.1.0`）发布经过审计的 HAR 与 SHA-256 校验文件。

## 许可

SDK 原创代码使用 Apache-2.0，依赖的 libssh2 和 Mbed TLS 许可随包提供。
