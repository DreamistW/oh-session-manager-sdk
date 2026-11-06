#ifndef HOMOXTERM_SSH_NAPI_H
#define HOMOXTERM_SSH_NAPI_H

#include <napi/native_api.h>

namespace homoxterm {

napi_value ConnectNapi(napi_env env, napi_callback_info info);
napi_value AcceptHostKeyNapi(napi_env env, napi_callback_info info);
napi_value AuthenticateNapi(napi_env env, napi_callback_info info);
napi_value KeyboardInteractivePromptNapi(napi_env env, napi_callback_info info);
napi_value RespondKeyboardInteractiveNapi(napi_env env, napi_callback_info info);
napi_value OpenPtyNapi(napi_env env, napi_callback_info info);
napi_value WriteNapi(napi_env env, napi_callback_info info);
napi_value ReadNapi(napi_env env, napi_callback_info info);
napi_value ResizePtyNapi(napi_env env, napi_callback_info info);
napi_value OpenSftpNapi(napi_env env, napi_callback_info info);
napi_value ListDirectoryNapi(napi_env env, napi_callback_info info);
napi_value ListDeleteDirectoryNapi(napi_env env, napi_callback_info info);
napi_value BeginScpNapi(napi_env env, napi_callback_info info);
napi_value StepScpNapi(napi_env env, napi_callback_info info);
napi_value EndScpNapi(napi_env env, napi_callback_info info);
napi_value ReadFileChunkNapi(napi_env env, napi_callback_info info);
napi_value WriteFileChunkNapi(napi_env env, napi_callback_info info);
napi_value CreateDirectoryNapi(napi_env env, napi_callback_info info);
napi_value RemoveEntryNapi(napi_env env, napi_callback_info info);
napi_value CollectRemoteMetricsNapi(napi_env env, napi_callback_info info);
napi_value ReserveMetricsNapi(napi_env env, napi_callback_info info);
napi_value CancelMetricsNapi(napi_env env, napi_callback_info info);
napi_value ConnectMetricsNapi(napi_env env, napi_callback_info info);
napi_value DisconnectMetricsNapi(napi_env env, napi_callback_info info);
napi_value DisconnectNapi(napi_env env, napi_callback_info info);

} // namespace homoxterm

#endif // HOMOXTERM_SSH_NAPI_H
