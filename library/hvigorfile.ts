import { harTasks } from '@ohos/hvigor-ohos-plugin';

// 保留静态原生库，由消费者自己的 NAPI 或 C/C++ 模块链接。
export default { system: harTasks, plugins: [] };
