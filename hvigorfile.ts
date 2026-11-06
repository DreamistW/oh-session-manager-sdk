import { appTasks } from '@ohos/hvigor-ohos-plugin';

// 独立工程只编译 HAR，不读取宿主应用的签名配置。
export default { system: appTasks, plugins: [] };
