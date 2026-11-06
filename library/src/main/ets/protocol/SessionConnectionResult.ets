import { HostKeyDecision } from './HostKey';

export class SessionConnectionResult {
  connected: boolean;
  decision: HostKeyDecision;
  message: string;

  // 弹窗使用底层错误；message 仍供状态分类和诊断记录使用。
  readonly errorMessage: string;

  constructor(connected: boolean, decision: HostKeyDecision, message: string, errorMessage: string = '') {
    this.errorMessage = errorMessage;
    this.connected = connected;
    this.decision = decision;
    this.message = message;
  }
}
