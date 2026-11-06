// Only transient transport failures are retried; authentication and trust never loop.
export class MetricsRecoveryPolicy {
  private failures: number = 0;
  private retryAt: number = 0;
  private blocked: boolean = false;
  ready(now: number): boolean { return !this.blocked && now >= this.retryAt; }
  reset(): void { this.failures = 0; this.retryAt = 0; this.blocked = false; }
  fail(message: string, now: number): string {
    const text = message.toLowerCase();
    const native = text.match(/libssh2 error (-?\d+)/);
    const code = native === null ? 0 : Number(native[1]);
    // libssh2.h transport/timeout codes take precedence over incidental words in an error message.
    const networkCode = [-1, -2, -3, -7, -9, -13, -26, -27, -30, -43, -45].indexOf(code) >= 0;
    const blockedCode = [-4, -5, -8, -10, -11, -12, -15, -18, -19, -21, -22, -32, -33, -48, -51].indexOf(code) >= 0;
    const terminal = /host key|fingerprint|credentials|authentication failed|authentication method|not supported|denied|private key|publickey|password|channel request|channel open failure|output is too large/.test(text);
    const transient = networkCode || (!blockedCode && !terminal && /timed out|timeout|socket|connect|network|transport|eof|closed|disconnect|recv|send|banner|handshake/.test(text));
    if (!transient) { this.blocked = true; return 'metrics blocked'; }
    const delays = [1000, 2000, 5000, 10000, 30000];
    this.retryAt = now + delays[Math.min(this.failures++, delays.length - 1)];
    return 'metrics retry pending';
  }
}
