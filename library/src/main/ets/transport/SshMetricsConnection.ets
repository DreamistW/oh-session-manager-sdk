import { hilog } from '@kit.PerformanceAnalysisKit';
import { SessionManagerNativeApi } from '../native/SessionManagerNativeApi';
import { MetricsCredentials } from '../protocol/MetricsCredentials';
import { MetricsRecoveryPolicy } from '../protocol/MetricsRecoveryPolicy';

// Credentials are requested only when opening, never retained by this adapter.
export class SshMetricsConnection {
  private readonly native: SessionManagerNativeApi;

  constructor(native: SessionManagerNativeApi) {
    this.native = native;
  }

  private sessionId: number = 0;
  private generation: number = 0;
  private pending: boolean = false;
  private readonly recovery: MetricsRecoveryPolicy = new MetricsRecoveryPolicy();
  private releasePending: Promise<void> = Promise.resolve();
  epoch: number = 0;

  async collect(host: string, port: number, fingerprint: string, username: string,
    credentials: () => Promise<MetricsCredentials>, legacySsh: boolean = false): Promise<string> {
    if (this.pending || !this.recovery.ready(Date.now())) { throw new Error('metrics retry pending'); }
    const generation = this.generation;
    this.pending = true;
    try {
      await this.releasePending;
      this.assertCurrent(generation);
      if (this.sessionId <= 0) {
        const material = await credentials();
        this.assertCurrent(generation);
        if (material.secret.length === 0 || (material.kind !== 'password' && material.kind !== 'private-key')) {
          throw new Error('metrics credentials unavailable');
        }
        const id: number = this.native.reserveMetrics();
        this.sessionId = id;
        try {
          const opening: Promise<number> = this.native.connectMetrics(host, port, fingerprint, username, material.kind,
            material.secret, material.passphrase, id, legacySsh);
          await opening;
        } finally {
          material.secret = '';
          material.passphrase = '';
        }
        this.assertCurrent(generation);
        this.epoch++;
      }
      const operation: Promise<string> = this.native.collectRemoteMetrics(this.sessionId);
      const value: string = await operation;
      this.assertCurrent(generation);
      this.recovery.reset();
      return value;
    } catch (error) {
      if (generation !== this.generation) { throw new Error('metrics cancelled'); }
      this.release();
      const message = (error as Error).message ?? '';
      const failure = this.recovery.fail(message, Date.now());
      const native = message.match(/libssh2 error (-?\d+)/);
      hilog.warn(0x0000, 'RemoteMetrics', 'failure=%{public}s nativeCode=%{public}d',
        failure, native === null ? 0 : Number(native[1]));
      throw new Error(failure);
    } finally {
      if (generation === this.generation) { this.pending = false; }
    }
  }

  close(): void {
    this.generation++;
    this.epoch++;
    this.pending = false;
    this.recovery.reset();
    this.release();
  }

  private assertCurrent(generation: number): void {
    if (generation !== this.generation) { throw new Error('metrics cancelled'); }
  }

  private release(): void {
    const id = this.sessionId;
    this.sessionId = 0;
    if (id <= 0) { return; }
    // Signal cancellation synchronously; joining stays off the UI thread.
    this.native.cancelMetrics(id);
    this.releasePending = this.native.disconnectMetrics(id).then((): void => {}, (): void => {});
  }
}
