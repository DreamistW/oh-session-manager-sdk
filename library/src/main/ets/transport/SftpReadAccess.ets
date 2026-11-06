import { SessionManagerNativeApi } from '../native/SessionManagerNativeApi';

/** SFTP 原生目录条目。 */
export interface SftpDirectoryEntry {
  name: string;
  isDirectory: boolean;
  size: number;
  modified: number;
}

/** 读操作绑定原连接，断开或重连后旧接口失效。 */
export class SftpReadAccess {
  readonly home: string;
  private readonly native: SessionManagerNativeApi;
  private readonly id: number;
  private readonly current: () => boolean;

  constructor(native: SessionManagerNativeApi, id: number, home: string, current: () => boolean) {
    this.native = native;
    this.id = id;
    this.home = home;
    this.current = current;
  }

  isCurrent(): boolean {
    return this.current();
  }

  async listDirectory(path: string): Promise<SftpDirectoryEntry[]> {
    this.assertCurrent();
    const raw = await this.native.listDirectory(this.id, path);
    this.assertCurrent();
    return JSON.parse(raw) as SftpDirectoryEntry[];
  }

  async readFileChunk(path: string, offset: number, length: number): Promise<ArrayBuffer> {
    this.assertCurrent();
    const bytes = await this.native.readFileChunk(this.id, path, offset, length);
    this.assertCurrent();
    return bytes;
  }

  private assertCurrent(): void {
    if (!this.current()) { throw new Error('SFTP session ended'); }
  }
}
