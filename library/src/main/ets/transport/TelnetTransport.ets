import { socketError } from '../protocol/SocketError';
/*
 * Copyright (c) 2026 HomoXterm contributors.
 * Licensed under the Apache License, Version 2.0.
 */

import { util } from '@kit.ArkTS';
import { socket } from '@kit.NetworkKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { KeyboardInteractiveChallenge } from '../protocol/KeyboardInteractiveChallenge';
import { HostKeyDecision, HostKeyVerifier } from '../protocol/HostKey';
import { SessionConnectionResult } from '../protocol/SessionConnectionResult';
import { TransportCredential, TransportProfile } from '../protocol/SessionOptions';
import { RemoteEntry } from '../protocol/RemoteFileTypes';
import { TelnetCodec } from '../protocol/TelnetCodec';
import { TransportState } from '../protocol/TransportState';

/** Telnet 连接只持有本实例的 TCP 通道和协商状态。 */
export class TelnetTransport {
  private readonly diagnosticsEnabled: () => boolean;

  constructor(diagnosticsEnabled: () => boolean = () => false) {
    this.diagnosticsEnabled = diagnosticsEnabled;
  }

  state: TransportState = TransportState.Disconnected;
  onData: ((text: string) => void) | undefined = undefined;
  onKeyboardInteractivePrompt: ((challenge: KeyboardInteractiveChallenge) => void) | undefined = undefined;
  onKeyboardInteractiveComplete: (() => void) | undefined = undefined;
  private client: socket.TCPSocket | undefined = undefined;
  private generation: number = 0;
  private codec: TelnetCodec = new TelnetCodec();
  private decoder: util.TextDecoder = util.TextDecoder.create('utf-8', { fatal: false, ignoreBOM: true });
  private diagnosticWriteSequence: number = 0;

  async connect(_hostKeys: HostKeyVerifier, profile: TransportProfile, _credential: TransportCredential | undefined,
    _secret: string, _passphrase: string, _trustUnknown: boolean): Promise<SessionConnectionResult> {
    this.disconnect();
    const generation = ++this.generation;
    this.codec = new TelnetCodec();
    this.decoder = util.TextDecoder.create('utf-8', { fatal: false, ignoreBOM: true });
    const client = socket.constructTCPSocketInstance();
    this.client = client;
    client.on('message', (message: socket.SocketMessageInfo): void => this.receive(generation, message));
    client.on('close', (): void => this.closed(generation));
    client.on('error', (): void => this.failed(generation));
    try {
      await client.connect({ address: { address: profile.host, port: profile.port }, timeout: 10000 });
      if (generation !== this.generation || this.client !== client) {
        await client.close();
        return new SessionConnectionResult(false, HostKeyDecision.Trusted, 'Telnet connection cancelled');
      }
      this.state = TransportState.Connected;
      await client.setExtraOptions({ TCPNoDelay: true, keepAlive: true });
      return new SessionConnectionResult(true, HostKeyDecision.Trusted,
        'Telnet connected using plaintext transport | ' + profile.host + ':' + profile.port.toString());
    } catch (error) {
      if (this.client === client) {
        this.client = undefined;
      }
      this.state = TransportState.Disconnected;
      client.close().catch((): void => {});
      const detail = socketError(error) || 'Telnet connection failed';
      return new SessionConnectionResult(false, HostKeyDecision.Trusted, detail, detail);
    }
  }

  disconnect(): void {
    this.generation++;
    const client = this.client;
    this.client = undefined;
    this.state = TransportState.Disconnected;
    if (client !== undefined) {
      client.off('message');
      client.off('close');
      client.off('error');
      client.close().catch((): void => {});
    }
  }

  writeBytes(bytes: Uint8Array): Promise<number> {
    return this.send(this.codec.encode(bytes)).then((): number => bytes.byteLength);
  }

  async writeRaw(text: string): Promise<number> {
    const bytes = new util.TextEncoder('utf-8').encodeInto(text);
    const sequence = ++this.diagnosticWriteSequence;
    if (this.diagnosticsEnabled()) { hilog.info(0x0000, 'TerminalInputDiag',
      'telnet write start id=%{public}d bytes=%{public}d time=%{public}d',
      sequence, bytes.byteLength, Date.now()); }
    try {
      await this.send(this.codec.encode(bytes));
      if (this.diagnosticsEnabled()) { hilog.info(0x0000, 'TerminalInputDiag',
        'telnet write done id=%{public}d written=%{public}d time=%{public}d',
        sequence, bytes.byteLength, Date.now()); }
      return bytes.byteLength;
    } catch {
      if (this.diagnosticsEnabled()) { hilog.warn(0x0000, 'TerminalInputDiag', 'telnet write failed id=%{public}d time=%{public}d',
        sequence, Date.now()); }
      throw new Error('Telnet write failed');
    }
  }

  resize(columns: number, rows: number): Promise<boolean> {
    if (this.client === undefined || this.state !== TransportState.Connected) {
      return Promise.resolve(false);
    }
    return this.send(this.codec.windowSize(columns, rows)).then((): boolean => true, (): boolean => false);
  }

  runCryptoDiagnostics(): Promise<boolean> { return Promise.resolve(false); }
  presentedFingerprint(_profile: TransportProfile): string { return ''; }
  presentedHostKeyAlgorithm(): string { return ''; }
  respondKeyboardInteractive(_response: string): boolean { return false; }
  startSftpSession(_profile: TransportProfile, _secret: string): Promise<boolean> { return Promise.resolve(false); }
  sftpPath(): string { return '/'; }
  primeHomeDirectory(): Promise<string> { return Promise.resolve('/'); }
  listDirectory(_path: string): Promise<RemoteEntry[]> { return Promise.resolve([]); }
  changeSftpDirectory(_target: string): Promise<boolean> { return Promise.resolve(false); }
  goSftpHome(): void {}
  removeEntry(_remotePath: string, _isDirectory: boolean): Promise<boolean> { return Promise.resolve(false); }
  createDirectory(_remotePath: string): Promise<boolean> { return Promise.resolve(false); }
  downloadToFile(_remotePath: string, _localUri: string, _onProgress: (bytesDone: number) => void,
    _isCancelled: () => boolean): Promise<number> { return Promise.reject(new Error('SFTP unavailable for Telnet')); }
  uploadFromFile(_localUri: string, _remotePath: string, _onProgress: (bytesDone: number) => void,
    _isCancelled: () => boolean): Promise<number> { return Promise.reject(new Error('SFTP unavailable for Telnet')); }

  private receive(generation: number, message: socket.SocketMessageInfo): void {
    if (generation !== this.generation || this.client === undefined) {
      return;
    }
    const decoded = this.codec.decode(new Uint8Array(message.message));
    if (decoded.reply.length > 0) {
      this.send(new Uint8Array(decoded.reply)).catch((): void => this.failed(generation));
    }
    if (decoded.data.length > 0) {
      if (this.diagnosticsEnabled()) { hilog.info(0x0000, 'TerminalInputDiag', 'telnet read bytes=%{public}d time=%{public}d',
        decoded.data.length, Date.now()); }
      const text = this.decoder.decodeToString(new Uint8Array(decoded.data), { stream: true });
      if (text.length > 0) {
        this.onData?.(text);
      }
    }
  }

  private send(bytes: Uint8Array): Promise<void> {
    const client = this.client;
    if (client === undefined || this.state !== TransportState.Connected) {
      return Promise.reject(new Error('Telnet is not connected'));
    }
    const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    return client.send({ data: buffer });
  }

  private closed(generation: number): void {
    if (generation === this.generation) {
      this.client = undefined;
      this.state = TransportState.Disconnected;
    }
  }

  private failed(generation: number): void {
    if (generation === this.generation) {
      this.disconnect();
    }
  }
}
