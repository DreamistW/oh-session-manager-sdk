import { util } from '@kit.ArkTS';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { fileIo } from '@kit.CoreFileKit';
import { SessionManagerNativeApi } from '../native/SessionManagerNativeApi';
import { KeyboardInteractiveChallenge } from '../protocol/KeyboardInteractiveChallenge';
import { RemoteMetricsPort } from '../protocol/RemoteMetricsPort';
import { HostKeyDecision, HostKeyRecord, HostKeyVerifier } from '../protocol/HostKey';
import { SessionConnectionResult } from '../protocol/SessionConnectionResult';
import { CredentialKind, TransportCredential, TransportProfile, SessionProtocol, isSshFileProtocol } from '../protocol/SessionOptions';
import { formatRemoteModifiedTime, RemoteEntry, sortRemoteEntries } from '../protocol/RemoteFileTypes';
import { SftpListingParser } from '../protocol/SftpListingParser';
import { SftpDeletePolicy } from '../protocol/SftpDeletePolicy';
import { TransportState } from '../protocol/TransportState';
import { MetricsCredentials } from '../protocol/MetricsCredentials';
import { SshMetricsConnection } from './SshMetricsConnection';
import { SftpReadAccess } from './SftpReadAccess';

class NativeConnectionInfo {
  sessionId: number = 0;
  fingerprint: string = '';
  hostKeyAlgorithm: string = '';
  kex: string = '';
  cipher: string = '';
  mac: string = '';
}

class NativeDirectoryEntry {
  name: string = '';
  isDirectory: boolean = false;
  isSymbolicLink: boolean = false;
  size: number = 0;
  modified: number = 0;
}

class SftpDeleteBudget {
  remaining: number = 10000;
  readonly deadline: number = Date.now() + 60000;
}

export class SshTransport {
  get transferGeneration(): number { return this.connectGeneration; }
  state: TransportState = TransportState.Disconnected;
  lastProfileId: string = '';
  lastAuthKind: string = '';
  reconnectCount: number = 0;
  lastError: string = '';
  onData: ((text: string) => void) | undefined = undefined;
  onKeyboardInteractivePrompt: ((challenge: KeyboardInteractiveChallenge) => void) | undefined = undefined;
  onKeyboardInteractiveComplete: (() => void) | undefined = undefined;
  private readonly metricsConnection: SshMetricsConnection;
  private readonly native: SessionManagerNativeApi;
  private readonly diagnosticsEnabled: () => boolean;

  constructor(native: SessionManagerNativeApi, diagnosticsEnabled: () => boolean = () => false) {
    this.native = native;
    this.metricsConnection = new SshMetricsConnection(native);
    this.diagnosticsEnabled = diagnosticsEnabled;
  }
  private metricsEnabled: boolean = false;
  private metricsRequested: boolean = true;
  private metricsProfile: TransportProfile | undefined = undefined;
  loadMetricsCredentials: (() => Promise<MetricsCredentials>) | undefined = undefined;
  get metricsEpoch(): number { return this.metricsConnection.epoch; }
  setMetricsEnabled(enabled: boolean): void {
    this.metricsRequested = enabled;
    if (!enabled) { this.metricsConnection.close(); }
  }
  private readAccess: SftpReadAccess | undefined = undefined;

  /** 暴露当前已认证会话的只读文件接口。 */
  get sftpReadAccess(): SftpReadAccess | undefined {
    return this.state === TransportState.Connected ? this.readAccess : undefined;
  }

  get remoteMetrics(): RemoteMetricsPort | undefined {
    return this.metricsEnabled && this.metricsRequested ? this : undefined;
  }

  private sessionId: number = 0;
  private scpFiles: boolean = false;
  private currentPath: string = '/';
  private homeDirectory: string = '/';
  private sftpPathValue: string = '/';
  private fingerprint: string = '';
  private hostKeyAlgorithm: string = '';
  private connectGeneration: number = 0;
  private commandChain: Promise<string> = Promise.resolve('');
  private captureOutput: boolean = false;
  private capturedText: string = '';
  private keyboardInteractiveActive: boolean = false;
  private keyboardPromptSequence: number = 0;
  private diagnosticWriteSequence: number = 0;
  private decoder: util.TextDecoder = util.TextDecoder.create('utf-8', {
    fatal: false,
    ignoreBOM: true
  });

  configure(_filesDir: string): void {
  }

  async runCryptoDiagnostics(): Promise<boolean> {
    try {
      const diagnostics: Promise<string> = this.native.runCryptoCompatibilityGate();
      const report: string = await diagnostics;
      return report.startsWith('OHCRYPTO_GATE_PASS');
    } catch (error) {
      this.lastError = this.errorText(error);
      return false;
    }
  }

  async collectRemoteMetrics(): Promise<string> {
    if (!this.metricsEnabled || !this.metricsRequested || this.sessionId <= 0 || this.state !== TransportState.Connected) {
      throw new Error('SSH session is not connected');
    }
    const startedAt = Date.now();
    const diagnostic = this.diagnosticsEnabled();
    if (diagnostic) {
      hilog.info(0x0000, 'TerminalInputDiag', 'ssh metrics start time=%{public}d', startedAt);
    }
    try {
      const profile = this.metricsProfile;
      const credentials = this.loadMetricsCredentials;
      if (profile === undefined || credentials === undefined) { throw new Error('metrics credentials unavailable'); }
      return await this.metricsConnection.collect(profile.host, profile.port, this.fingerprint, profile.username, credentials, profile.legacySsh);
    } finally {
      if (diagnostic) {
        hilog.info(0x0000, 'TerminalInputDiag', 'ssh metrics done elapsed=%{public}d time=%{public}d',
          Date.now() - startedAt, Date.now());
      }
    }
  }

  path(): string {
    return this.currentPath;
  }

  sftpPath(): string {
    return this.sftpPathValue;
  }

  homePath(): string {
    return this.homeDirectory;
  }

  presentedFingerprint(_profile: TransportProfile): string {
    return this.fingerprint;
  }

  presentedHostKeyAlgorithm(): string {
    return this.hostKeyAlgorithm;
  }

  verifyHostKey(store: HostKeyVerifier, profile: TransportProfile,
    trustUnknown: boolean): SessionConnectionResult {
    if (this.fingerprint.length === 0 || this.hostKeyAlgorithm.length === 0) {
      return new SessionConnectionResult(false, HostKeyDecision.Unknown,
        'Server host key is available only after the SSH handshake | ' + profile.endpoint());
    }
    return this.verifyPresentedHostKey(store, profile, trustUnknown);
  }

  async connect(store: HostKeyVerifier, profile: TransportProfile, credential: TransportCredential | undefined,
    secret: string, passphrase: string, trustUnknown: boolean): Promise<SessionConnectionResult> {
    this.lastError = '';
    if (credential === undefined) {
      this.state = TransportState.AuthFailed;
      this.lastAuthKind = 'none';
      return new SessionConnectionResult(false, HostKeyDecision.Trusted,
        'Authentication failed | none | ' + profile.endpoint());
    }
    this.disconnect();
    this.decoder = util.TextDecoder.create('utf-8', { fatal: false, ignoreBOM: true });
    const generation = ++this.connectGeneration;
    let authenticationStarted = false;
    let authenticationCompleted = false;
    let openingTerminal = false;
    try {
      const connectOperation: Promise<string> = this.native.connect(profile.host, profile.port, profile.legacySsh);
      const raw: string = await connectOperation;
      const connection = JSON.parse(raw) as NativeConnectionInfo;
      if (generation !== this.connectGeneration || connection.sessionId <= 0) {
        if (connection.sessionId > 0) {
          const cancelOperation: Promise<boolean> = this.native.disconnect(connection.sessionId);
          await cancelOperation;
        }
        return new SessionConnectionResult(false, HostKeyDecision.Unknown, 'SSH connection cancelled');
      }
      this.sessionId = connection.sessionId;
      this.fingerprint = connection.fingerprint;
      this.hostKeyAlgorithm = connection.hostKeyAlgorithm;
      const hostResult = this.verifyPresentedHostKey(store, profile, trustUnknown);
      if (!hostResult.connected) {
        const rejectedSessionId = this.sessionId;
        this.sessionId = 0;
        try {
          const disconnectOperation: Promise<boolean> = this.native.disconnect(rejectedSessionId);
          await disconnectOperation;
        } catch (_cleanupError) {}
        return hostResult;
      }
      const acceptHostKeyOperation: Promise<boolean> = this.native.acceptHostKey(this.sessionId, true);
      await acceptHostKeyOperation;
      authenticationStarted = true;
      const authentication: Promise<boolean> = this.native.authenticate(this.sessionId, profile.username,
        credential.kind,
        credential.kind === CredentialKind.KeyboardInteractive ? '' : secret, passphrase);
      if (credential.kind === CredentialKind.KeyboardInteractive) {
        this.keyboardInteractiveActive = true;
        this.keyboardPromptSequence = 0;
        this.pollKeyboardInteractive(generation, this.sessionId);
      }
      try {
        if (!await authentication) {
          if (generation !== this.connectGeneration) {
            return new SessionConnectionResult(false, HostKeyDecision.Unknown, 'SSH connection cancelled');
          }
          this.disconnect();
          this.state = TransportState.PasswordRequired;
          return new SessionConnectionResult(false, HostKeyDecision.Trusted, '');
        }
        authenticationCompleted = true;
      } finally {
        this.finishKeyboardInteractive();
      }
      this.scpFiles = profile.protocol === SessionProtocol.SCP;
      if (!isSshFileProtocol(profile.protocol)) {
        openingTerminal = true;
        const openPtyOperation: Promise<boolean> = this.native.openPty(this.sessionId, 'xterm-256color', 80, 24);
        await openPtyOperation;
        openingTerminal = false;
      }
      if (isSshFileProtocol(profile.protocol)) {
        await this.openFileChannel(connection.sessionId);
      }
      if (generation !== this.connectGeneration) {
        return new SessionConnectionResult(false, HostKeyDecision.Unknown, 'SSH connection cancelled');
      }
      const wasReconnect = this.lastProfileId === profile.id;
      this.state = TransportState.Connected;
      this.lastProfileId = profile.id;
      this.lastAuthKind = credential.kind;
      this.commandChain = Promise.resolve('');
      if (!isSshFileProtocol(profile.protocol)) {
        this.startReadPump(generation);
      }
      if (wasReconnect) {
        this.reconnectCount++;
      }
      this.metricsEnabled = profile.protocol === SessionProtocol.SSH &&
        credential.kind !== CredentialKind.KeyboardInteractive;
      this.metricsProfile = this.metricsEnabled ? profile : undefined;
      return new SessionConnectionResult(true, HostKeyDecision.Trusted,
        (wasReconnect ? 'Reconnected' : hostResult.message) + ' | ' + profile.endpoint() +
        ' | ' + connection.kex + ' | ' + connection.cipher + ' | ' + connection.mac);
    } catch (error) {
      const authenticationFailed = authenticationStarted && !authenticationCompleted;
      this.state = openingTerminal ? TransportState.TerminalOpenFailed :
        (authenticationCompleted && isSshFileProtocol(profile.protocol) ? TransportState.SftpOpenFailed :
          (authenticationFailed ? TransportState.AuthFailed : TransportState.Disconnected));
      this.lastAuthKind = credential.kind;
      const detail = this.errorText(error);
      this.lastError = (authenticationFailed ? 'Authentication failed | ' :
        (detail.indexOf('timed out') >= 0 ? 'SSH connection timed out | ' : 'SSH connection failed | ')) +
        profile.endpoint() + ' | ' + detail;
      const id = this.sessionId;
      this.sessionId = 0;
      if (id > 0) {
        try {
          const disconnectOperation: Promise<boolean> = Promise.resolve(this.native.disconnect(id));
          await disconnectOperation;
        } catch (_disconnectError) {
        }
      }
      return new SessionConnectionResult(false, HostKeyDecision.Trusted, this.lastError, detail);
    }
  }

  disconnect(): void {
    this.connectGeneration++;
    this.readAccess = undefined;
    this.metricsEnabled = false;
    this.metricsProfile = undefined;
    this.metricsConnection.close();
    this.finishKeyboardInteractive();
    const id = this.sessionId;
    this.sessionId = 0;
    if (id > 0) {
      this.native.disconnect(id).catch((error: Object): void => {
        this.lastError = this.errorText(error);
      });
    }
    this.state = TransportState.Disconnected;
    this.currentPath = '/';
    this.homeDirectory = '/';
    this.sftpPathValue = '/';
    this.fingerprint = '';
    this.hostKeyAlgorithm = '';
    this.captureOutput = false;
    this.capturedText = '';
    this.commandChain = Promise.resolve('');
  }

  async primeHomeDirectory(): Promise<string> {
    return this.homeDirectory;
  }

  execute(command: string): Promise<string> {
    if (this.sessionId <= 0 || this.state !== TransportState.Connected) {
      return Promise.resolve('ssh: not connected');
    }
    const next = this.commandChain.then((): Promise<string> => this.executeCaptured(command));
    this.commandChain = next.then((): string => '', (): string => '');
    return next;
  }

  executeSftp(_command: string): Promise<string> {
    return Promise.resolve('sftp: shell command emulation disabled');
  }

  async listDirectory(path: string): Promise<RemoteEntry[]> {
    if (this.sessionId <= 0) {
      return [];
    }
    const listOperation: Promise<string> = this.native.listDirectory(this.sessionId, path);
    const raw: string = await listOperation;
    const nativeEntries = JSON.parse(raw) as NativeDirectoryEntry[];
    const entries: RemoteEntry[] = [];
    if (path !== '/') {
      entries.push(new RemoteEntry('..', '', '', true));
    }
    nativeEntries.forEach((entry: NativeDirectoryEntry): void => {
      entries.push(new RemoteEntry(entry.name, this.formatSize(entry.size, entry.isDirectory),
        formatRemoteModifiedTime(entry.modified), entry.isDirectory, entry.size, entry.modified,
        entry.isSymbolicLink));
    });
    return sortRemoteEntries(entries);
  }

  async changeDirectory(target: string): Promise<boolean> {
    const next = SftpListingParser.resolve(this.currentPath, target, this.homeDirectory);
    const raw = await this.execute('cd ' + SftpListingParser.quote(next) + ' && pwd');
    const lines = raw.replace(/\r/g, '').split('\n');
    for (let index = 0; index < lines.length; index++) {
      const value = lines[index].trim();
      if (value.charAt(0) === '/') {
        this.currentPath = value;
        return true;
      }
    }
    return false;
  }

  async changeSftpDirectory(target: string): Promise<boolean> {
    const next = SftpListingParser.resolve(this.sftpPathValue, target, this.homeDirectory);
    try {
      const listOperation: Promise<string> = this.native.listDirectory(this.sessionId, next);
      await listOperation;
      this.sftpPathValue = next;
      return true;
    } catch (error) {
      this.lastError = this.errorText(error);
      return false;
    }
  }

  goSftpHome(): void {
    this.sftpPathValue = this.homeDirectory;
  }

  async removeEntry(remotePath: string, isDirectory: boolean): Promise<boolean> {
    if (this.sessionId <= 0) {
      throw new Error('SSH session is not connected');
    }
    if (!SftpDeletePolicy.isSafePath(remotePath)) {
      throw new Error('Unsafe SFTP delete path');
    }
    return await this.removeTreeEntry(this.sessionId, this.connectGeneration, remotePath, isDirectory,
      new SftpDeleteBudget(), 0);
  }

  private async removeTreeEntry(sessionId: number, generation: number, path: string, isDirectory: boolean,
    budget: SftpDeleteBudget, depth: number): Promise<boolean> {
    this.assertDeleteCurrent(sessionId, generation, budget);
    if (depth > 64 || budget.remaining-- <= 0 || !SftpDeletePolicy.isSafePath(path)) {
      throw new Error('SFTP recursive delete exceeds safe limits');
    }
    if (isDirectory) {
      // The native listing rejects symbolic links and non-canonical ancestors.
      // Each awaited native operation yields the session worker to PTY traffic.
      const listOperation: Promise<string> = this.native.listDeleteDirectory(sessionId, path);
      const raw: string = await listOperation;
      this.assertDeleteCurrent(sessionId, generation, budget);
      const entries: NativeDirectoryEntry[] = JSON.parse(raw) as NativeDirectoryEntry[];
      if (entries.length > budget.remaining || entries.some((entry: NativeDirectoryEntry): boolean =>
        SftpDeletePolicy.child(path, entry.name).length === 0)) {
        throw new Error('SFTP recursive delete listing is unsafe');
      }
      let failed = false;
      for (let index = 0; index < entries.length; index++) {
        const entry = entries[index];
        try {
          if (!await this.removeTreeEntry(sessionId, generation, SftpDeletePolicy.child(path, entry.name),
            entry.isDirectory, budget, depth + 1)) {
            failed = true;
          }
        } catch (_error) {
          this.assertDeleteCurrent(sessionId, generation, budget);
          failed = true;
        }
      }
      if (failed) {
        throw new Error('SFTP recursive delete partially failed');
      }
    }
    this.assertDeleteCurrent(sessionId, generation, budget);
    const removeOperation: Promise<boolean> = this.native.removeEntry(sessionId, path, isDirectory);
    const removed: boolean = await removeOperation;
    this.assertDeleteCurrent(sessionId, generation, budget);
    return removed;
  }

  private assertDeleteCurrent(sessionId: number, generation: number, budget: SftpDeleteBudget): void {
    if (this.sessionId !== sessionId || this.connectGeneration !== generation ||
      this.state !== TransportState.Connected || Date.now() >= budget.deadline) {
      throw new Error('SFTP recursive delete interrupted');
    }
  }

  async createDirectory(remotePath: string): Promise<boolean> {
    if (this.sessionId <= 0) {
      throw new Error('SSH session is not connected');
    }
    if (remotePath.length === 0 || remotePath === '/' || remotePath.indexOf('\u0000') >= 0 ||
      remotePath.endsWith('/.') || remotePath.endsWith('/..')) {
      throw new Error('Unsafe SFTP directory path');
    }
    return await this.native.createDirectory(this.sessionId, remotePath);
  }

  async downloadToFile(remotePath: string, localUri: string,
    onProgress: (bytesDone: number) => void, isCancelled: () => boolean): Promise<number> {
    if (this.sessionId <= 0) {
      return 0;
    }
    const file = fileIo.openSync(localUri, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE |
      fileIo.OpenMode.TRUNC);
    let offset = 0;
    let failure: Object | undefined = undefined;
    const chunkSize = 128 * 1024;
    try {
      if (this.scpFiles) {
        const received = await this.transferScp(file.fd, remotePath, false, 0, onProgress, isCancelled);
        fileIo.fsyncSync(file.fd);
        return received;
      }
      for (;;) {
        if (isCancelled()) {
          throw new Error('transfer cancelled');
        }
        const readOperation: Promise<ArrayBuffer> =
          this.native.readFileChunk(this.sessionId, remotePath, offset, chunkSize);
        const buffer: ArrayBuffer = await readOperation;
        if (buffer.byteLength === 0) {
          break;
        }
        const written = fileIo.writeSync(file.fd, buffer);
        if (written !== buffer.byteLength) {
          throw new Error('short local file write');
        }
        offset += buffer.byteLength;
        onProgress(offset);
        await this.delay(0);
      }
      fileIo.fsyncSync(file.fd);
    } catch (error) {
      failure = error;
    } finally {
      fileIo.closeSync(file.fd);
    }
    if (failure !== undefined) {
      try {
        fileIo.unlinkSync(localUri);
      } catch (_unlinkError) {
      }
      throw new Error(this.errorText(failure));
    }
    return offset;
  }

  async uploadFromFile(localUri: string, remotePath: string,
    onProgress: (bytesDone: number) => void, isCancelled: () => boolean): Promise<number> {
    const id = this.sessionId;
    if (id <= 0) {
      return 0;
    }
    const file = fileIo.openSync(localUri, fileIo.OpenMode.READ_ONLY);
    const total = fileIo.statSync(file.fd).size;
    const chunkSize = 128 * 1024;
    let offset = 0;
    let writeStarted = false;
    try {
      if (this.scpFiles) {
        return await this.transferScp(file.fd, remotePath, true, total, onProgress, isCancelled);
      }
      if (total === 0 && !isCancelled()) {
        // 空文件也需要打开并截断远端目标。
        writeStarted = true;
        await this.native.writeFileChunk(id, remotePath, 0, new ArrayBuffer(0), true);
      }
      while (offset < total) {
        if (isCancelled() || id !== this.sessionId) {
          throw new Error('transfer cancelled');
        }
        const buffer = new ArrayBuffer(Math.min(chunkSize, total - offset));
        const count = fileIo.readSync(file.fd, buffer, { offset: offset, length: buffer.byteLength });
        if (count <= 0) {
          break;
        }
        const chunk = count === buffer.byteLength ? buffer : buffer.slice(0, count);
        writeStarted = true;
        const writeOperation: Promise<number> = this.native.writeFileChunk(id, remotePath, offset,
          chunk, offset === 0);
        const written: number = await writeOperation;
        if (written !== count) {
          throw new Error('short SFTP write');
        }
        offset += written;
        onProgress(offset);
        await this.delay(0);
      }
      if (isCancelled() || id !== this.sessionId) {
        throw new Error('transfer cancelled');
      }
      return offset;
    } catch (error) {
      if (writeStarted) {
        // 取消前未写入时保留原目标；清理只使用发起写入的会话。
        await this.native.removeEntry(id, remotePath, false).catch((): boolean => false);
      }
      throw new Error(this.errorText(error));
    } finally {
      fileIo.closeSync(file.fd);
    }
  }

  // SCP 的每个文件单独协商通道，分块让出工作线程供取消和其他标签继续运行。
  private async transferScp(fd: number, path: string, upload: boolean, size: number,
    onProgress: (bytes: number) => void, isCancelled: () => boolean): Promise<number> {
    const id = this.sessionId;
    if (isCancelled()) { throw new Error('transfer cancelled'); }
    const handle: number = await this.native.beginScp(id, path, upload, size);
    let done = 0;
    let complete = false;
    try {
      while (!isCancelled() && this.sessionId === id) {
        const count: number = await this.native.stepScp(id, handle, fd);
        if (count === 0) { complete = true; break; }
        done += count;
        onProgress(done);
      }
      if (!complete) { throw new Error('transfer cancelled'); }
    } finally {
      if (complete) { await this.native.endScp(id, handle, true); }
      else { await this.native.endScp(id, handle, false).catch((): void => {}); }
    }
    return done;
  }

  authKindLabel(credential: TransportCredential | undefined): string {
    if (credential === undefined) {
      return 'none';
    }
    if (credential.kind === CredentialKind.PrivateKey) {
      return CredentialKind.PrivateKey;
    }
    if (credential.kind === CredentialKind.KeyboardInteractive) {
      return CredentialKind.KeyboardInteractive;
    }
    return CredentialKind.Password;
  }

  // SSH 的文件通道独立于已打开的 PTY；纯 SFTP 会话在 connect 中完成初始化。
  async startSftpSession(profile: TransportProfile, _secret: string): Promise<boolean> {
    const id = this.sessionId;
    if (id <= 0 || this.state !== TransportState.Connected) { return false; }
    if (profile.protocol === SessionProtocol.SSH) {
      await this.openFileChannel(id);
      if (this.sessionId !== id) { return false; }
      this.readAccess = new SftpReadAccess(this.native, id, this.homeDirectory,
        (): boolean => id === this.sessionId && this.state === TransportState.Connected);
    }
    return true;
  }

  private async openFileChannel(id: number): Promise<void> {
    const opening: Promise<string> = this.native.openSftp(id);
    const home: string = await opening;
    if (this.sessionId !== id) { throw new Error('SFTP session closed'); }
    this.homeDirectory = home;
    this.currentPath = home;
    this.sftpPathValue = home;
  }

  resize(columns: number, rows: number): Promise<boolean> {
    if (this.sessionId <= 0) {
      return Promise.resolve(false);
    }
    return this.native.resizePty(this.sessionId, columns, rows);
  }

  writeBytes(bytes: Uint8Array): Promise<number> {
    return this.sessionId > 0 ? this.native.write(this.sessionId, bytes.buffer as ArrayBuffer) : Promise.resolve(0);
  }

  writeRaw(text: string): Promise<number> {
    if (this.sessionId <= 0) {
      return Promise.resolve(0);
    }
    const sequence = ++this.diagnosticWriteSequence;
    const bytes = this.encodeUtf8(text);
    if (this.diagnosticsEnabled()) { hilog.info(0x0000, 'TerminalInputDiag',
      'ssh write start id=%{public}d bytes=%{public}d time=%{public}d',
      sequence, bytes.byteLength, Date.now()); }
    return this.native.write(this.sessionId, bytes).then((written: number): number => {
      if (this.diagnosticsEnabled()) {
        hilog.info(0x0000, 'TerminalInputDiag',
          'ssh write done id=%{public}d written=%{public}d time=%{public}d', sequence, written, Date.now());
      }
      return written;
    }).catch((): number => {
      if (this.diagnosticsEnabled()) {
        hilog.warn(0x0000, 'TerminalInputDiag', 'ssh write failed id=%{public}d time=%{public}d', sequence, Date.now());
      }
      throw new Error('SSH write failed');
    });
  }

  respondKeyboardInteractive(response: string): boolean {
    if (!this.keyboardInteractiveActive || this.sessionId <= 0) {
      return false;
    }
    try {
      return this.native.respondKeyboardInteractive(this.sessionId, response);
    } catch (_error) {
      return false;
    }
  }

  private verifyPresentedHostKey(store: HostKeyVerifier, profile: TransportProfile,
    trustUnknown: boolean): SessionConnectionResult {
    const presented = new HostKeyRecord(profile.host, profile.port, this.hostKeyAlgorithm, this.fingerprint);
    const decision = store.verify(presented);
    if (decision === HostKeyDecision.Mismatch) {
      this.state = TransportState.HostKeyBlocked;
      return new SessionConnectionResult(false, decision,
        'Host key mismatch for ' + presented.key() + ' | connection refused');
    }
    if (decision === HostKeyDecision.Unknown && !trustUnknown) {
      this.state = TransportState.Disconnected;
      return new SessionConnectionResult(false, decision,
        'Unknown host key for ' + presented.key() + ' | ' + this.hostKeyAlgorithm + ' ' + this.fingerprint);
    }
    if (decision === HostKeyDecision.Unknown) {
      store.trust(presented);
      return new SessionConnectionResult(true, HostKeyDecision.Trusted,
        'Trusted host key on first use');
    }
    return new SessionConnectionResult(true, decision, 'Host key trusted');
  }

  private pollKeyboardInteractive(generation: number, id: number): void {
    if (!this.keyboardInteractiveActive || generation !== this.connectGeneration || id !== this.sessionId) {
      return;
    }
    try {
      const raw: string = this.native.keyboardInteractivePrompt(id);
      const challenge = JSON.parse(raw) as KeyboardInteractiveChallenge;
      if (challenge.pending && challenge.sequence > 0 && challenge.sequence !== this.keyboardPromptSequence) {
        this.keyboardPromptSequence = challenge.sequence;
        const listener = this.onKeyboardInteractivePrompt;
        if (listener !== undefined) {
          listener(challenge);
        }
      }
    } catch (_error) {
    }
    setTimeout((): void => this.pollKeyboardInteractive(generation, id), 16);
  }

  private finishKeyboardInteractive(): void {
    const wasActive = this.keyboardInteractiveActive || this.keyboardPromptSequence > 0;
    this.keyboardInteractiveActive = false;
    this.keyboardPromptSequence = 0;
    if (wasActive) {
      const listener = this.onKeyboardInteractiveComplete;
      if (listener !== undefined) {
        listener();
      }
    }
  }

  private async executeCaptured(command: string): Promise<string> {
    this.captureOutput = true;
    this.capturedText = '';
    try {
      const writeOperation: Promise<number> = this.native.write(this.sessionId, this.encodeUtf8(command + '\r'));
      await writeOperation;
      await this.delay(350);
      return this.capturedText;
    } finally {
      this.captureOutput = false;
      this.capturedText = '';
    }
  }

  private startReadPump(generation: number): void {
    if (generation !== this.connectGeneration || this.sessionId <= 0) {
      return;
    }
    const id = this.sessionId;
    this.native.read(id, 64 * 1024).then((buffer: ArrayBuffer): void => {
      if (generation !== this.connectGeneration || id !== this.sessionId) {
        return;
      }
      const bytes = new Uint8Array(buffer);
      if (bytes.byteLength > 0) {
        if (this.diagnosticsEnabled()) { hilog.info(0x0000, 'TerminalInputDiag', 'ssh read bytes=%{public}d time=%{public}d',
          bytes.byteLength, Date.now()); }
        const text = this.decoder.decodeToString(bytes, { stream: true });
        if (this.captureOutput) {
          this.capturedText += text;
        } else if (this.onData !== undefined && text.length > 0) {
          this.onData(text);
        }
      }
      setTimeout((): void => this.startReadPump(generation), bytes.byteLength > 0 ? 0 : 16);
    }).catch((error: Object): void => {
      if (generation === this.connectGeneration) {
        this.lastError = this.errorText(error);
        this.disconnect();
      }
    });
  }

  private encodeUtf8(text: string): ArrayBuffer {
    const encoder = new util.TextEncoder('utf-8');
    const bytes = encoder.encodeInto(text);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  private formatSize(bytes: number, isDirectory: boolean): string {
    if (isDirectory) {
      return '';
    }
    if (bytes >= 1024 * 1024) {
      return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }
    if (bytes >= 1024) {
      return (bytes / 1024).toFixed(1) + ' KB';
    }
    return bytes.toString() + ' B';
  }

  private delay(milliseconds: number): Promise<void> {
    return new Promise<void>((resolve: () => void): void => {
      setTimeout(resolve, milliseconds);
    });
  }

  private errorText(error: Object): string {
    const record = error as Record<string, Object>;
    const message = record['message'];
    const raw = typeof message === 'string' && message.length > 0 ? message : error.toString();
    const text = raw.length > 0 && raw !== '[object Object]' ? raw : 'unknown SSH error';
    return text.replace(/\/(?:home|root|Users|var|opt|tmp|mnt|data)[^\s|]*/g, '[remote path]');
  }
}
