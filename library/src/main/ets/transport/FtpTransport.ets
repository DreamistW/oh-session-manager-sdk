import { SessionManagerNativeApi } from '../native/SessionManagerNativeApi';
import { socketError } from '../protocol/SocketError';
import { fileIo } from '@kit.CoreFileKit';
import { FtpSocket } from './FtpSocket';
import { util } from '@kit.ArkTS';
import { KeyboardInteractiveChallenge } from '../protocol/KeyboardInteractiveChallenge';
import { HostKeyDecision, HostKeyVerifier } from '../protocol/HostKey';
import { SessionConnectionResult } from '../protocol/SessionConnectionResult';
import { TransportCredential, TransportProfile, SessionProtocol } from '../protocol/SessionOptions';
import { TransportState } from '../protocol/TransportState';
import { RemoteEntry } from '../protocol/RemoteFileTypes';
import { SftpListingParser } from '../protocol/SftpListingParser';
import { FtpPassiveEndpoint, FtpProtocol, FtpReply, FtpReplyParser } from '../protocol/FtpProtocol';

const FTP_TIMEOUT_MS = 15000;
const FTP_CHUNK_SIZE = 128 * 1024;

class FtpTraversalBudget {
  remaining: number = 10000;
}

class PendingFtpReply {
  readonly resolve: (reply: FtpReply) => void;
  readonly reject: (error: Error) => void;
  readonly timeoutId: number;

  constructor(resolve: (reply: FtpReply) => void, reject: (error: Error) => void, timeoutId: number) {
    this.resolve = resolve;
    this.reject = reject;
    this.timeoutId = timeoutId;
  }
}

class FtpDataConnection {
  readonly tcp: FtpSocket;
  readonly completed: Promise<void>;
  private complete: () => void = (): void => {};
  private fail: (error: Error) => void = (_error: Error): void => {};
  private settled: boolean = false;

  constructor(tcp: FtpSocket) {
    this.tcp = tcp;
    this.completed = new Promise<void>((resolve: () => void, reject: (error: Error) => void): void => {
      this.complete = resolve;
      this.fail = reject;
    });
  }

  connected(onBytes: (bytes: Uint8Array) => void): void {
    const message = (bytes: ArrayBuffer): void => {
      if (this.settled) { return; }
      try { onBytes(new Uint8Array(bytes)); }
      catch (error) { this.reject(error instanceof Error ? error : new Error('FTP data processing failed')); }
    };
    const closed = (): void => this.resolve();
    const failed = (): void => this.reject(new Error('FTP data connection failed'));
    this.tcp.listen(message, closed, failed);
  }

  async send(bytes: Uint8Array): Promise<void> {
    const data = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    await this.tcp.send(data);
  }

  async close(): Promise<void> {
    try {
      await this.tcp.close();
    } finally {
      this.resolve();
    }
  }

  abort(error: Error): void {
    this.reject(error);
    this.tcp.close().catch((): void => {});
  }

  private resolve(): void {
    if (!this.settled) { this.settled = true; this.complete(); }
  }

  private reject(error: Error): void {
    if (!this.settled) { this.settled = true; this.fail(error); }
  }
}

export class FtpTransport {
  get transferGeneration(): number { return this.generation; }
  state: TransportState = TransportState.Disconnected;
  onData: ((text: string) => void) | undefined = undefined;
  onKeyboardInteractivePrompt: ((challenge: KeyboardInteractiveChallenge) => void) | undefined = undefined;
  onKeyboardInteractiveComplete: (() => void) | undefined = undefined;
  private secure: boolean = false;
  private readonly trustedCa: string | undefined;
  private readonly native: SessionManagerNativeApi;

  constructor(native: SessionManagerNativeApi, trustedCa?: string) {
    this.native = native;
    this.trustedCa = trustedCa;
  }
  private controlTcp: FtpSocket | undefined = undefined;
  private decoder: util.TextDecoder = util.TextDecoder.create('utf-8', { fatal: false, ignoreBOM: true });
  private readonly encoder: util.TextEncoder = new util.TextEncoder('utf-8');
  private parser: FtpReplyParser = new FtpReplyParser();
  private pending: PendingFtpReply | undefined = undefined;
  private readonly queuedReplies: FtpReply[] = [];
  private activeData: FtpDataConnection | undefined = undefined;
  private currentPath: string = '/';
  private homePath: string = '/';
  private host: string = '';
  private port: number = 21;
  private generation: number = 0;
  private operationChain: Promise<boolean> = Promise.resolve(true);

  async connect(_hostKeys: HostKeyVerifier, profile: TransportProfile, _credential: TransportCredential | undefined,
    secret: string, _passphrase: string, _trustUnknown: boolean): Promise<SessionConnectionResult> {
    this.disconnect();
    const generation = ++this.generation;
    this.host = profile.host;
    this.port = profile.port;
    this.decoder = util.TextDecoder.create('utf-8', { fatal: false, ignoreBOM: true });
    this.parser = new FtpReplyParser();
    this.state = TransportState.Disconnected;
    let failureDetail = '';
    try {
      this.secure = profile.protocol === SessionProtocol.FTPS || profile.protocol === SessionProtocol.FTPSImplicit;
      const implicit = profile.protocol === SessionProtocol.FTPSImplicit;
      const tcp = new FtpSocket(this.native, this.host, this.port, this.trustedCa);
      this.controlTcp = tcp;
      if (implicit) {
        await tcp.connectTcp();
        tcp.prepareTls();
      }
      this.attachTcpControl(tcp, generation);
      const greeting = this.waitReply();
      const connected = implicit ? tcp.connectTls() : tcp.connectTcp();
      const responses = await Promise.all([greeting, connected]);
      const reply = responses[0];
      if (reply.code === 0) {
        failureDetail = reply.text;
        throw new Error('FTP protocol mismatch');
      }
      this.requireReply(reply, [220], true);
      if (profile.protocol === SessionProtocol.FTPS) {
        this.requireReply(await this.command('AUTH TLS'), [234], true);
        tcp.prepareTls();
        this.queuedReplies.length = 0;
        this.parser = new FtpReplyParser();
        this.attachTcpControl(tcp, generation);
        await tcp.connectTls();
      }
      if (generation !== this.generation) { throw new Error('FTP connection cancelled'); }
      const user = await this.command('USER ' + profile.username);
      if (user.code === 331) {
        const password = await this.command('PASS ' + secret);
        if (password.code !== 230) {
          failureDetail = password.text;
          if (password.code === 530 && !FtpProtocol.requiresTls(password.text)) {
            this.state = TransportState.AuthFailed;
            throw new Error('FTP authentication failed | server methods: password');
          }
          throw new Error(failureDetail);
        }
      } else {
        if (user.code === 530 && !FtpProtocol.requiresTls(user.text)) {
          this.state = TransportState.AuthFailed;
          failureDetail = user.text;
          throw new Error('FTP username rejected');
        }
        this.requireReply(user, [230], true);
      }
      if (this.secure) {
        this.requireReply(await this.command('PBSZ 0'), [200], true);
        this.requireReply(await this.command('PROT P'), [200], true);
      }
      this.requireReply(await this.command('TYPE I'), [200], true);
      await this.command('OPTS UTF8 ON');
      const pwd = await this.command('PWD');
      if (pwd.code === 257) {
        this.currentPath = FtpProtocol.pathFromPwd(pwd);
        this.homePath = this.currentPath;
      }
      if (generation !== this.generation) { throw new Error('FTP connection cancelled'); }
      this.state = TransportState.Connected;
      return new SessionConnectionResult(true, HostKeyDecision.Trusted,
        profile.protocol + ' connected | ' + profile.host + ':' + profile.port.toString());
    } catch (error) {
      if (generation !== this.generation) {
        return new SessionConnectionResult(false, HostKeyDecision.Trusted, 'FTP connection cancelled');
      }
      const authFailed = this.state === TransportState.AuthFailed;
      this.rejectPending(new Error('FTP connection failed'));
      this.closeSockets();
      this.state = authFailed ? TransportState.AuthFailed : TransportState.Disconnected;
      const message = socketError(error) || 'FTP connection failed';
      // 服务端可能在回复中回显 PASS 参数；在交给弹框及日志前遮蔽本次密码。
      const raw = failureDetail || message;
      const detail = secret ? raw.split(secret).join('[REDACTED]') : raw;
      const safeMessage = secret ? message.split(secret).join('[REDACTED]') : message;
      return new SessionConnectionResult(false, HostKeyDecision.Trusted, safeMessage, detail);
    }
  }

  startSftpSession(_profile: TransportProfile, _secret: string): Promise<boolean> {
    return Promise.resolve(this.state === TransportState.Connected);
  }

  disconnect(): void {
    this.generation++;
    this.rejectPending(new Error('FTP disconnected'));
    this.closeSockets();
    this.state = TransportState.Disconnected;
  }

  sftpPath(): string { return this.currentPath; }
  primeHomeDirectory(): Promise<string> { return Promise.resolve(this.homePath); }
  goSftpHome(): void { this.currentPath = this.homePath; }

  listDirectory(path: string): Promise<RemoteEntry[]> {
    return this.serialize(async (): Promise<RemoteEntry[]> => {
      try {
        return await this.listDirectoryInternal(SftpListingParser.resolve(this.currentPath, path, this.homePath));
      } catch (error) {
        throw error instanceof Error ? error : new Error('FTP directory listing failed');
      }
    });
  }

  changeSftpDirectory(target: string): Promise<boolean> {
    return this.serialize(async (): Promise<boolean> => {
      const path = SftpListingParser.resolve(this.currentPath, target, this.homePath);
      const reply = await this.command('CWD ' + FtpProtocol.safePath(path));
      if (reply.code >= 200 && reply.code < 300) { this.currentPath = path; return true; }
      return false;
    });
  }

  removeEntry(remotePath: string, isDirectory: boolean): Promise<boolean> {
    return this.serialize(async (): Promise<boolean> =>
      this.removeTreeEntry(remotePath, isDirectory, 0, new FtpTraversalBudget()));
  }

  createDirectory(remotePath: string): Promise<boolean> {
    return this.serialize(async (): Promise<boolean> => {
      const reply = await this.command('MKD ' + FtpProtocol.safePath(remotePath));
      return reply.code === 257 || reply.code === 250;
    });
  }

  downloadToFile(remotePath: string, localUri: string, onProgress: (bytesDone: number) => void,
    isCancelled: () => boolean): Promise<number> {
    return this.serialize(async (): Promise<number> => {
      const file = fileIo.openSync(localUri, fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.CREATE |
        fileIo.OpenMode.TRUNC);
      let written = 0;
      let data: FtpDataConnection | undefined = undefined;
      try {
        data = await this.openDataCommand('RETR ' + FtpProtocol.safePath(remotePath),
          (bytes: Uint8Array): void => {
          if (isCancelled()) { return; }
          let offset = 0;
          while (offset < bytes.byteLength) {
            const remaining = bytes.subarray(offset);
            const buffer = remaining.buffer.slice(remaining.byteOffset, remaining.byteOffset + remaining.byteLength);
            const count = fileIo.writeSync(file.fd, buffer);
            if (count <= 0) { throw new Error('local file write failed'); }
            offset += count;
            written += count;
          }
          onProgress(written);
        });
        if (data === undefined) { throw new Error('FTP data connection unavailable'); }
        await this.finishDataTransfer(data);
        if (isCancelled()) { throw new Error('transfer cancelled'); }
        return written;
      } catch (error) {
        if (data !== undefined) { await data.close().catch((): void => {}); }
        throw error instanceof Error ? error : new Error('FTP download failed');
      } finally {
        fileIo.closeSync(file);
        if (isCancelled() && data !== undefined) { await data.close(); }
        if (data !== undefined) { this.releaseData(data); }
      }
    });
  }

  uploadFromFile(localUri: string, remotePath: string, onProgress: (bytesDone: number) => void,
    isCancelled: () => boolean): Promise<number> {
    return this.serialize(async (): Promise<number> => {
      const generation = this.generation;
      const path = FtpProtocol.safePath(remotePath);
      const staging = this.secure ? path.substring(0, path.lastIndexOf('/') + 1) +
        '.homoxterm-upload-' + util.generateRandomUUID(true) : path;
      const file = fileIo.openSync(localUri, fileIo.OpenMode.READ_ONLY);
      let data: FtpDataConnection | undefined = undefined;
      let sent = 0;
      try {
        data = await this.openDataCommand('STOR ' + staging,
          (_bytes: Uint8Array): void => {});
        if (data === undefined) { throw new Error('FTP data connection unavailable'); }
        const buffer = new ArrayBuffer(FTP_CHUNK_SIZE);
        while (!isCancelled()) {
          const count = fileIo.readSync(file.fd, buffer, { offset: sent, length: buffer.byteLength });
          if (count <= 0) { break; }
          await data.send(new Uint8Array(buffer, 0, count));
          sent += count;
          onProgress(sent);
        }
        await Promise.all([this.waitReply().then((reply: FtpReply) => this.requireReply(reply, [226, 250])), data.close()]);
        if (isCancelled() || generation !== this.generation) { throw new Error('transfer cancelled'); }
        if (staging !== path) {
          this.requireReply(await this.command('RNFR ' + staging), [350]);
          this.requireReply(await this.command('RNTO ' + path), [250]);
        }
        return sent;
      } catch (error) {
        if (data !== undefined) { await data.close().catch((): void => {}); }
        if (data && staging !== path && generation === this.generation && this.state === TransportState.Connected) {
          await this.command('DELE ' + staging).catch((): void => {});
        }
        throw error instanceof Error ? error : new Error('FTP upload failed');
      } finally {
        fileIo.closeSync(file);
        if (isCancelled() && data !== undefined) { await data.close(); }
        if (data !== undefined) { this.releaseData(data); }
      }
    });
  }

  resize(_columns: number, _rows: number): Promise<boolean> { return Promise.resolve(false); }
  writeRaw(_text: string): Promise<number> { return Promise.reject(new Error('terminal unavailable for FTP')); }
  writeBytes(_bytes: Uint8Array): Promise<number> { return Promise.reject(new Error('terminal unavailable for FTP')); }
  runCryptoDiagnostics(): Promise<boolean> { return Promise.resolve(false); }
  presentedFingerprint(_profile: TransportProfile): string { return ''; }
  presentedHostKeyAlgorithm(): string { return ''; }
  respondKeyboardInteractive(_response: string): boolean { return false; }

  private async serialize<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.operationChain;
    let release: (value: boolean) => void = (_value: boolean): void => {};
    this.operationChain = new Promise<boolean>((resolve: (value: boolean) => void): void => { release = resolve; });
    await previous;
    try { return await operation(); }
    finally { release(true); }
  }

  private attachTcpControl(tcp: FtpSocket, generation: number): void {
    tcp.listen((bytes: ArrayBuffer): void => this.receiveControl(generation, bytes),
      (): void => this.controlClosed(generation),
      (error: Error): void => this.controlClosed(generation, socketError(error)));
  }

  private receiveControl(generation: number, bytes: ArrayBuffer): void {
    if (generation !== this.generation) { return; }
    const text = this.decoder.decodeToString(new Uint8Array(bytes), { stream: true });
    this.parser.push(text).forEach((reply: FtpReply): void => {
      const pending = this.pending;
      if (pending === undefined) { this.queuedReplies.push(reply); }
      else {
        this.pending = undefined;
        clearTimeout(pending.timeoutId);
        pending.resolve(reply);
      }
    });
  }

  private controlClosed(generation: number, detail: string = ''): void {
    if (generation === this.generation) {
      this.rejectPending(new Error(detail || 'FTP control connection closed'));
      this.activeData?.abort(new Error(detail || 'FTP control connection closed'));
      this.activeData = undefined;
      this.state = TransportState.Disconnected;
    }
  }

  private waitReply(phase: string = 'data'): Promise<FtpReply> {
    const queued = this.queuedReplies.shift();
    if (queued !== undefined) { return Promise.resolve(queued); }
    return new Promise<FtpReply>((resolve: (reply: FtpReply) => void, reject: (error: Error) => void): void => {
      const timeoutId = setTimeout((): void => {
        this.pending = undefined;
        reject(new Error('FTP response timed out (' + phase + ')'));
      }, FTP_TIMEOUT_MS);
      this.pending = new PendingFtpReply(resolve, reject, timeoutId);
    });
  }

  private async command(command: string): Promise<FtpReply> {
    FtpProtocol.safeCommand(command);
    if (this.controlTcp === undefined) {
      throw new Error('FTP is not connected');
    }
    const waiting = this.waitReply(command.split(' ')[0]);
    const bytes = this.encoder.encodeInto(command + '\r\n');
    const data = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    try {
      if (this.controlTcp !== undefined) { await this.controlTcp.send(data); }
      else { throw new Error('FTP control connection unavailable'); }
    } catch (error) {
      this.rejectPending(new Error(socketError(error) || 'FTP control send failed'));
    }
    return waiting;
  }

  private async listDirectoryInternal(target: string): Promise<RemoteEntry[]> {
    let listing: string | undefined = await this.receiveDataCommand('MLSD ' + FtpProtocol.safePath(target), true);
    if (listing !== undefined) { return FtpProtocol.parseMlsd(listing, target); }
    listing = await this.receiveDataCommand('LIST ' + FtpProtocol.safePath(target), false);
    if (listing === undefined) { throw new Error('FTP directory listing failed'); }
    return FtpProtocol.parseList(listing, target);
  }

  private async removeTreeEntry(path: string, isDirectory: boolean, depth: number,
    budget: FtpTraversalBudget): Promise<boolean> {
    if (depth > 64 || budget.remaining-- <= 0) {
      throw new Error('FTP recursive delete exceeds safe limits');
    }
    FtpProtocol.safePath(path);
    if (isDirectory) {
      const children = await this.listDirectoryInternal(path);
      for (const child of children) {
        if (child.name === '..' || child.isSymbolicLink ||
          !await this.removeTreeEntry((path === '/' ? '' : path) + '/' + child.name, child.isDirectory,
            depth + 1, budget)) {
          return false;
        }
      }
    }
    const reply = await this.command((isDirectory ? 'RMD ' : 'DELE ') + path);
    return reply.code >= 200 && reply.code < 300;
  }

  private requireReply(reply: FtpReply, allowed: number[], connecting: boolean = false): void {
    if (allowed.indexOf(reply.code) < 0) {
      throw new Error(connecting ? reply.text : 'FTP status ' + reply.code.toString());
    }
  }

  private async passiveEndpoint(): Promise<FtpPassiveEndpoint> {
    let reply = await this.command('EPSV');
    let endpoint = FtpProtocol.passiveEndpoint(reply, this.host);
    if (endpoint === undefined) {
      reply = await this.command('PASV');
      endpoint = FtpProtocol.passiveEndpoint(reply, this.host);
    }
    if (endpoint === undefined) { throw new Error('FTP passive mode unavailable'); }
    return endpoint;
  }

  private async openPassiveTcp(): Promise<FtpSocket> {
    const endpoint = await this.passiveEndpoint();
    const tcp = new FtpSocket(this.native, endpoint.host, endpoint.port, this.trustedCa);
    try {
      await tcp.connectTcp();
      return tcp;
    } catch (error) {
      await tcp.close().catch((): void => {});
      throw error instanceof Error ? error : new Error('FTP data connection failed');
    }
  }

  private async activateDataConnection(tcp: FtpSocket,
    onBytes: (bytes: Uint8Array) => void): Promise<FtpDataConnection> {
    if (this.secure) { tcp.prepareTls(this.controlTcp); }
    const connection = new FtpDataConnection(tcp);
    this.activeData = connection;
    connection.connected(onBytes);
    connection.completed.catch((): void => {});
    if (this.secure) { await tcp.connectTls(); }
    return connection;
  }

  private async openDataCommand(command: string, onBytes: (bytes: Uint8Array) => void,
    allowFailure: boolean = false): Promise<FtpDataConnection | undefined> {
    const tcp = await this.openPassiveTcp();
    const activation = this.activateDataConnection(tcp, onBytes);
    activation.catch((): void => {});
    try {
      const preliminary = await this.command(command);
      if (preliminary.code !== 125 && preliminary.code !== 150) {
        await tcp.close().catch((): void => {});
        await activation.catch((): FtpDataConnection | undefined => undefined);
        if (allowFailure) { return undefined; }
        throw new Error('FTP status ' + preliminary.code.toString());
      }
      return await activation;
    } catch (error) {
      await tcp.close().catch((): void => {});
      await activation.catch((): FtpDataConnection | undefined => undefined);
      throw error instanceof Error ? error : new Error('FTP data command failed');
    }
  }

  private async receiveDataCommand(command: string, allowFailure: boolean): Promise<string | undefined> {
    const chunks: Uint8Array[] = [];
    const data = await this.openDataCommand(command,
      (bytes: Uint8Array): void => { chunks.push(bytes); }, allowFailure);
    if (data === undefined) { return undefined; }
    try {
      await this.finishDataTransfer(data);
    } finally {
      await data.close().catch((): void => {});
      this.releaseData(data);
    }
    let text = '';
    const dataDecoder = util.TextDecoder.create('utf-8', { fatal: false, ignoreBOM: true });
    chunks.forEach((chunk: Uint8Array): void => {
      text += dataDecoder.decodeToString(chunk, { stream: true });
    });
    text += dataDecoder.decodeToString(new Uint8Array(0), { stream: false });
    return text;
  }

  private async finishDataTransfer(data: FtpDataConnection): Promise<void> {
    const completion = this.waitReply();
    const dataSettled = data.completed;
    await Promise.all([dataSettled, completion.then((reply: FtpReply): void => this.requireReply(reply, [226, 250]))]);
  }

  private rejectPending(error: Error): void {
    const pending = this.pending;
    this.pending = undefined;
    if (pending !== undefined) {
      clearTimeout(pending.timeoutId);
      pending.reject(error);
    }
    this.queuedReplies.length = 0;
  }

  private closeSockets(): void {
    const tcp = this.controlTcp;
    const data = this.activeData;
    this.controlTcp = undefined;
    this.activeData = undefined;
    tcp?.close().catch((): void => {});
    data?.abort(new Error('FTP disconnected'));
  }

  private releaseData(connection: FtpDataConnection): void {
    if (this.activeData === connection) { this.activeData = undefined; }
  }

}
