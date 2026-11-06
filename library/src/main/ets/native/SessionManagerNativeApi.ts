export interface FtpsTlsResult {
  ready: boolean;
  eof: boolean;
  wire: ArrayBuffer;
  plain: ArrayBuffer;
}
export interface SessionManagerNativeApi {
  ftpsTlsCreate(host: string, parent?: object): object;
  ftpsTlsStep(handle: object, operation: number, bytes: ArrayBuffer): FtpsTlsResult;
  ftpsTlsPeer(handle: object): ArrayBuffer[];
  runCryptoCompatibilityGate(): Promise<string>;
  runLibssh2HandshakeGate(host: string, port: number): Promise<string>;
  connect(host: string, port: number, legacy?: boolean): Promise<string>;
  acceptHostKey(sessionId: number, accepted: boolean): Promise<boolean>;
  authenticate(sessionId: number, username: string, kind: string, secret: string,
    passphrase: string): Promise<boolean>;
  keyboardInteractivePrompt(sessionId: number): string;
  respondKeyboardInteractive(sessionId: number, response: string): boolean;
  openPty(sessionId: number, terminalType: string, columns: number, rows: number): Promise<boolean>;
  write(sessionId: number, bytes: ArrayBuffer): Promise<number>;
  read(sessionId: number, maximumBytes: number): Promise<ArrayBuffer>;
  resizePty(sessionId: number, columns: number, rows: number): Promise<boolean>;
  collectRemoteMetrics(sessionId: number): Promise<string>;
  reserveMetrics(): number;
  cancelMetrics(sessionId: number): boolean;
  connectMetrics(host: string, port: number, fingerprint: string, username: string, kind: string,
    secret: string, passphrase: string, reservedId: number, legacy?: boolean): Promise<number>;
  disconnectMetrics(sessionId: number): Promise<boolean>;
  openSftp(sessionId: number): Promise<string>;
  listDirectory(sessionId: number, path: string): Promise<string>;
  beginScp(sessionId: number, path: string, upload: boolean, size: number): Promise<number>;
  stepScp(sessionId: number, handle: number, fd: number): Promise<number>;
  endScp(sessionId: number, handle: number, complete: boolean): Promise<boolean>;
  readFileChunk(sessionId: number, path: string, offset: number, maximumBytes: number): Promise<ArrayBuffer>;
  writeFileChunk(sessionId: number, path: string, offset: number, bytes: ArrayBuffer,
    truncate: boolean): Promise<number>;
  createDirectory(sessionId: number, path: string): Promise<boolean>;
  removeEntry(sessionId: number, path: string, isDirectory: boolean): Promise<boolean>;
  listDeleteDirectory(sessionId: number, path: string): Promise<string>;
  disconnect(sessionId: number): Promise<boolean>;
}
