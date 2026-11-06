import { socket } from '@kit.NetworkKit';
import { cert } from '@kit.DeviceCertificateKit';
import { deviceInfo } from '@kit.BasicServicesKit';
import { util } from '@kit.ArkTS';
import { SessionManagerNativeApi, FtpsTlsResult } from '../native/SessionManagerNativeApi';

const TIMEOUT_MS = 15000;
const EMPTY = new ArrayBuffer(0);

// 每条 TCP 通道独占 TLS 状态，只向已验证的对端交付应用数据。
export class FtpSocket {
  private readonly tcp: socket.TCPSocket = socket.constructTCPSocketInstance();
  private readonly host: string;
  private readonly port: number;
  private readonly ca: string | undefined;
  private tls: object | undefined = undefined;
  private verified: boolean = false;
  private eof: boolean = false;
  private closed: boolean = false;
  private incoming: Promise<void> = Promise.resolve();
  private outgoing: Promise<void> = Promise.resolve();
  private onMessage: (bytes: ArrayBuffer) => void = (_bytes: ArrayBuffer): void => {};
  private onClose: () => void = (): void => {};
  private onError: (error: Error) => void = (_error: Error): void => {};
  private tlsReady: () => void = (): void => {};
  private tlsFailed: (error: Error) => void = (_error: Error): void => {};

  private readonly native: SessionManagerNativeApi;

  constructor(native: SessionManagerNativeApi, host: string, port: number, ca?: string) {
    this.native = native;
    this.host = host;
    this.port = port;
    this.ca = ca;
    this.tcp.on('message', (info: socket.SocketMessageInfo): void => {
      this.incoming = this.incoming.then(() => this.receive(info.message)).catch((error: Error) => this.fail(error));
    });
    this.tcp.on('error', (error: Error): void => this.fail(error));
    this.tcp.on('close', (): void => {
      this.incoming.then((): void => {
        if (this.closed) { return; }
        if (this.tls && !this.eof) { this.fail(new Error('FTPS data truncated before close_notify')); }
        else if (!this.eof) { this.onClose(); }
      });
    });
  }

  async connectTcp(): Promise<void> {
    await this.tcp.connect({ address: { address: this.host, port: this.port }, timeout: TIMEOUT_MS });
  }

  prepareTls(control?: FtpSocket): void {
    const parent = control?.tls;
    this.tls = parent ? this.native.ftpsTlsCreate(this.host, parent) : this.native.ftpsTlsCreate(this.host);
  }

  async connectTls(): Promise<void> {
    const handshake = new Promise<void>((resolve, reject) => {
      this.tlsReady = resolve;
      this.tlsFailed = reject;
    });
    const timer = setTimeout(() => this.fail(new Error('FTPS handshake timed out')), TIMEOUT_MS);
    try { await Promise.all([handshake, this.receive(EMPTY)]); }
    finally { clearTimeout(timer); }
  }

  listen(message: (bytes: ArrayBuffer) => void, close: () => void, error: (err: Error) => void): void {
    this.onMessage = message;
    this.onClose = close;
    this.onError = error;
  }

  private async verifyPeer(handle: object): Promise<void> {
    const certificates: cert.X509Cert[] = [];
    const chain: ArrayBuffer[] = this.native.ftpsTlsPeer(handle);
    for (const der of chain) {
      certificates.push(await cert.createX509Cert({ data: new Uint8Array(der), encodingFormat: cert.EncodingFormat.FORMAT_DER }));
    }
    if (certificates.length === 0) { throw new Error('FTPS server certificate is missing'); }
    const anchors: cert.X509TrustAnchor[] = [];
    if (this.ca) {
      const pem = util.TextEncoder.create().encodeInto(this.ca);
      const ca = await cert.createX509Cert({ data: pem, encodingFormat: cert.EncodingFormat.FORMAT_PEM });
      anchors.push({ CACert: ca });
    }
    // IP 字面值由原生握手按 iPAddress SAN 精确比对，DNS（含通配符）由系统证书验证器处理。
    const dns = !/^[0-9.]+$/.test(this.host) && !this.host.includes(':');
    if (deviceInfo.apiAvailable('26.0.0')) {
      const params: cert.CertValidationParams = { trustSystemCa: !this.ca, untrustedCerts: certificates.slice(1) };
      const anchor = anchors[0]?.CACert;
      if (anchor) { params.trustedCerts = [anchor]; }
      if (dns) { params.hostnames = [this.host]; }
      await cert.createCertChainValidator('PKIX').validateCert(certificates[0], params);
    } else {
      const params: cert.CertChainValidationParameters = { trustAnchors: anchors, trustSystemCa: !this.ca };
      if (dns) {
        params.policy = cert.ValidationPolicyType.VALIDATION_POLICY_TYPE_SSL;
        params.sslHostname = this.host;
      }
      await cert.createX509CertChain(certificates).validate(params);
    }
  }

  private async receive(bytes: ArrayBuffer): Promise<void> {
    if (this.closed) { return; }
    const handle = this.tls;
    if (!handle) { this.onMessage(bytes); return; }
    const result: FtpsTlsResult = this.native.ftpsTlsStep(handle, 0, bytes);
    await this.flush(result.wire);
    if (result.ready && !this.verified) {
      await this.verifyPeer(handle);
      if (this.closed) { return; }
      this.verified = true;
      this.tlsReady();
    }
    if (this.verified && result.plain.byteLength) { this.onMessage(result.plain); }
    if (result.eof && !this.eof) {
      this.eof = true;
      this.onClose();
      await this.close();
    }
  }

  private flush(data: ArrayBuffer): Promise<void> {
    if (data.byteLength > 0) {
      this.outgoing = this.outgoing.then(() => this.tcp.send({ data: data }));
    }
    return this.outgoing;
  }

  async send(data: ArrayBuffer): Promise<void> {
    if (this.closed) { throw new Error('FTP socket closed'); }
    if (this.tls && !this.verified) { throw new Error('FTPS server certificate not verified'); }
    await this.flush(this.tls ? this.native.ftpsTlsStep(this.tls, 1, data).wire : data);
  }

  private fail(error: Error): void {
    if (!this.closed) {
      this.tlsFailed(error);
      this.onError(error);
      this.close().catch((): void => {});
    }
  }

  async close(): Promise<void> {
    if (this.closed) { return; }
    this.closed = true;
    this.tlsFailed(new Error('FTP socket closed'));
    try {
      if (this.tls && this.verified) {
        await this.flush(this.native.ftpsTlsStep(this.tls, 2, EMPTY).wire);
      }
    } finally {
      this.tcp.off('message'); this.tcp.off('close'); this.tcp.off('error');
      await this.tcp.close();
      this.tls = undefined;
    }
  }
}
