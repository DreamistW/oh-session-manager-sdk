export enum HostKeyDecision {
  Unknown = 'unknown',
  Trusted = 'trusted',
  Mismatch = 'mismatch'
}

export class HostKeyRecord {
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;

  constructor(host: string, port: number, algorithm: string, fingerprint: string) {
    this.host = host;
    this.port = port;
    this.algorithm = algorithm;
    this.fingerprint = fingerprint;
  }

  key(): string {
    return this.host + ':' + this.port.toString();
  }
}

/** 宿主为已核实的服务器身份提供信任决策与保存。 */
export interface HostKeyVerifier {
  verify(presented: HostKeyRecord): HostKeyDecision;
  trust(presented: HostKeyRecord): void;
}
