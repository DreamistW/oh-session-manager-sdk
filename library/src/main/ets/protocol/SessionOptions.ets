export enum CredentialKind {
  Password = 'password',
  PrivateKey = 'private-key',
  KeyboardInteractive = 'keyboard-interactive'
}

export enum SessionProtocol {
  SSH = 'SSH',
  SFTP = 'SFTP',
  FTP = 'FTP',
  FTPS = 'FTPS',
  FTPSImplicit = 'FTPS implicit',
  SCP = 'SCP',
  Telnet = 'Telnet'
}

export function isFtpProtocol(protocol: string | undefined): boolean {
  return protocol === SessionProtocol.FTP || protocol === SessionProtocol.FTPS || protocol === SessionProtocol.FTPSImplicit;
}

export function isSshFileProtocol(protocol: string | undefined): boolean {
  return protocol === SessionProtocol.SFTP || protocol === SessionProtocol.SCP;
}

/** 单个连接需要的参数；档案及凭据存储由宿主负责。 */
export interface TransportProfile {
  readonly id: string;
  readonly host: string;
  readonly port: number;
  readonly username: string;
  readonly protocol: string;
  readonly legacySsh: boolean;
  endpoint(): string;
}

/** 连接只读取认证方式，秘密由宿主按请求传入。 */
export interface TransportCredential {
  readonly kind: CredentialKind;
}
