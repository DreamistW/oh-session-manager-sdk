export class MetricsCredentials {
  kind: string;
  secret: string;
  passphrase: string;
  constructor(kind: string, secret: string, passphrase: string) {
    this.kind = kind;
    this.secret = secret;
    this.passphrase = passphrase;
  }
}
