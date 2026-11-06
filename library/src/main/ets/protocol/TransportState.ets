export enum TransportState {
  Disconnected = 'disconnected',
  SftpOpenFailed = 'sftp-open-failed',
  TerminalOpenFailed = 'terminal-open-failed',
  Connected = 'connected',
  PasswordRequired = 'password-required',
  AuthFailed = 'auth-failed',
  HostKeyBlocked = 'host-key-blocked'
}
