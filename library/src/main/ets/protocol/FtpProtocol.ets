import { RemoteEntry, sortRemoteEntries } from './RemoteFileTypes';
import { SftpListingParser } from './SftpListingParser';

export class FtpReply {
  readonly code: number;
  readonly text: string;

  constructor(code: number, text: string) {
    this.code = code;
    this.text = text;
  }

  positive(): boolean {
    return this.code >= 100 && this.code < 400;
  }
}

export class FtpReplyParser {
  private buffer: string = '';
  private multilineCode: string = '';
  private multilineLines: string[] = [];

  push(text: string): FtpReply[] {
    this.buffer += text;
    const replies: FtpReply[] = [];
    let separator = this.buffer.indexOf('\n');
    while (separator >= 0) {
      let line = this.buffer.substring(0, separator);
      this.buffer = this.buffer.substring(separator + 1);
      if (line.endsWith('\r')) { line = line.substring(0, line.length - 1); }
      const reply = this.consumeLine(line);
      if (reply !== undefined) { replies.push(reply); }
      separator = this.buffer.indexOf('\n');
    }
    return replies;
  }

  private consumeLine(line: string): FtpReply | undefined {
    if (this.multilineCode.length > 0) {
      this.multilineLines.push(line);
      if (line.startsWith(this.multilineCode + ' ')) {
        const reply = new FtpReply(Number(this.multilineCode), this.multilineLines.join('\n'));
        this.multilineCode = '';
        this.multilineLines = [];
        return reply;
      }
      return undefined;
    }
    if (!/^[0-9]{3}[ -]/.test(line)) {
      // 单独报告可识别的异协议标识，避免把 SSH/HTTP 服务误报为 FTP 超时。
      return /^(SSH-\d|HTTP\/\d)/.test(line) ? new FtpReply(0, line) : undefined;
    }
    if (line.charAt(3) === '-') {
      this.multilineCode = line.substring(0, 3);
      this.multilineLines = [line];
      return undefined;
    }
    return new FtpReply(Number(line.substring(0, 3)), line);
  }
}

export class FtpPassiveEndpoint {
  readonly host: string;
  readonly port: number;

  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
  }
}

export class FtpProtocol {
  // 仅在服务器明确要求加密时识别 FTPS，不能把所有 530 都当成密码错误。
  static requiresTls(detail: string): boolean {
    if (!/^(530|534|522|550)[ -]/.test(detail)) { return false; }
    return detail.split(/[.;\r\n]/).some((clause: string): boolean => {
      if (/\b(?:not|never)\s+requir(?:e|es|ed)\b/i.test(clause)) { return false; }
      return /\b(?:TLS|SSL|FTPS|encryption|encrypted)(?:\s+(?:connections?|sessions?|channels?))?(?:\s+(?:is|are))?\s+(?:required|mandatory|only)\b/i.test(clause) ||
        /\b(?:requires?|must\s+(?:use|enable)|only(?:\s+(?:accepts?|supports?|allows?))?)\s+(?:(?:an?|the|AUTH)\s+)?(?:TLS|SSL|FTPS|encryption|encrypted)\b/i.test(clause);
    });
  }

  static safeCommand(command: string): string {
    if (command.indexOf('\r') >= 0 || command.indexOf('\n') >= 0 || command.indexOf('\u0000') >= 0) {
      throw new Error('invalid FTP command');
    }
    return command;
  }

  static passiveEndpoint(reply: FtpReply, controlHost: string): FtpPassiveEndpoint | undefined {
    if (reply.code === 229) {
      const match = /\(\|\|\|([0-9]+)\|\)/.exec(reply.text);
      const port = match === null ? 0 : Number(match[1]);
      return port >= 1 && port <= 65535 ? new FtpPassiveEndpoint(controlHost, port) : undefined;
    }
    if (reply.code !== 227) { return undefined; }
    const match = /\(([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)\)/.exec(reply.text);
    if (match === null) { return undefined; }
    const port = Number(match[5]) * 256 + Number(match[6]);
    return port >= 1 && port <= 65535 ? new FtpPassiveEndpoint(controlHost, port) : undefined;
  }

  static safePath(path: string): string {
    if (path.indexOf('\r') >= 0 || path.indexOf('\n') >= 0 || path.indexOf('\u0000') >= 0) {
      throw new Error('invalid FTP path');
    }
    return path;
  }

  static pathFromPwd(reply: FtpReply): string {
    const first = reply.text.indexOf('"');
    if (first < 0) { return '/'; }
    let result = '';
    for (let index = first + 1; index < reply.text.length; index++) {
      const ch = reply.text.charAt(index);
      if (ch !== '"') { result += ch; }
      else if (reply.text.charAt(index + 1) === '"') { result += '"'; index++; }
      else { return result.length === 0 ? '/' : result; }
    }
    return '/';
  }

  static parseMlsd(raw: string, currentPath: string): RemoteEntry[] {
    const entries: RemoteEntry[] = currentPath === '/' ? [] : [new RemoteEntry('..', '', '', true)];
    raw.replace(/\r/g, '').split('\n').forEach((line: string): void => {
      const separator = line.indexOf(' ');
      if (separator <= 0) { return; }
      const name = line.substring(separator + 1);
      if (name.length === 0 || name === '.' || name === '..') { return; }
      let type = '';
      let size = 0;
      let modified = '';
      line.substring(0, separator).split(';').forEach((fact: string): void => {
        const equals = fact.indexOf('=');
        if (equals <= 0) { return; }
        const key = fact.substring(0, equals).toLowerCase();
        const value = fact.substring(equals + 1);
        if (key === 'type') { type = value.toLowerCase(); }
        if (key === 'size') { size = Math.max(0, Number(value) || 0); }
        if (key === 'modify') { modified = FtpProtocol.formatMlsdTime(value); }
      });
      if (type === 'cdir' || type === 'pdir') { return; }
      const isDirectory = type === 'dir';
      const unsupported = type.indexOf('slink') >= 0 || (type.length > 0 && type !== 'file' && !isDirectory);
      if (!unsupported) {
        entries.push(new RemoteEntry(name, SftpListingParser.formatSize(size, isDirectory), modified,
          isDirectory, size, 0));
      }
    });
    return sortRemoteEntries(entries);
  }

  static parseList(raw: string, currentPath: string): RemoteEntry[] {
    const unixEntries = SftpListingParser.parse(raw, currentPath)
      .filter((entry: RemoteEntry): boolean => !entry.isSymbolicLink);
    if (unixEntries.some((entry: RemoteEntry): boolean => entry.name !== '..')) {
      return unixEntries;
    }
    const entries: RemoteEntry[] = currentPath === '/' ? [] : [new RemoteEntry('..', '', '', true)];
    raw.replace(/\r/g, '').split('\n').forEach((line: string): void => {
      const match = /^([0-9]{2})-([0-9]{2})-([0-9]{2,4})\s+([0-9]{2}):([0-9]{2})(AM|PM)\s+(<DIR>|[0-9]+)\s+(.+)$/.exec(line.trim());
      if (match === null) { return; }
      const name = match[8];
      if (name.length === 0 || name === '.' || name === '..') { return; }
      const isDirectory = match[7] === '<DIR>';
      const size = isDirectory ? 0 : Math.max(0, Number(match[7]) || 0);
      const modified = match[1] + '/' + match[2] + '/' + match[3] + ' ' + match[4] + ':' + match[5] + match[6];
      entries.push(new RemoteEntry(name, SftpListingParser.formatSize(size, isDirectory), modified,
        isDirectory, size, 0));
    });
    return sortRemoteEntries(entries);
  }

  private static formatMlsdTime(value: string): string {
    if (!/^[0-9]{14}/.test(value)) { return ''; }
    return value.substring(0, 4) + '/' + value.substring(4, 6) + '/' + value.substring(6, 8) + ' ' +
      value.substring(8, 10) + ':' + value.substring(10, 12) + ':' + value.substring(12, 14) + ' UTC';
  }
}
