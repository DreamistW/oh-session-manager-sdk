import { RemoteEntry, sortRemoteEntries } from './RemoteFileTypes';

export class SftpListingParser {
  static parse(raw: string, currentPath: string): RemoteEntry[] {
    const entries: RemoteEntry[] = [];
    if (currentPath !== '/') {
      entries.push(new RemoteEntry('..', '', '', true));
    }
    const lines = SftpListingParser.stripControls(raw).replace(/\r/g, '').split('\n');
    lines.forEach((line: string) => {
      const entry = SftpListingParser.parseLine(line);
      if (entry !== undefined) {
        entries.push(entry);
      }
    });
    return sortRemoteEntries(entries);
  }

  static parseFind(raw: string, currentPath: string): RemoteEntry[] {
    const entries: RemoteEntry[] = [];
    if (currentPath !== '/') {
      entries.push(new RemoteEntry('..', '', '', true));
    }
    const lines = SftpListingParser.stripControls(raw).replace(/\r/g, '').split('\n');
    lines.forEach((line: string) => {
      const trimmed = line.trim();
      if (trimmed.length === 0 || trimmed.indexOf('HOMOX_') === 0) {
        return;
      }
      const sep = trimmed.indexOf('\t');
      if (sep <= 0) {
        return;
      }
      const kind = trimmed.substring(0, sep);
      const name = trimmed.substring(sep + 1);
      if (name.length === 0 || name === '.' || name === '..') {
        return;
      }
      entries.push(new RemoteEntry(name, '', '', kind === 'd'));
    });
    return sortRemoteEntries(entries);
  }

  static stripControls(raw: string): string {
    let cleaned = '';
    let skip = false;
    for (let index = 0; index < raw.length; index++) {
      const ch = raw.charAt(index);
      const code = raw.charCodeAt(index);
      if (ch === '\u001b') {
        skip = true;
        continue;
      }
      if (skip) {
        if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
          skip = false;
        }
        continue;
      }
      if (code < 32 && ch !== '\n' && ch !== '\t') {
        continue;
      }
      cleaned += ch;
    }
    return cleaned;
  }

  static resolve(currentPath: string, target: string, homePath: string): string {
    if (target.length === 0 || target === '.') {
      return currentPath;
    }
    if (target === '~') {
      return homePath;
    }
    if (target.charAt(0) === '/') {
      return SftpListingParser.normalize(target);
    }
    const parts = currentPath === '/' ? [] : currentPath.split('/').slice(1);
    const segments = target.split('/');
    segments.forEach((segment: string) => {
      if (segment.length === 0 || segment === '.') {
        return;
      }
      if (segment === '..') {
        if (parts.length > 0) {
          parts.pop();
        }
      } else {
        parts.push(segment);
      }
    });
    return parts.length === 0 ? '/' : '/' + parts.join('/');
  }

  static extractPath(raw: string): string {
    const lines = SftpListingParser.stripControls(raw).replace(/\r/g, '').split('\n');
    for (let index = lines.length - 1; index >= 0; index--) {
      const line = lines[index].trim();
      if (line.length > 0 && line.charAt(0) === '/' && line.indexOf(' ') < 0) {
        return SftpListingParser.normalize(line);
      }
    }
    return '/';
  }

  static quote(path: string): string {
    return "'" + path.split("'").join("'\\''") + "'";
  }

  static formatSize(bytes: number, isDirectory: boolean): string {
    if (isDirectory || bytes < 0) {
      return '';
    }
    if (bytes >= 1024 * 1024) {
      return (Math.floor(bytes * 10 / (1024 * 1024)) / 10).toString() + ' MB';
    }
    if (bytes >= 1024) {
      return (Math.floor(bytes * 10 / 1024) / 10).toString() + ' KB';
    }
    return bytes.toString();
  }

  private static parseLine(line: string): RemoteEntry | undefined {
    const trimmed = SftpListingParser.stripControls(line).trim();
    if (trimmed.length === 0 || trimmed.indexOf('total ') === 0 || trimmed.indexOf('ls:') === 0) {
      return undefined;
    }
    if (trimmed.charAt(0) !== 'd' && trimmed.charAt(0) !== '-' && trimmed.charAt(0) !== 'l') {
      return undefined;
    }
    const parts = SftpListingParser.splitColumns(trimmed);
    if (parts.length < 9) {
      return undefined;
    }
    let name = parts.slice(8).join(' ');
    const arrow = name.indexOf(' -> ');
    if (arrow >= 0) {
      name = name.substring(0, arrow);
    }
    if (name === '.' || name === '..' || name.length === 0) {
      return undefined;
    }
    const isDirectory = trimmed.charAt(0) === 'd';
    const isSymbolicLink = trimmed.charAt(0) === 'l';
    const bytes = Number(parts[4]);
    const size = SftpListingParser.formatSize(isNaN(bytes) ? 0 : bytes, isDirectory);
    const modified = parts[5] + ' ' + parts[6] + ' ' + parts[7];
    return new RemoteEntry(name, size, modified, isDirectory, Number.isFinite(bytes) ? bytes : 0, 0, isSymbolicLink);
  }

  private static splitColumns(line: string): string[] {
    const parts: string[] = [];
    let current = '';
    for (let index = 0; index < line.length; index++) {
      const ch = line.charAt(index);
      if (ch === ' ' || ch === '\t') {
        if (current.length > 0) {
          parts.push(current);
          current = '';
        }
      } else {
        current += ch;
      }
    }
    if (current.length > 0) {
      parts.push(current);
    }
    return parts;
  }

  private static normalize(path: string): string {
    if (path === '//' || path === '') {
      return '/';
    }
    const parts: string[] = [];
    path.split('/').forEach((segment: string) => {
      if (segment.length === 0 || segment === '.') {
        return;
      }
      if (segment === '..') {
        if (parts.length > 0) {
          parts.pop();
        }
      } else {
        parts.push(segment);
      }
    });
    return parts.length === 0 ? '/' : '/' + parts.join('/');
  }
}
