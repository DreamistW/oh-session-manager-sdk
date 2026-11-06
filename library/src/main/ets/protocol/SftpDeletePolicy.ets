/*
 * Copyright (c) 2026 HomoXterm contributors.
 * Licensed under the Apache License, Version 2.0.
 */

export class SftpDeletePolicy {
  static isSafePath(path: string): boolean {
    if (path.length <= 1 || path.length > 4096 || !path.startsWith('/') || path.endsWith('/')) {
      return false;
    }
    return path.substring(1).split('/').every((part: string): boolean => SftpDeletePolicy.isSafeName(part));
  }

  static isSafeName(name: string): boolean {
    return name.length > 0 && name.length <= 255 && name !== '.' && name !== '..' &&
      !/[\/\\\u0000-\u001f\u007f]/.test(name);
  }

  static child(root: string, name: string): string {
    if (!SftpDeletePolicy.isSafePath(root) || !SftpDeletePolicy.isSafeName(name)) {
      return '';
    }
    const path = root + '/' + name;
    return SftpDeletePolicy.isSafePath(path) ? path : '';
  }
}
