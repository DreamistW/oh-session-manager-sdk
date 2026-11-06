export enum RemoteEntrySortField {
  Name = 'name',
  Size = 'size',
  Modified = 'modified'
}

export class RemoteEntry {
  name: string;
  size: string;
  modified: string;
  isDirectory: boolean;
  sizeBytes: number;
  modifiedEpochSeconds: number;
  isSymbolicLink: boolean;

  constructor(name: string, size: string, modified: string, isDirectory: boolean,
    sizeBytes: number = 0, modifiedEpochSeconds: number = 0, isSymbolicLink: boolean = false) {
    this.name = name;
    this.size = size;
    this.modified = modified;
    this.isDirectory = isDirectory;
    this.sizeBytes = sizeBytes;
    this.modifiedEpochSeconds = modifiedEpochSeconds;
    this.isSymbolicLink = isSymbolicLink;
  }
}

function compareRemoteEntryValues(left: RemoteEntry, right: RemoteEntry, field: RemoteEntrySortField): number {
  if (field === RemoteEntrySortField.Size) {
    const sizeDifference = remoteEntrySizeBytes(left) - remoteEntrySizeBytes(right);
    return sizeDifference === 0 ? left.name.localeCompare(right.name) : sizeDifference;
  }
  if (field === RemoteEntrySortField.Modified) {
    const leftModified = left.modifiedEpochSeconds;
    const rightModified = right.modifiedEpochSeconds;
    if (leftModified !== rightModified) {
      return leftModified - rightModified;
    }
    const modifiedDifference = left.modified.localeCompare(right.modified);
    return modifiedDifference === 0 ? left.name.localeCompare(right.name) : modifiedDifference;
  }
  return left.name.localeCompare(right.name);
}

export function remoteEntrySizeBytes(entry: RemoteEntry): number {
  if (entry.sizeBytes > 0 || entry.size === '0 B') {
    return entry.sizeBytes;
  }
  const numeric = Number(entry.size.replace(/[^0-9.]/g, ''));
  if (!Number.isFinite(numeric)) {
    return 0;
  }
  if (entry.size.indexOf('MB') >= 0) {
    return numeric * 1024 * 1024;
  }
  if (entry.size.indexOf('KB') >= 0) {
    return numeric * 1024;
  }
  return numeric;
}

function padDatePart(value: number): string {
  return value < 10 ? '0' + value.toString() : value.toString();
}

export function formatRemoteModifiedTime(epochSeconds: number): string {
  if (epochSeconds <= 0) {
    return '';
  }
  const date = new Date(epochSeconds * 1000);
  if (!Number.isFinite(date.getTime())) {
    return '';
  }
  return date.getFullYear().toString() + '/' + padDatePart(date.getMonth() + 1) + '/' +
    padDatePart(date.getDate()) + ' ' + padDatePart(date.getHours()) + ':' +
    padDatePart(date.getMinutes()) + ':' + padDatePart(date.getSeconds());
}

export function sortRemoteEntries(entries: RemoteEntry[], field: RemoteEntrySortField = RemoteEntrySortField.Name,
  ascending: boolean = true): RemoteEntry[] {
  return entries.slice().sort((left: RemoteEntry, right: RemoteEntry): number => {
    if (left.name === '..') {
      return right.name === '..' ? 0 : -1;
    }
    if (right.name === '..') {
      return 1;
    }
    if (left.isDirectory !== right.isDirectory) {
      return left.isDirectory ? -1 : 1;
    }
    const comparison = compareRemoteEntryValues(left, right, field);
    return ascending ? comparison : -comparison;
  });
}
