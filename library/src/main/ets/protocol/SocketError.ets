/** 保留系统网络错误码与文本，供宿主按业务策略处理。 */
export function socketError(error: Object): string {
  if (!error) { return ''; }
  if (typeof error === 'string') { return error; }
  const record = error as Record<string, Object>;
  const message = typeof record['message'] === 'string' ? record['message'] as string : '';
  const code = record['code'];
  return typeof code === 'number' || typeof code === 'string' ? (code.toString() + ' ' + message).trim() : message;
}
