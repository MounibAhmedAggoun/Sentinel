import type { CookieInfo } from './types.js';

/** Parses Set-Cookie header values into the flags we care about. Values are never stored. */
export function parseCookies(setCookie: string[]): CookieInfo[] {
  return setCookie.flatMap((line) => {
    const [pair = '', ...attributes] = line.split(';').map((part) => part.trim());
    const name = pair.split('=')[0]?.trim() ?? '';
    if (name === '') return [];

    let secure = false;
    let httpOnly = false;
    let sameSite: CookieInfo['sameSite'] = null;

    for (const attribute of attributes) {
      const [key = '', value = ''] = attribute.split('=').map((s) => s.trim());
      switch (key.toLowerCase()) {
        case 'secure':
          secure = true;
          break;
        case 'httponly':
          httpOnly = true;
          break;
        case 'samesite': {
          const v = value.toLowerCase();
          if (v === 'strict' || v === 'lax' || v === 'none') sameSite = v;
          break;
        }
      }
    }

    return [{ name, secure, httpOnly, sameSite }];
  });
}
