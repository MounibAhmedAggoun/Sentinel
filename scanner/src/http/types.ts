export type HttpErrorCode =
  | 'INVALID_URL'
  | 'BLOCKED_TARGET'
  | 'TIMEOUT'
  | 'TOO_MANY_REDIRECTS'
  | 'CONNECTION_FAILED'
  | 'TLS_ERROR'
  | 'UNKNOWN';

export interface HttpError {
  code: HttpErrorCode;
  message: string;
}

export interface CookieInfo {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none' | null;
}

/** One request/response in a redirect chain. */
export interface HttpHop {
  url: string;
  status: number;
  /** Header names are lowercased. */
  headers: Record<string, string | string[]>;
  cookies: CookieInfo[];
  /** The validated IP we actually connected to. */
  remoteIp: string;
  timingMs: number;
}

/** Hops are kept even when an error happens part-way through the chain. */
export interface HttpResult {
  startUrl: string;
  finalUrl: string | null;
  hops: HttpHop[];
  error: HttpError | null;
}
