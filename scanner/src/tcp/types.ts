export type PortState = 'open' | 'closed' | 'timeout' | 'error';

export interface PortResult {
  port: number;
  state: PortState;
  /** Time until the connection succeeded or failed. */
  timingMs: number;
  /** Only set when state is "error". */
  error?: string;
}

export interface TcpResult {
  /** The validated IP that every port check connected to. */
  ip: string;
  ports: PortResult[];
}
