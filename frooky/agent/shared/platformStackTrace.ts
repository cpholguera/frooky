export interface PlatformStackTrace {
  build(limit: number, stackTraceFilter?: string[], ctx?: CpuContext): string[];
}
