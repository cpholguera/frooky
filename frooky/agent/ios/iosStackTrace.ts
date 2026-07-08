import { PlatformStackTrace } from "../shared/platformStackTrace";

export const IosStackTrace: PlatformStackTrace = {
  build(limit: number, stackTraceFilter?: string[], ctx?: CpuContext): string[] {
    return [];
  },
};
