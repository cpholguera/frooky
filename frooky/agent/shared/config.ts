import type { HookSettings } from "frooky";

export const DEFAULT_HOOK_SETTINGS: HookSettings = {
  stackTraceLimit: 10,
  disableStacktrace: false,
  eventFilter: [],
  decoderSettings: {
    fastDecode: false,
    magicDecode: false,
    maxRecursion: 5,
    decodeLimit: 1000,
  },
};

// specifies the interval between cached events are send back to the host
export const SEND_INTERVAL = 100;
