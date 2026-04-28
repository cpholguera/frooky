import type { DecoderSettings } from "./decoders/decoderSettings";
import type { HookSettings } from "./hook/hook";

export const DEFAULT_DECODER_SETTINGS: DecoderSettings = {
  fastDecode: false,
  magicDecode: false,
  maxRecursion: 5,
  decodeLimit: 1000,
};

export const DEFAULT_HOOK_SETTINGS: HookSettings = {
  hookTimeout: 5,
  stackTraceLimit: 10,
  eventFilter: [],
};

// specifies the interval between cached events are send back to the host
export const SEND_INTERVAL = 100;
