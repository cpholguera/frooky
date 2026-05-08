import type { DecodeAt } from "./decoders/decodableTypes";
import type { DecoderSettings } from "./decoders/decoderSettings";
import { HookSettings } from "./hook/hookSettings";

export const DEFAULT_DECODE_AT: DecodeAt = "enter";

export const DEFAULT_DECODER_SETTINGS: DecoderSettings = {
  fastDecode: false,
  magicDecode: false,
  maxRecursion: 10,
  decodeLimit: 1000,
};

export const DEFAULT_HOOK_SETTINGS: HookSettings = {
  hookTimeout: 5,
  stackTraceLimit: 10,
  eventFilter: [],
};

// specifies the interval between cached events are send back to the host
export const SEND_INTERVAL_MS = 100;

// specifies the interval during frida module and classes lookup
export const HOOK_LOOKUP_INTERVAL_MS = 500;
