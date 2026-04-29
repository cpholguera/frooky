import { DecodeAt } from "./decoders/decodableTypes";
import type { DecoderSettings} from "./decoders/decoderSettings";
import type { HookSettings } from "./hook/hook";

export const DEFAULT_DECODE_AT: DecodeAt = "enter"

export const DEFAULT_DECODER_SETTINGS: DecoderSettings = {
  fastDecode: false,
  magicDecode: false,
  maxRecursion: 77,
  decodeLimit: 77
};

export const DEFAULT_HOOK_SETTINGS: HookSettings = {
  hookTimeout: 77,
  stackTraceLimit: 77,
  eventFilter: [],
};

// specifies the interval between cached events are send back to the host
export const SEND_INTERVAL = 100;
