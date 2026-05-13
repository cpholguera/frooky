import { DecodeAt } from "./decoders/decodable";
import { DecoderSettings, FrookySettings, HookSettings } from "./frookySettings";

export const DEFAULT_DECODE_AT: DecodeAt = "enter";

export const DEFAULT_DECODER_SETTINGS: DecoderSettings = {
  fastDecode: false,
  magicDecode: false,
  maxRecursion: 10,
  decodeLimit: 1000,
  customDecoder: "",
  decoderArgs: [],
};

export const DEFAULT_HOOK_SETTINGS: HookSettings = {
  stackTraceLimit: 0,
  eventFilter: [],
};

export const DEFAULT_FROOKY_SETTINGS: FrookySettings = {
  verbose: false,
  logLevel: "debug",
  logTo: "frooky",
  resolverTimeout: 5,
  hookSettings: DEFAULT_HOOK_SETTINGS,
  decoderSettings: DEFAULT_DECODER_SETTINGS,
};

// specifies the interval between cached events are send back to the host
export const SEND_INTERVAL_MS = 100;

// specifies the interval during frida module and classes lookup
export const HOOK_LOOKUP_INTERVAL_MS = 500;
