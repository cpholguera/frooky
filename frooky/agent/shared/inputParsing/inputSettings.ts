import type { DecodeAt } from "../decoders/decodableTypes";
import type { DecoderSettings } from "../decoders/decoderSettings";
import { HookSettings } from "../hook/hookSettings";

export type InputHookSettings = Partial<HookSettings>;
export type InputDecoderSettings = Partial<DecoderSettings>;
export type InputParamSettings = Partial<DecoderSettings> & {
  decodeAt?: DecodeAt;
};
