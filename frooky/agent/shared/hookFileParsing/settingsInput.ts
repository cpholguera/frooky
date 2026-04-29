import { DecodeAt } from "../decoders/decodableTypes";
import type { DecoderSettings } from "../decoders/decoderSettings";
import type { HookSettings } from "../hook/hook";

export type HookSettingsInput = Partial<HookSettings>;
export type DecoderSettingsInput = Partial<DecoderSettings>;
export type ParamSettings = Partial<DecoderSettings> & {
  decodeAt?: DecodeAt
}