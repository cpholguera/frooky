import type { DecodeAt } from "../decoders/decodableTypes";
import { DecoderSettings, FrookySettings, HookSettings } from "../frookySettings";

export type InputFrookySettings = Omit<Partial<FrookySettings>, "hookSettings" | "decoderSettings"> & {
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
};
export type InputHookSettings = Partial<HookSettings>;
export type InputDecoderSettings = Partial<DecoderSettings>;
export type InputParamSettings = Partial<DecoderSettings> & {
  decodeAt?: DecodeAt;
};
