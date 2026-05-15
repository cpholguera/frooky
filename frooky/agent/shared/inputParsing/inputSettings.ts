import { direction } from "../decoders/decodable";
import { DecoderSettings, HookSettings } from "../frookySettings";

export type InputFrookySettings = {
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
};
export type InputHookSettings = Partial<HookSettings>;
export type InputDecoderSettings = Partial<DecoderSettings>;
export type InputParamSettings = Partial<DecoderSettings> & {
  direction?: direction;
};
