import { RetType } from "../decoders/decodable";
import { DecoderSettings, HookSettings } from "../frookySettings";

export interface Hook {
  hookSettings: HookSettings;
  decoderSettings: DecoderSettings;
  retType?: RetType;
}
