import { DecoderSettings } from "../decoders/decoderSettings";
import { HookSettings } from "./hookSettings";

export interface Hook {
  hookSettings: HookSettings;
  decoderSettings: DecoderSettings;
}
