import { Param, RetType } from "../decoders/decodableTypes";
import { DecoderSettings } from "../decoders/decoderSettings";
import { HookSettings } from "./hookSettings";

export interface Hook {
  hookSettings: HookSettings;
  decoderSettings: DecoderSettings;
  params?: Param[];
  retType?: RetType;
}
