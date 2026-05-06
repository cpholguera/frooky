import { DecoderSettings } from "../decoders/decoderSettings";
import { FrookyConfig } from "../frookyConfig";
import { HookSettings } from "./hookSettings";

export interface HookValidator<THookNormalized, THookGroup> {
  validateAndNormalizeHooks(inputFrookyConfig: FrookyConfig, hookSettings: HookSettings, decoderSetting: DecoderSettings): THookNormalized[];
  getPlatformHookGroups(inputFrookyConfig: FrookyConfig): THookGroup[];
}
