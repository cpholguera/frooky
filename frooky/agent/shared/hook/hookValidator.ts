import { InputFrookyConfig } from "../frookyConfig";
import { FrookySettings } from "../frookySettings";

export interface HookValidator<THookNormalized, THookGroup> {
  validateAndNormalizeHooks(inputFrookyConfig: InputFrookyConfig, settings: FrookySettings): THookNormalized[];
  getPlatformHookGroups(inputFrookyConfig: InputFrookyConfig): THookGroup[];
}
