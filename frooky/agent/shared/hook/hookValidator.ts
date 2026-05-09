import { FrookyConfig } from "../frookyConfig";
import { FrookySettings } from "../frookySettings";

export interface HookValidator<THookNormalized, THookGroup> {
  validateAndNormalizeHooks(inputFrookyConfig: FrookyConfig, settings: FrookySettings): THookNormalized[];
  getPlatformHookGroups(inputFrookyConfig: FrookyConfig): THookGroup[];
}
