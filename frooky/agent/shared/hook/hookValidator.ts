import { FrookyConfig, FrookySettings } from "frooky/shared";

export interface HookValidator<THookNormalized, THookGroup> {
  validateAndNormalizeHooks(inputFrookyConfig: FrookyConfig, settings: FrookySettings): THookNormalized[];
  getPlatformHookGroups(inputFrookyConfig: FrookyConfig): THookGroup[];
}
