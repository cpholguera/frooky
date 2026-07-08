import { InputFrookyConfig } from "../../shared/frookyConfig";
import { FrookySettings } from "../../shared/frookySettings";
import { HookValidator } from "../../shared/hook/hookValidator";
import { InputObjcHookGroup, InputObjcHookNormalized, isObjcHookScope } from "../../shared/inputParsing/inputIosHookGroup";

/**
 * IMPORTANT: This is just a place holder file!
 * At the moment, only native hooks can be used on iOS
 */
export class IosHookValidator implements HookValidator<InputObjcHookNormalized, InputObjcHookGroup> {
  validateAndNormalizeHooks(inputFrookyConfig: InputFrookyConfig, settings: FrookySettings): InputObjcHookNormalized[] {
    const normalizedJavaHooks: InputObjcHookNormalized[] = [];
    return normalizedJavaHooks;
  }

  getPlatformHookGroups(inputFrookyConfig: InputFrookyConfig): InputObjcHookGroup[] {
    const platformHookGroup: InputObjcHookGroup[] = [];
    for (const hookScope of inputFrookyConfig.hookGroup) {
      if (isObjcHookScope(hookScope)) {
        platformHookGroup.push(hookScope);
      }
    }
    return platformHookGroup;
  }
}
