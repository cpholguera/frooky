import z from "zod";

import { FrookyConfig } from "../../shared/frookyConfig";
import { FrookySettings } from "../../shared/frookySettings";
import { HookValidator } from "../../shared/hook/hookValidator";
import {
  InputNativeHookGroup,
  InputNativeHookNormalized,
  isNativeHookGroup,
  normalizeNativeHookGroup,
} from "../../shared/inputParsing/inputNativeHookGroup";
import { inputNativeHookNormalizedSchema } from "../../shared/inputParsing/zodSchemas/inputNativeHookGroup.zod";

export class NativeHookValidator implements HookValidator<InputNativeHookNormalized, InputNativeHookGroup> {
  validateAndNormalizeHooks(inputFrookyConfig: FrookyConfig, settings: FrookySettings): InputNativeHookNormalized[] {
    const nativeHookGroups = this.getPlatformHookGroups(inputFrookyConfig);
    const normalizedNativeHooks: InputNativeHookNormalized[] = [];

    for (const nativeHookGroup of nativeHookGroups) {
      const normalizedNativeHookGroup = normalizeNativeHookGroup(nativeHookGroup, settings);
      for (const inputNativeHook of normalizedNativeHookGroup.hooks) {
        try {
          normalizedNativeHooks.push(inputNativeHookNormalizedSchema.parse(inputNativeHook));
        } catch (e) {
          const symbol = typeof inputNativeHook === "string" ? inputNativeHook : inputNativeHook.symbol;
          frooky.log.warn([
            `Skipping hook for function with the symbol name '${symbol}' from module '${normalizedNativeHookGroup.module}' due to an invalid declaration.`,
            `Validation error:\n${z.prettifyError(e as z.ZodError)}`,
          ]);
        }
      }
    }
    return normalizedNativeHooks;
  }

  getPlatformHookGroups(inputFrookyConfig: FrookyConfig): InputNativeHookGroup[] {
    const platformHookGroup: InputNativeHookGroup[] = [];
    for (const hookScope of inputFrookyConfig.hookGroup) {
      if (isNativeHookGroup(hookScope)) {
        platformHookGroup.push(hookScope);
      }
    }
    return platformHookGroup;
  }
}
