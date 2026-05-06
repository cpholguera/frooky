import z from "zod";
import { validateAndRepairDecoderSettings, validateAndRepairHookSettings } from "../../shared/configValidator";
import { DecoderSettings } from "../../shared/decoders/decoderSettings";
import { FrookyConfig } from "../../shared/frookyConfig";
import { HookSettings } from "../../shared/hook/hookSettings";
import { HookValidator } from "../../shared/hook/hookValidator";
import { InputJavaHook, InputJavaHookGroup, InputJavaHookNormalized, isJavaHookScope } from "../../shared/inputParsing/inputJavaHookGroup";
import { inputJavaHookNormalizedSchema } from "../../shared/inputParsing/zodSchemas/inputJavaHookGroup.zod";

export class JavaHookValidator implements HookValidator<InputJavaHookNormalized, InputJavaHookGroup> {
  validateAndNormalizeHooks(
    inputFrookyConfig: FrookyConfig,
    globalHookSettings: HookSettings,
    globalDecoderSettings: DecoderSettings,
  ): InputJavaHookNormalized[] {
    const inputJavaHookCanonical: InputJavaHookNormalized[] = [];
    const inputJavaHookGroups = this.getPlatformHookGroups(inputFrookyConfig);
    for (const inputJavaHookGroup of inputJavaHookGroups) {
      for (const inputJavaHook of inputJavaHookGroup.hooks) {
        const hookScopeHookSettings = validateAndRepairHookSettings({ ...globalHookSettings, ...inputJavaHookGroup.hookSettings });
        const hookScopeDecoderSettings = validateAndRepairDecoderSettings({ ...globalDecoderSettings, ...inputJavaHookGroup.decoderSettings });
        const normalizedJavaHook = this.normalizeHook(inputJavaHook, hookScopeHookSettings, hookScopeDecoderSettings, inputJavaHookGroup.javaClass);
        if (normalizedJavaHook !== undefined) {
          inputJavaHookCanonical.push(normalizedJavaHook);
        }
      }
    }
    return inputJavaHookCanonical;
  }
  normalizeHook(
    inputHook: InputJavaHook,
    hookScopeHookSettings: HookSettings,
    hookScopeDecoderSettings: DecoderSettings,
    className: string,
  ): InputJavaHookNormalized | undefined {
    const methodName = typeof inputHook === "string" ? inputHook : inputHook.method;

    let hookSettings: HookSettings;
    let decoderSettings: DecoderSettings;
    if (typeof inputHook === "string") {
      hookSettings = hookScopeHookSettings;
      decoderSettings = hookScopeDecoderSettings;
    } else {
      hookSettings = { ...hookScopeHookSettings, ...inputHook.hookSettings };
      decoderSettings = { ...hookScopeDecoderSettings, ...inputHook.decoderSettings };
    }

    const testCandidate: InputJavaHook = {
      ...(typeof inputHook === "string" ? { method: inputHook } : inputHook),
      javaClass: className,
      hookSettings,
      decoderSettings,
    };

    try {
      return inputJavaHookNormalizedSchema.parse(testCandidate);
    } catch (e) {
      frooky.log.warn([
        `Skipping hook for method '${methodName}' from class '${className}' due to an invalid declaration.`,
        `Validation error:\n${z.prettifyError(e as z.ZodError)}`,
      ]);
    }
  }
  getPlatformHookGroups(inputFrookyConfig: FrookyConfig): InputJavaHookGroup[] {
    const platformHookGroup: InputJavaHookGroup[] = [];
    for (const hookScope of inputFrookyConfig.hookGroup) {
      if (isJavaHookScope(hookScope)) {
        platformHookGroup.push(hookScope);
      }
    }
    return platformHookGroup;
  }
}
