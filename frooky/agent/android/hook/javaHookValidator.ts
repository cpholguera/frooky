import z from "zod";
import { InputFrookyConfig } from "../../shared/frookyConfig";
import { FrookySettings } from "../../shared/frookySettings";
import { HookValidator } from "../../shared/hook/hookValidator";
import { InputJavaHookGroup, InputJavaHookNormalized, isJavaHookScope, normalizeJavaHookGroup } from "../../shared/inputParsing/inputJavaHookGroup";
import { inputJavaHookNormalizedSchema } from "../../shared/inputParsing/zodSchemas/inputJavaHookGroup.zod";

export class JavaHookValidator implements HookValidator<InputJavaHookNormalized, InputJavaHookGroup> {
  validateAndNormalizeHooks(inputFrookyConfig: InputFrookyConfig, settings: FrookySettings): InputJavaHookNormalized[] {
    const javaHookGroups = this.getPlatformHookGroups(inputFrookyConfig);
    const normalizedJavaHooks: InputJavaHookNormalized[] = [];

    for (const javaHookGroup of javaHookGroups) {
      const normalizedJavaHookGroup = normalizeJavaHookGroup(javaHookGroup, settings);
      for (const inputJavaHook of normalizedJavaHookGroup.hooks) {
        try {
          normalizedJavaHooks.push(inputJavaHookNormalizedSchema.parse(inputJavaHook));
        } catch (e) {
          const method = typeof inputJavaHook === "string" ? inputJavaHook : inputJavaHook.method;
          frooky.log.warn([
            `Skipping hook for java method '${method}' from class '${normalizedJavaHookGroup.javaClass}' due to an invalid declaration.`,
            `Validation error:\n${z.prettifyError(e as z.ZodError)}`,
          ]);
        }
      }
    }
    return normalizedJavaHooks;
  }

  getPlatformHookGroups(inputFrookyConfig: InputFrookyConfig): InputJavaHookGroup[] {
    const platformHookGroup: InputJavaHookGroup[] = [];
    for (const hookScope of inputFrookyConfig.hookGroup) {
      if (isJavaHookScope(hookScope)) {
        platformHookGroup.push(hookScope);
      }
    }
    return platformHookGroup;
  }
}
