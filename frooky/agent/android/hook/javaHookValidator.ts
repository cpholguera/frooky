import z from "zod";
import { validateAndRepairDecoderSettings, validateAndRepairHookSettings } from "../../shared/configValidator";
import { DecoderSettings } from "../../shared/decoders/decoderSettings";
import { FrookyConfig } from "../../shared/frookyConfig";
import { InputJavaHook, InputJavaHookCanonical, isJavaHookScope, JavaHookScope } from "../../shared/frookyConfigParsing/javaHookScope";
import { inputJavaHookCanonicalSchema } from "../../shared/frookyConfigParsing/zodSchemas/javaHookScope.zod";
import { HookSettings } from "../../shared/hook/hookSettings";
import { HookValidator } from "../../shared/hook/hookValidator";

export class JavaHookValidator implements HookValidator<InputJavaHook, InputJavaHookCanonical, JavaHookScope> {
  validateHooks(inputFrookyConfig: FrookyConfig, globalHookSettings: HookSettings, globalDecoderSettings: DecoderSettings): InputJavaHookCanonical[] {
    const inputJavaHookCanonical: InputJavaHookCanonical[] = [];
    const inputJavaHookScopes = this.getPlatformHookScopes(inputFrookyConfig);
    for (const inputJavaHookScope of inputJavaHookScopes) {
      for (const inputJavaHook of inputJavaHookScope.hooks) {
        const hookScopeHookSettings = validateAndRepairHookSettings({ ...globalHookSettings, ...inputJavaHookScope.hookSettings });
        const hookScopeDecoderSettings = validateAndRepairDecoderSettings({ ...globalDecoderSettings, ...inputJavaHookScope.decoderSettings });
        const canonical = this.validateAndNormalizeInputHook(
          inputJavaHook,
          hookScopeHookSettings,
          hookScopeDecoderSettings,
          inputJavaHookScope.javaClass,
        );
        if (canonical !== undefined) {
          inputJavaHookCanonical.push(canonical);
        }
      }
    }
    return inputJavaHookCanonical;
  }
  validateAndNormalizeInputHook(
    inputHook: InputJavaHook,
    hookScopeHookSettings: HookSettings,
    hookScopeDecoderSettings: DecoderSettings,
    className: string,
  ): InputJavaHookCanonical | undefined {
    const methodName = typeof inputHook === "string" ? inputHook : inputHook.methodName;

    let hookSettings: HookSettings;
    let decoderSettings: DecoderSettings;
    if (typeof inputHook === "string") {
      hookSettings = hookScopeHookSettings;
      decoderSettings = hookScopeDecoderSettings;
    } else {
      hookSettings = { ...hookScopeHookSettings, ...inputHook.hookSettings };
      decoderSettings = { ...hookScopeDecoderSettings, ...inputHook.decoderSettings };
    }

    const testCandidate: InputJavaHookCanonical = {
      ...(typeof inputHook === "string" ? { methodName: inputHook } : inputHook),
      className,
      hookSettings,
      decoderSettings,
    };

    try {
      return inputJavaHookCanonicalSchema.parse(testCandidate);
    } catch (e) {
      frooky.log.warn([
        `Skipping hook for method '${methodName}' from class '${className}' due to an invalid declaration.`,
        `Validation error:\n${z.prettifyError(e as z.ZodError)}`,
      ]);
    }
  }
  getPlatformHookScopes(inputFrookyConfig: FrookyConfig): JavaHookScope[] {
    const platformHookScopes: JavaHookScope[] = [];
    for (const hookScope of inputFrookyConfig.hookScopes) {
      if (isJavaHookScope(hookScope)) {
        platformHookScopes.push(hookScope);
      }
    }
    return platformHookScopes;
  }
}
