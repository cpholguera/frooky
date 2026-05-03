import z from "zod";
import { validateAndRepairDecoderSettings, validateAndRepairHookSettings } from "../../shared/configValidator";
import { DecoderSettings } from "../../shared/decoders/decoderSettings";
import { FrookyConfig } from "../../shared/frookyConfig";
import { InputNativeHook, InputNativeHookCanonical, isNativeHookScope, NativeHookScope } from "../../shared/frookyConfigParsing/nativeHookScope";
import { inputNativeHookCanonicalSchema } from "../../shared/frookyConfigParsing/zodSchemas/nativeHookScope.zod";
import { HookSettings } from "../../shared/hook/hookSettings";
import { HookValidator } from "../../shared/hook/hookValidator";

export class NativeHookValidator implements HookValidator<InputNativeHook, InputNativeHookCanonical, NativeHookScope> {
  validateHooks(
    inputFrookyConfig: FrookyConfig,
    globalHookSettings: HookSettings,
    globalDecoderSettings: DecoderSettings,
  ): InputNativeHookCanonical[] {
    const inputNativeHookCanonical: InputNativeHookCanonical[] = [];
    const inputNativeHookScopes = this.getPlatformHookScopes(inputFrookyConfig);
    for (const inputNativeHookScope of inputNativeHookScopes) {
      for (const inputNativeHook of inputNativeHookScope.hooks) {
        const hookScopeHookSettings = validateAndRepairHookSettings({ ...globalHookSettings, ...inputNativeHookScope.hookSettings });
        const hookScopeDecoderSettings = validateAndRepairDecoderSettings({ ...globalDecoderSettings, ...inputNativeHookScope.decoderSettings });
        const canonical = this.validateAndNormalizeInputHook(
          inputNativeHook,
          hookScopeHookSettings,
          hookScopeDecoderSettings,
          inputNativeHookScope.module,
        );
        if (canonical !== undefined) {
          inputNativeHookCanonical.push(canonical);
        }
      }
    }
    return inputNativeHookCanonical;
  }
  validateAndNormalizeInputHook(
    inputHook: InputNativeHook,
    hookScopeHookSettings: HookSettings,
    hookScopeDecoderSettings: DecoderSettings,
    moduleName: string,
  ): InputNativeHookCanonical | undefined {
    const symbolName = typeof inputHook === "string" ? inputHook : inputHook.symbolName;

    let hookSettings: HookSettings;
    let decoderSettings: DecoderSettings;
    if (typeof inputHook === "string") {
      hookSettings = hookScopeHookSettings;
      decoderSettings = hookScopeDecoderSettings;
    } else {
      hookSettings = { ...hookScopeHookSettings, ...inputHook.hookSettings };
      decoderSettings = { ...hookScopeDecoderSettings, ...inputHook.decoderSettings };
    }

    const testCandidate: InputNativeHookCanonical = {
      ...(typeof inputHook === "string" ? { symbolName: inputHook } : inputHook),
      moduleName,
      hookSettings,
      decoderSettings,
    };

    try {
      return inputNativeHookCanonicalSchema.parse(testCandidate);
    } catch (e) {
      frooky.log.warn([
        `Skipping hook for function with the symbol name '${symbolName}' from module '${inputHook}' due to an invalid declaration.`,
        `Validation error:\n${z.prettifyError(e as z.ZodError)}`,
      ]);
    }
  }
  getPlatformHookScopes(inputFrookyConfig: FrookyConfig): NativeHookScope[] {
    const platformHookScopes: NativeHookScope[] = [];
    for (const hookScope of inputFrookyConfig.hookScopes) {
      if (isNativeHookScope(hookScope)) {
        platformHookScopes.push(hookScope);
      }
    }
    return platformHookScopes;
  }
}
