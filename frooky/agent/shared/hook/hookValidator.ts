import { DecoderSettings } from "../decoders/decoderSettings";
import { FrookyConfig } from "../frookyConfig";
import { HookSettings } from "./hookSettings";

// export function mergeAndRepairHookSettings(
//   hookScopeHookSettings: InputHookSettings,
//   hookOverrides?: { hookSettings?: InputHookSettings; decoderSettings?: InputDecoderSettings },
// ): HookSettings {
//   return validateAndRepairHookSettings({ ...DEFAULT_HOOK_SETTINGS, ...hookScopeHookSettings, ...hookOverrides?.hookSettings });
// }

// export function mergeDecoderSettings(
//   hookScopeHookSettings: InputHookSettings,
//   hookScopeDecoderSettings: InputDecoderSettings,
//   hookOverrides?: { hookSettings?: InputHookSettings; decoderSettings?: InputDecoderSettings },
// ): { hookSettings: HookSettings; decoderSettings: DecoderSettings } {
//   return {
//     hookSettings: validateAndRepairHookSettings({
//       ...DEFAULT_HOOK_SETTINGS,
//       ...hookScopeHookSettings,
//       ...hookOverrides?.hookSettings,
//     }),
//     decoderSettings: validateAndRepairDecoderSettings({
//       ...DEFAULT_DECODER_SETTINGS,
//       ...hookScopeDecoderSettings,
//       ...hookOverrides?.decoderSettings,
//     }),
//   };
// }

// function validateAndRepairInputNativeHook(
//   inputNativeHook: InputNativeHook,
//   hookScopeHookSettings: InputHookSettings,
//   hookScopeDecoderSettings: InputDecoderSettings,
//   moduleName: string,
// ): NativeHookCanonical | undefined {
//   const symbolName = typeof inputNativeHook === "string" ? inputNativeHook : inputNativeHook.symbolName;
//   const label = `${moduleName}:${symbolName}`;

//   const { hookSettings, decoderSettings } = mergeSettings(
//     hookScopeHookSettings,
//     hookScopeDecoderSettings,
//     typeof inputNativeHook !== "string" ? inputNativeHook : undefined,
//   );

//   const candidate: InputNativeHookCanonical = {
//     ...(typeof inputNativeHook === "string" ? { symbolName: inputNativeHook } : inputNativeHook),
//     moduleName,
//     hookSettings,
//     decoderSettings,
//   };

//   try {
//     return inputNativeHookCanonicalSchema.parse(candidate);
//   } catch (e) {
//     frooky.log.warn([`Skipping hook '${label}' due to an invalid declaration.`, `Validation error:\n${z.prettifyError(e as z.ZodError)}`]);
//   }
// }

// function validateAndRepairInputJavaHook(
//   inputJavaHook: InputJavaHook,
//   hookScopeHookSettings: InputHookSettings,
//   hookScopeDecoderSettings: InputDecoderSettings,
//   className: string,
// ): InputJavaHookCanonical | undefined {
//   const methodName = typeof inputJavaHook === "string" ? inputJavaHook : inputJavaHook.methodName;
//   const label = `${className}:${methodName}`;

//   const { hookSettings, decoderSettings } = mergeSettings(
//     hookScopeHookSettings,
//     hookScopeDecoderSettings,
//     typeof inputJavaHook !== "string" ? inputJavaHook : undefined,
//   );

//   const candidate: InputJavaHookCanonical = {
//     ...(typeof inputJavaHook === "string" ? { methodName: inputJavaHook } : inputJavaHook),
//     className,
//     hookSettings,
//     decoderSettings,
//   };

//   try {
//     return inputJavaHookCanonicalSchema.parse(candidate);
//   } catch (e) {
//     frooky.log.warn([`Skipping hook '${label}' due to an invalid declaration.`, `Validation error:\n${z.prettifyError(e as z.ZodError)}`]);
//   }
// }

// export function validateInputHooks(inputFrookyConfig: FrookyConfig, globalHookSettings: HookSettings, globalDecoderSettings: DecoderSettings): { validJavaInputHooks: InputJavaHookCanonical[]; validNativeInputHooks: InputNativeHookCanonical[] } {
//   const javaHooks: InputJavaHookCanonical[] = [];
//   const nativeHooks: InputNativeHookCanonical[] = [];

//   for (const hookScope of inputFrookyConfig.hookScopes) {
//     const hookScopeHookSettings = validateAndRepairHookSettings({ ...globalHookSettings, ...hookScope.hookSettings });
//     const hookScopeDecoderSettings = validateAndRepairDecoderSettings({ ...globalDecoderSettings, ...hookScope.decoderSettings });

//     if (isJavaHookScope(hookScope as JavaHookScope)) {
//       const { javaClass } = hookScope as JavaHookScope;
//       for (const hook of hookScope.hooks) {
//         const canonical = validateAndRepairInputJavaHook(hook as InputJavaHook, hookScopeHookSettings, hookScopeDecoderSettings, javaClass);
//         if (canonical) javaHooks.push(canonical);
//       }
//     } else if (isNativeHookScope(hookScope as NativeHookScope)) {
//       const { module } = hookScope as NativeHookScope;
//       for (const hook of hookScope.hooks) {
//         const canonical = validateAndRepairInputNativeHook(hook as InputNativeHook, hookScopeHookSettings, hookScopeDecoderSettings, module);
//         if (canonical) nativeHooks.push(canonical);
//       }
//     }
//   }

//   return { validJavaInputHooks: javaHooks, validNativeInputHooks: nativeHooks };
// }

export interface HookValidator<TInputHook, TInputHookCanonical, THookScope> {
  validateHooks(inputFrookyConfig: FrookyConfig, globalHookSettings: HookSettings, globalDecoderSettings: DecoderSettings): TInputHookCanonical[];
  validateAndNormalizeInputHook(
    inputHook: TInputHook,
    hookScopeHookSettings: HookSettings,
    hookScopeDecoderSettings: DecoderSettings,
    className?: string,
    moduleName?: string,
  ): TInputHookCanonical | undefined;

  getPlatformHookScopes(inputFrookyConfig: FrookyConfig): THookScope[];
}
