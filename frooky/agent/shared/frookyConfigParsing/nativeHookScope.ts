import type { DecoderSettings } from "../decoders/decoderSettings";
import { HookSettings } from "../hook/hookSettings";
import { type ParamInput, type RetTypeInput } from "./decodableTypesInput";
import { InputDecoderSettings, InputHookSettings } from "./settingsInput";

export type InputNativeHookCanonical = {
  moduleName: string;
  symbolName: string;
  params?: ParamInput[];
  retType?: RetTypeInput;
  hookSettings?: HookSettings;
  decoderSettings?: DecoderSettings;
};

/**
 * Type describing a native function in an YAML input file.
 *
 * Can be string, or a NativeFrookyFunction with optional properties.
 *
 * @public
 */
export type InputNativeHook = string | InputNativeHookCanonical;

/**
 * Native hook configuration for YAML parsing.
 * Extends {@link NativeHookScope} with a looser `functions` type that accepts
 * both plain symbol names and detailed definitions.
 * *
 * The settings are optional here.
 *
 * @public
 * @discriminator {type}
 */
export interface NativeHookScope {
  type: "native";
  module: string;
  hooks: InputNativeHook[];
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
}

// Type guard function
export function isNativeHookScope(inputHookScope: object): inputHookScope is NativeHookScope {
  return "module" in inputHookScope && !("javaClass" in inputHookScope) && !("objcClass" in inputHookScope);
}

// // normalizes the NativeFrookyFunctionInput used in the YAML to an internally usable NativeFrookyFunction
// function normalizeFunction(moduleName: string, fn: NativeHookInput, hookSettings: HookSettings, decoderSettings: DecoderSettings): NativeHook {
//   if (typeof fn === "string") {
//     return {
//       moduleName: moduleName,
//       symbolName: fn,
//       hookSettings: hookSettings,
//       decoderSettings: decoderSettings,
//     };
//   }

//   return {
//     moduleName: moduleName,
//     symbolName: fn.symbolName,
//     params: fn.params?.map((param: ParamInput) => normalizeParamType(param, decoderSettings)),
//     retType: fn.retType ? normalizeReturnType(fn.retType, decoderSettings) : undefined,
//     hookSettings: hookSettings,
//     decoderSettings: decoderSettings,
//   };
// }

// /**
//  *
//  * resolves the declared hooks form the hook file and returns a NativeHookScope.
//  *
//  */
// export function normalizeNativeHookScope(inputHookScope: NativeHookScopeInput): NativeHookScope {
//   const mergedDecoderSettings: DecoderSettings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...inputHookScope.decoderSettings });
//   const mergedHookSettings: HookSettings = validateAndRepairHookSettings({ ...DEFAULT_HOOK_SETTINGS, ...inputHookScope.hookSettings });

//   return {
//     ...inputHookScope,
//     hooks: inputHookScope.hooks.map((fn: NativeHookInput) => normalizeFunction(inputHookScope.moduleName, fn, mergedHookSettings, mergedDecoderSettings)),
//     hookSettings: mergedHookSettings,
//     decoderSettings: mergedDecoderSettings,
//   };
// }
