import type { NativeFrookyFunction, NativeHook } from "../../native/hook/nativeHook";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import type { DecoderSettings } from "../decoders/decoderSettings";
import type { Hook, HookSettings } from "../hook/hook";
import { validateAndRepairDecoderSettings, validateAndRepairHookSettings } from "../validator/configValidator";
import { normalizeParamType, normalizeReturnType, type ParamInput, type RetTypeInput } from "./decodableTypesInput";
import type { DecoderSettingsInput, HookSettingsInput } from "./settingsInput";

/**
 * Native function selector — either a simple function name or a detailed definition.
 *
 * @public
 */
export type NativeFrookyFunctionInput =
  | string
  | (Omit<NativeFrookyFunction, "params" | "retType" | "decoderSettings"> & {
      params?: ParamInput[];
      retType?: RetTypeInput;
      decoderSettings?: DecoderSettings;
    });

/**
 * Native hook configuration for YAML parsing.
 * Extends {@link NativeHook} with a looser `functions` type that accepts
 * both plain symbol names and detailed definitions.
 * *
 * The settings are optional here.
 *
 * @public
 * @discriminator {type}
 */
export interface NativeHookInput extends Omit<NativeHook, "functions" | "hookSettings" | "decoderSettings"> {
  type: "native";
  functions: NativeFrookyFunctionInput[];
  hookSettings?: HookSettingsInput;
  decoderSettings?: DecoderSettingsInput;
}

// Type guard function
export function isNativeHook(h: Hook): h is NativeHook {
  return "functions" in h;
}

// normalizes the NativeFrookyFunctionInput used in the YAML to an internally usable NativeFrookyFunction
function normalizeFunction(fn: NativeFrookyFunctionInput, decoderSettings: DecoderSettings): NativeFrookyFunction {
  if (typeof fn === "string") {
    return { symbol: fn, decoderSettings: decoderSettings };
  }

  return {
    symbol: fn.symbol,
    params: fn.params?.map((param: ParamInput) => normalizeParamType(param, decoderSettings)),
    retType: fn.retType ? normalizeReturnType(fn.retType, decoderSettings) : undefined,
    decoderSettings: decoderSettings,
  };
}

/**
 * Normalizes any NativeHookInput into a NativeHook.
 * Provided decoderSettings are merged with DEFAULT_DECODER_SETTINGS
 * and applied to all parameters and return types.
 */
export function normalizeNativeHook(inputHook: NativeHookInput): NativeHook {
  const mergedDecoderSettings: DecoderSettings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...inputHook.decoderSettings });
  const mergedHookSettings: HookSettings = validateAndRepairHookSettings({ ...DEFAULT_HOOK_SETTINGS, ...inputHook.hookSettings });

  return {
    ...inputHook,
    functions: inputHook.functions.map((fn: NativeFrookyFunctionInput) => normalizeFunction(fn, mergedDecoderSettings)),
    hookSettings: mergedHookSettings,
    decoderSettings: mergedDecoderSettings,
  };
}
