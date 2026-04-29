import type { NativeFrookyFunction, NativeHook } from "../../native/hook/nativeHook";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import type { Hook } from "../hook/hook";
import { normalizeParamType, normalizeReturnType, ParamInput, ReturnTypeInput } from "./decodableTypesInput";
import type { DecoderSettingsInput, HookSettingsInput } from "./settingsInput";

/**
 * Expanded Native function definition with YAML-parsed parameters.
 *
 * @public
 */
export interface NativeFrookyFunctionInput extends Omit<NativeFrookyFunction, "params" | "returnType"> {
  params?: ParamInput[];
  returnType?: ReturnTypeInput;
}

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

function normalizeFunctionDefinition(input: NativeFrookyFunctionInput): NativeFrookyFunction {
  return {
    ...input,
    params: input.params?.map(normalizeParamType),
    returnType: input.returnType ? normalizeReturnType(input.returnType) : undefined,
  };
}

function normalizeFunction(input: NativeFrookyFunctionInput): NativeFrookyFunction {
  if (typeof input === "string") {
    return { symbol: input };
  }
  return normalizeFunctionDefinition(input);
}

// will return a NativeHook for any form of NativeHookInput
// if not set, the default settings for the hook and their decoders are set here
export function normalizeNativeHook(input: NativeHookInput): NativeHook {
  return {
    ...input,
    functions: input.functions.map(normalizeFunction),
    hookSettings: {
      ...DEFAULT_HOOK_SETTINGS,
      ...input.hookSettings,
    },
    decoderSettings: {
      ...DEFAULT_DECODER_SETTINGS,
      ...input.decoderSettings,
    },
  };
}
