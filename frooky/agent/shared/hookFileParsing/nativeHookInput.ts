import { NativeParam } from "../../native/decoders/nativeDecodableTypes";
import type { NativeFrookyFunction, NativeHook } from "../../native/hook/nativeHook";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import { Param } from "../decoders/decodableTypes";
import { DecoderSettings } from "../decoders/decoderSettings";
import type { Hook } from "../hook/hook";
import { normalizeParamType, normalizeReturnType, ParamInput, RetTypeInput } from "./decodableTypesInput";
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

function normalizeFunction(fn: NativeFrookyFunctionInput, decoderSettings: DecoderSettings): NativeFrookyFunction {
  if (typeof fn === "string") {
    return { symbol: fn, decoderSettings: decoderSettings };
  } else {

    console.log("ABOUT TO NORMALIZE THE NATIVE FUNCTION: ")
    console.log(JSON.stringify(fn,null,2))

    let normalizedParams: Param[] = []
    if(fn.params){
      fn.params.forEach(( param: ParamInput ) => {
        normalizedParams.push( normalizeParamType(param, decoderSettings))
      })
    }

    return {
      symbol: fn.symbol,
      params: fn.params? normalizedParams: undefined,
      retType: fn.retType ? normalizeReturnType(fn.retType, decoderSettings): undefined,
      decoderSettings: decoderSettings
    };
  }
}

// will return a NativeHook for any form of NativeHookInput
// decoderSettings will be used for parameter and return type settings
// if no decoderSettings are provided, the DEFAULT_DECODER_SETTINGS are applied
export function normalizeNativeHook(inputHook: NativeHookInput): NativeHook {
  const mergedDecoderSettings: DecoderSettings = {...DEFAULT_DECODER_SETTINGS, ...inputHook.decoderSettings}
  // normalize all functions
  const normalizedFunctions: NativeFrookyFunction[] = []
  inputHook.functions.forEach((fn: NativeFrookyFunctionInput) => {
    normalizedFunctions.push(normalizeFunction(fn, mergedDecoderSettings))
  })
  return {
    ...inputHook,
    functions: normalizedFunctions,
    hookSettings: {
      ...DEFAULT_HOOK_SETTINGS,
      ...inputHook.hookSettings,
    },
    decoderSettings: mergedDecoderSettings,
  };
}
