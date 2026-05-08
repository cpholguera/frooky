import { validateAndRepairDecoderSettings, validateAndRepairHookSettings } from "../configValidator";
import type { DecoderSettings } from "../decoders/decoderSettings";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../defaultValues";
import { HookSettings } from "../hook/hookSettings";
import { InputParam, InputRetType, normalizeInputParam, normalizeInputRetType } from "./inputDecodableTypes";
import { InputDecoderSettings, InputHookSettings } from "./inputSettings";

export type InputNativeHookNormalized = {
  symbol: string;
  module: string;
  params?: InputParam[];
  retType?: InputRetType;
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
export type InputNativeHook = string | InputNativeHookNormalized;

/**
 * Native hook configuration for YAML parsing.
 * Extends {@link InputNativeHookGroup} with a looser `functions` type that accepts
 * both plain symbol names and detailed definitions.
 * *
 * The settings are optional here.
 *
 * @public
 * @discriminator {type}
 */
export interface InputNativeHookGroup {
  type: "native";
  module: string;
  hooks: InputNativeHook[];
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
}

// Type guard function
export function isNativeHookGroup(inputHookScope: object): inputHookScope is InputNativeHookGroup {
  return "module" in inputHookScope && !("javaClass" in inputHookScope) && !("objcClass" in inputHookScope);
}

function normalizeHook(
  inputHook: InputNativeHook,
  moduleName: string,
  hookSettings: HookSettings,
  decoderSettings: DecoderSettings,
): InputNativeHookNormalized {
  if (typeof inputHook === "string") {
    return {
      symbol: inputHook,
      module: moduleName,
      hookSettings: hookSettings,
      decoderSettings: decoderSettings,
    };
  }

  return {
    symbol: inputHook.symbol,
    module: moduleName,
    params: inputHook.params?.map((paramInput: InputParam) => normalizeInputParam(paramInput, decoderSettings)),
    retType: inputHook.retType ? normalizeInputRetType(inputHook.retType, decoderSettings) : undefined,
    hookSettings: hookSettings,
    decoderSettings: decoderSettings,
  };
}

/**
 * Normalizes the hook group by merging default decoder and hook settings with optional settings provided on the hook and decoder level,
 *
 * If no settings are set, the default settings will be set.
 *
 * Then each hook, parameter and return types are normalized by using objects such as InputNativeHookNormalized or Param only.
 *
 * @param hookGroup - The input native hook group to normalize.
 * @returns A new `InputNativeHookGroup` with merged settings and normalized hooks.
 */
export function normalizeNativeHookGroup(
  hookGroup: InputNativeHookGroup,
  globalHookSettings: HookSettings,
  globalDecoderSettings: DecoderSettings,
): InputNativeHookGroup {
  const mergedHookSettings: HookSettings = validateAndRepairHookSettings({
    ...DEFAULT_HOOK_SETTINGS,
    ...globalHookSettings,
    ...hookGroup.hookSettings,
  });
  const mergedDecoderSettings: DecoderSettings = validateAndRepairDecoderSettings({
    ...DEFAULT_DECODER_SETTINGS,
    ...globalDecoderSettings,
    ...hookGroup.decoderSettings,
  });

  return {
    ...hookGroup,
    hooks: hookGroup.hooks.map((inputHook: InputNativeHook) => normalizeHook(inputHook, hookGroup.module, mergedHookSettings, mergedDecoderSettings)),
    hookSettings: mergedHookSettings,
    decoderSettings: mergedDecoderSettings,
  };
}
