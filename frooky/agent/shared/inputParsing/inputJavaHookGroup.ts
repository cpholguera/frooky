import { validateAndRepairDecoderSettings, validateAndRepairHookSettings } from "../configValidator";
import { DecoderSettings } from "../decoders/decoderSettings";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../defaultValues";
import { HookSettings } from "../hook/hookSettings";
import { InputParam, InputRetType, normalizeInputParam, normalizeInputRetType } from "./inputDecodableTypes";
import { InputDecoderSettings, InputHookSettings } from "./inputSettings";

/**
 * Describes a specific Java method overload.
 * Extended type for YAML input parsing.
 * @public
 */
export interface InputOverload {
  /**
   * Parameter type for this overload.
   */
  params: InputParam[];
}

/**
 * Java method selector - either a simple method name or a detailed definition.
 *
 * @public
 */
export type InputJavaHookNormalized = {
  javaClass: string;
  method: string;
  overloads?: InputOverload[];
  retType?: InputRetType;
  hookSettings?: HookSettings;
  decoderSettings?: DecoderSettings;
};

/**
 * Java method selector - either a simple method name or a detailed definition.
 *
 * @public
 */
export type InputJavaHook = string | InputJavaHookNormalized;

/**
 * Native hook configuration.
 *
 * Extended type for YAML input parsing.
 *
 * The settings are optional here.
 *
 * @public
 * @discriminator {type}
 */
export interface InputJavaHookGroup {
  type: "java";
  javaClass: string;
  hooks: InputJavaHook[];
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
}

// Type guard function
export function isJavaHookScope(hookScopeInput: object): hookScopeInput is InputJavaHookGroup {
  return "javaClass" in hookScopeInput;
}

// will return a JavaOverload for any form of JavaOverloadInput
function normalizeOverload(overload: InputOverload, decoderSettings: DecoderSettings): InputOverload {
  return {
    ...overload,
    params: overload.params.map((param: InputParam) => normalizeInputParam(param, decoderSettings)),
  };
}

// will return a JavaMethod for any form of JavaMethodInput or a simple method string
function normalizeMethod(
  javaClass: string,
  method: InputJavaHook,
  hookSettings: HookSettings,
  decoderSettings: DecoderSettings,
): InputJavaHookNormalized {
  if (typeof method === "string") {
    return { javaClass: javaClass, method: method, hookSettings: hookSettings, decoderSettings: decoderSettings };
  }

  return {
    ...method,
    javaClass: javaClass,
    overloads: method.overloads?.map((overload: InputOverload) => normalizeOverload(overload, decoderSettings)),
    retType: method.retType ? normalizeInputRetType(method.retType, decoderSettings) : undefined,
    hookSettings: hookSettings,
    decoderSettings: decoderSettings,
  };
}

// normalized hook group
export function normalizeJavaHookGroup(
  hookGroup: InputJavaHookGroup,
  globalHookSettings: HookSettings,
  globalDecoderSettings: DecoderSettings,
): InputJavaHookGroup {
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
    hooks: hookGroup.hooks.map((hook: InputJavaHook) => normalizeMethod(hookGroup.javaClass, hook, mergedHookSettings, mergedDecoderSettings)),
    hookSettings: mergedHookSettings,
    decoderSettings: mergedDecoderSettings,
  };
}
