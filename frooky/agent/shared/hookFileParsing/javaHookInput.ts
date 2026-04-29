import type { JavaHook, JavaMethod, JavaOverload } from "../../android/hook/javaHook";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import type { DecoderSettings } from "../decoders/decoderSettings";
import type { Hook, HookSettings } from "../hook/hook";
import { validateAndRepairDecoderSettings, validateAndRepairHookSettings } from "../validator/configValidator";
import { normalizeParamType, normalizeReturnType, type ParamInput, type RetTypeInput } from "./decodableTypesInput";
import type { DecoderSettingsInput, HookSettingsInput } from "./settingsInput";

/**
 * Describes a specific Java method overload.
 * Extended type for YAML input parsing.
 * @public
 */
export interface JavaOverloadInput extends Omit<JavaOverload, "params"> {
  /**
   * Parameter type for this overload.
   */
  params: ParamInput[];
}

/**
 * Java method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type JavaMethodInput =
  | string
  | (Omit<JavaMethod, "overloads" | "retType" | "decoderSettings"> & {
      /** Explicit overload definitions. */
      overloads?: JavaOverloadInput[];
      retType?: RetTypeInput;
      decoderSettings?: DecoderSettings;
    });

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

export interface JavaHookInput extends Omit<JavaHook, "methods" | "hookSettings" | "decoderSettings"> {
  type: "java";
  methods: JavaMethodInput[];
  hookSettings?: HookSettingsInput;
  decoderSettings?: DecoderSettingsInput;
}

// Type guard function
export function isJavaHook(h: Hook): h is JavaHook {
  return "javaClass" in h;
}

// will return a JavaOverload for any form of JavaOverloadInput
function normalizeOverload(overload: JavaOverloadInput, decoderSettings: DecoderSettings): JavaOverload {
  return {
    ...overload,
    params: overload.params.map((param: ParamInput) => normalizeParamType(param, decoderSettings)),
  };
}

// will return a JavaMethod for any form of JavaMethodInput or a simple method string
function normalizeMethod(method: JavaMethodInput, decoderSettings: DecoderSettings): JavaMethod {
  if (typeof method === "string") {
    return { name: method, decoderSettings };
  }

  return {
    ...method,
    overloads: method.overloads?.map((overload: JavaOverloadInput) => normalizeOverload(overload, decoderSettings)),
    retType: method.retType ? normalizeReturnType(method.retType, decoderSettings) : undefined,
    decoderSettings,
  };
}

// will return a JavaHook for any form of JavaHookInput
// if not set, the default settings for the hook and their decoders are set here
export function normalizeJavaHook(input: JavaHookInput): JavaHook {
  const mergedDecoderSettings: DecoderSettings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...input.decoderSettings });
  const mergedHookSettings: HookSettings = validateAndRepairHookSettings({ ...DEFAULT_HOOK_SETTINGS, ...input.hookSettings });

  return {
    ...input,
    methods: input.methods.map((method: JavaMethodInput) => normalizeMethod(method, mergedDecoderSettings)),
    hookSettings: mergedHookSettings,
    decoderSettings: mergedDecoderSettings,
  };
}
