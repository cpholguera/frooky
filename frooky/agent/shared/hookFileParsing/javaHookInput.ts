import type { JavaHook, JavaMethodDefinition, JavaOverload } from "../../android/hook/javaHook";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import type { Hook, MethodName } from "../hook/hook";
import { normalizeParam, type ParamInput } from "./paramInput";
import type { DecoderSettingsInput, HookSettingsInput } from "./settingsInput";

/**
 * Describes a specific Java method overload.
 * Extended type for YAML input parsing.
 * @public
 */
export interface JavaOverloadInput extends Omit<JavaOverload, "params"> {
  /**
   * Parameter definitions for this overload.
   */
  params: ParamInput[];
}

/**
 * Extended type for YAML input parsing.
 *
 * @public
 */
export interface JavaMethodDefinitionInput extends Omit<JavaMethodDefinition, "overloads"> {
  /**
   * Explicit overload definitions.
   */
  overloads?: JavaOverloadInput[];
}

/**
 * Java method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type JavaMethodInput = MethodName | JavaMethodDefinitionInput;

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
function normalizeOverload(input: JavaOverloadInput): JavaOverload {
  return {
    ...input,
    params: input.params.map(normalizeParam),
  };
}

// will return a JavaMethodDefinition for any form of JavaMethodDefinitionInput or a simple method string
function normalizeMethod(input: JavaMethodDefinitionInput | string): JavaMethodDefinition {
  if (typeof input === "string") {
    return { name: input };
  }

  return {
    ...input,
    overloads: input.overloads?.map(normalizeOverload),
  };
}

// will return a JavaHook for any form of JavaHookInput
// if not set, the default settings for the hook and their decoders are set here
export function normalizeJavaHook(input: JavaHookInput): JavaHook {
  return {
    ...input,
    methods: input.methods.map(normalizeMethod),
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
