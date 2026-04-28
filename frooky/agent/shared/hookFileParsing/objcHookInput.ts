import type { ObjcHook, ObjcMethodDefinition } from "../../ios/hook/objcHook";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import type { Hook, MethodName, ReturnType } from "../hook/hook";
import { normalizeParam, type ParamInput } from "./paramInput";
import type { DecoderSettingsInput, HookSettingsInput } from "./settingsInput";

/**
 * Expanded Objective-C method definition with name and optional overloads.
 *
 * @public
 */
export interface ObjcMethodDefinitionInput {
  name: MethodName;
  returnType?: ReturnType;
  params?: ParamInput[];
}

/**
 * Objc method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type ObjcMethodInput = MethodName | ObjcMethodDefinitionInput;

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
export interface ObjcHookInput extends Omit<ObjcHook, "methods" | "hookSettings" | "decoderSettings"> {
  type: "objc";
  methods: ObjcMethodInput[];
  hookSettings?: HookSettingsInput;
  decoderSettings?: DecoderSettingsInput;
}

// Type guard function
export function isObjcHook(h: Hook): h is ObjcHook {
  return "objcClass" in h;
}

// returns a normalized ObjcMethodDefinition from any type of ObjcMethodInput
function normalizeObjcMethod(input: ObjcMethodInput): ObjcMethodDefinition {
  if (typeof input === "string") {
    return { name: input };
  }

  return {
    ...input,
    params: input.params?.map(normalizeParam),
  };
}

// will return a NativeHook for any form of NativeHookInput
// if not set, the default settings for the hook and their decoders are set here
export function normalizeObjcHook(input: ObjcHookInput): ObjcHook {
  return {
    ...input,
    methods: input.methods.map(normalizeObjcMethod),
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
