import type { ObjcHook, ObjcMethod } from "../../ios/hook/objcHook";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import type { Hook } from "../hook/hook";
import { normalizeParamType, normalizeReturnType, ParamInput, RetTypeInput } from "./decodableTypesInput";
import type { DecoderSettingsInput, HookSettingsInput } from "./settingsInput";

/**
 * Objc method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type ObjcMethodInput = string | ObjcMethod;

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
    params: input.params?.map(normalizeParamType),
    retType: input.retType ? normalizeReturnType(input.retType) : undefined,
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
