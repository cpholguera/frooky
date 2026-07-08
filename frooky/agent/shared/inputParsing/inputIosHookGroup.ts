import { DecoderSettings, HookSettings } from "../frookySettings";
import { InputRetType } from "./inputDecodableTypes";
import { InputDecoderSettings, InputHookSettings } from "./inputSettings";

/**
 * IMPORTANT: This is just a place holder file!
 * At the moment, only native hooks can be used on iOS
 */

/**
 * Objective-C canonical input hook
 *
 * @public
 */
export type InputObjcHookNormalized = {
  objcClass: string;
  method: string;
  retType?: InputRetType;
  hookSettings?: HookSettings;
  decoderSettings?: DecoderSettings;
};

/**
 * Java method selector - either a simple method name or a detailed definition.
 *
 * @public
 */
export type InputObjcHook = string | InputObjcHookNormalized;

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
export interface InputObjcHookGroup {
  type: "objc";
  objcClass: string;
  hooks: InputObjcHook[];
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
}

// Type guard function
export function isObjcHookScope(hookScopeInput: object): hookScopeInput is InputObjcHookGroup {
  return "objcClass" in hookScopeInput;
}
