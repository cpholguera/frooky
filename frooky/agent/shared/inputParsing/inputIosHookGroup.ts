import { DecoderSettings, HookSettings, InputDecoderSettings, InputHookSettings, InputRetType } from "frooky/shared";

/**
 * Objective-C canonical input hook
 *
 * @public
 */
export type InputObjcHook = {
  className: string;
  methodName: string;
  retType?: InputRetType;
  hookSettings?: HookSettings;
  decoderSettings?: DecoderSettings;
};

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
  hooks: string | InputObjcHook;
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
}

// Type guard function
export function isObjcHookScope(hookScopeInput: object): hookScopeInput is InputObjcHookGroup {
  return "objcClass" in hookScopeInput;
}
