import { DecoderSettings } from "../decoders/decoderSettings";
import { HookSettings } from "../hook/hookSettings";
import { RetTypeInput } from "./decodableTypesInput";
import { InputDecoderSettings, InputHookSettings } from "./settingsInput";

/**
 * Objective-C canonical input hook
 *
 * @public
 */
export type InputObjcHookCanonical = {
  className: string;
  methodName: string;
  retType?: RetTypeInput;
  hookSettings?: HookSettings;
  decoderSettings?: DecoderSettings;
};

/**
 * Objective-C input hook - either a simple method name or a detailed definition (canonical form)
 *
 * @public
 */
export type InputObjcHook = string | InputObjcHookCanonical;

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
export interface ObjcHookScope {
  type: "objc";
  objcClass: string;
  hooks: InputObjcHook[];
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
}

// Type guard function
export function isObjcHookScope(hookScopeInput: object): hookScopeInput is ObjcHookScope {
  return "objcClass" in hookScopeInput;
}
