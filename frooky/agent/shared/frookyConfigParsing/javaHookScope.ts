import { DecoderSettings } from "../decoders/decoderSettings";
import { HookSettings } from "../hook/hookSettings";
import { ParamInput, RetTypeInput } from "./decodableTypesInput";
import { InputDecoderSettings, InputHookSettings } from "./settingsInput";

/**
 * Describes a specific Java method overload.
 * Extended type for YAML input parsing.
 * @public
 */
export interface InputOverload {
  /**
   * Parameter type for this overload.
   */
  params: ParamInput[];
}

/**
 * Java method selector - either a simple method name or a detailed definition.
 *
 * @public
 */
export type InputJavaHookCanonical = {
  className: string;
  methodName: string;
  overloads?: InputOverload[];
  retType?: RetTypeInput;
  hookSettings?: HookSettings;
  decoderSettings?: DecoderSettings;
};

/**
 * Java method selector - either a simple method name or a detailed definition.
 *
 * @public
 */
export type InputJavaHook = string | InputJavaHookCanonical;

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
export interface JavaHookScope {
  type: "java";
  javaClass: string;
  hooks: InputJavaHook[];
  hookSettings?: InputHookSettings;
  decoderSettings?: InputDecoderSettings;
}

// export interface HookScopeInput extends Omit<HookScope, "hookSettings" | "decoderSettings"> {
//   hookSettings?: HookSettingsInput;
//   decoderSettings?: DecoderSettingsInput;
// }

// Type guard function
export function isJavaHookScope(hookScopeInput: object): hookScopeInput is JavaHookScope {
  return "javaClass" in hookScopeInput;
}

// // will return a JavaOverload for any form of JavaOverloadInput
// function normalizeOverload(overload: JavaOverloadInput, decoderSettings: DecoderSettings): JavaOverload {
//   return {
//     ...overload,
//     params: overload.params.map((param: ParamInput) => normalizeParamType(param, decoderSettings)),
//   };
// }

// // will return a JavaMethod for any form of JavaMethodInput or a simple method string
// function normalizeMethod(method: JavaHookInput, hookSettings: HookSettings, decoderSettings: DecoderSettings): JavaHook {
//   if (typeof method === "string") {
//     return { name: method, hookSettings: hookSettings, decoderSettings: decoderSettings };
//   }

//   return {
//     ...method,
//     overloads: method.overloads?.map((overload: JavaOverloadInput) => normalizeOverload(overload, decoderSettings)),
//     retType: method.retType ? normalizeReturnType(method.retType, decoderSettings) : undefined,
//     hookSettings: hookSettings,
//     decoderSettings: decoderSettings,
//   };
// }

// // resolves the declared hooks form the hook file and returns a JavaHookScope
// export function resolveJavaHookScope(hookScopeInput: JavaHookScopeInput): JavaHookScope {
//   const mergedDecoderSettings: DecoderSettings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...hookScopeInput.decoderSettings });
//   const mergedHookSettings: HookSettings = validateAndRepairHookSettings({ ...DEFAULT_HOOK_SETTINGS, ...hookScopeInput.hookSettings });

//   return {
//     ...hookScopeInput,
//     hooks: hookScopeInput.hooks.map((hooks: JavaHookInput) => normalizeMethod(hooks, mergedHookSettings, mergedDecoderSettings)),
//     hookSettings: mergedHookSettings,
//     decoderSettings: mergedDecoderSettings,
//   };
// }
