import type { Hook, HookSettings, Platform } from "frooky";
import { z } from "zod";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../config";
import type { DecoderSettings } from "../decoders/decoderSettings";
import { isJavaHook, type JavaHookInput, normalizeJavaHook } from "../hookFileParsing/javaHookInput";
import { isNativeHook, type NativeHookInput, normalizeNativeHook } from "../hookFileParsing/nativeHookInput";
import { isObjcHook, normalizeObjcHook, type ObjcHookInput } from "../hookFileParsing/objcHookInput";
import { javaHookInputSchema } from "../hookFileParsing/zodSchemas/javaHook.input.zod";
import { nativeHookInputSchema } from "../hookFileParsing/zodSchemas/nativeHook.input.zod";
import { objcHookInputSchema } from "../hookFileParsing/zodSchemas/objcHook.input.zod";
import { prettyPrintHook } from "../utils";

export interface HookValidatorResult {
  validHooks: Hook[];
  invalidHooks: Hook[];
  totalHooks: number;
  totalErrors: number;
}

export function validateHooks(hooks: Hook[], platform: Platform, globalHooksSettings?: HookSettings, globalDecoderSettings?: DecoderSettings): HookValidatorResult {
  const result: HookValidatorResult = {
    validHooks: [],
    invalidHooks: [],
    totalHooks: 0,
    totalErrors: 0,
  };

  hooks.forEach((hook) => {
    result.totalHooks += 1;

    // Merge global hooks settings into hook setting
    if (globalHooksSettings) {
      hook.hookSettings = { ...DEFAULT_HOOK_SETTINGS, ...globalHooksSettings, ...hook.hookSettings };
    } else {
      hook.hookSettings = DEFAULT_HOOK_SETTINGS;
    }
    // Merge global decoder settings into hook setting
    if (globalDecoderSettings) {
      hook.decoderSettings = { ...DEFAULT_DECODER_SETTINGS, ...globalDecoderSettings, ...hook.decoderSettings };
    } else {
      hook.decoderSettings = DEFAULT_DECODER_SETTINGS;
    }

    try {
      if (isJavaHook(hook)) {
        if (platform !== "Android") {
          throw new Error(`Skipped the following hook, as it is not compatible with ${platform}: \n${prettyPrintHook(hook)}`);
        }
        const javaHookInput = hook as JavaHookInput;
        javaHookInput.type = "java";
        javaHookInputSchema.parse(javaHookInput);
        const javaHook = normalizeJavaHook(javaHookInput);
        result.validHooks.push(javaHook);
      } else if (isObjcHook(hook)) {
        if (platform !== "iOS") {
          throw new Error(`Skipped the following hook, as it is not compatible with ${platform}: \n${prettyPrintHook(hook)}`);
        }
        const objcHookInput = hook as ObjcHookInput;
        objcHookInput.type = "objc";
        objcHookInputSchema.parse(objcHookInput);
        const objcHook = normalizeObjcHook(objcHookInput);
        result.validHooks.push(objcHook);
      } else if (isNativeHook(hook)) {
        const nativeHookInput = hook as NativeHookInput;
        nativeHookInput.type = "native";
        nativeHookInputSchema.parse(nativeHookInput);
        const nativeHook = normalizeNativeHook(nativeHookInput);
        result.validHooks.push(nativeHook);
      } else {
        throw new Error("Hook type is unknown. Make sure that it is either a Java, Objective-C or native hook.");
      }
    } catch (e) {
      result.totalErrors += 1;
      result.invalidHooks.push(hook);
      if (e instanceof z.ZodError) {
        frooky.log.warn(`The hook contains invalid entires. It will be ignored:\n${z.prettifyError(e)}`);
      } else {
        frooky.log.warn(e as string);
      }
    }
  });

  frooky.log.info("All hooks validated.");

  return result;
}
