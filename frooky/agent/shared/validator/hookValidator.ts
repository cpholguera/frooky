import type { FrookyConfig, Hook, JavaHook, NativeHook, ObjCHook, Platform } from "frooky";
import z from "zod";
import { javaHookSchema } from "../../types/hook/javaHook.zod";
import { nativeHookSchema } from "../../types/hook/nativeHook.zod";
import { objCHookSchema } from "../../types/hook/objcHook.zod";
import { prettyPrintHook } from "shared/utils";


export interface HookValidatorResult {
    validHooks: Hook[];
    invalidHooks: Hook[];
    totalHooks: number;
    totalErrors: number;
}

export function validateHooks(frookyConfig: FrookyConfig, platform: Platform): HookValidatorResult {

    const result: HookValidatorResult = {
        validHooks: [],
        invalidHooks: [],
        totalHooks: 0,
        totalErrors: 0
    };

    frookyConfig.hooks.forEach(hook => {
        result.totalHooks += 1;

        // Merge config metadata into hook metadata
        if (frookyConfig.metadata) {
            hook.metadata = { ...frookyConfig.metadata, ...hook.metadata };
        }

        try {
            if ("javaClass" in hook) {
                const javaHook = hook as JavaHook
                javaHook.type = "java";
                if( platform !== "Android" ){
                    throw Error(`Skipped the following hook, as it is not compatible with ${platform}: \n${prettyPrintHook(javaHook)}`)
                }
                javaHookSchema.parse(javaHook);
                result.validHooks.push(javaHook)

            } else if ("objcClass" in hook) {
                const objcHook = hook as ObjCHook
                objcHook.type = "objc";
                if( platform !== "iOS" ){
                    throw Error(`Skipped the following hook, as it is not compatible with ${platform}: \n${prettyPrintHook(objcHook)}`)
                }
                objCHookSchema.parse(objcHook);
                result.validHooks.push(objcHook)

            } else if ("functions" in hook) {
                const nativeHook = hook as NativeHook
                nativeHook.type = "native";
                nativeHookSchema.parse(nativeHook);
                result.validHooks.push(nativeHook)
            } else {
                throw new Error("Hook type is unknown. Make sure that it is either a Java, Objective-C or native hook.");
            }
        } catch (error) {
            result.totalErrors += 1;
            result.invalidHooks.push(hook);
            if (error instanceof z.ZodError) {
                frooky.log.error(`Hook is not according to schema: ${z.prettifyError(error)}`);
            } else {
                frooky.log.error(error as string);
            }
        }
    });

    frooky.log.info("All hooks validated.")

    return result;
}
