import type { Hook, HookMetadata, NativeHook, Platform } from "frooky";
import z from "zod";



export interface HookValidatorResult {
    validHooks: Hook[];
    invalidHooks: Hook[];
    totalHooks: number;
    totalErrors: number;
}

export function validateHooks(hooks: Hook[], platform: Platform, metadata?: HookMetadata,): HookValidatorResult {

    const result: HookValidatorResult = {
        validHooks: [],
        invalidHooks: [],
        totalHooks: 0,
        totalErrors: 0
    };


    hooks.forEach(hook => {
        result.totalHooks += 1;

        // Merge config metadata into hook metadata
        if (metadata) {
            hook.metadata = { ...metadata, ...hook.metadata };
        }

        try {
            if ("javaClass" in hook) {
                const javaHookInputParsing = hook as JavaHookInput
                javaHookInputParsing.type = "java";
                if( platform !== "Android" ){
                    throw Error(`Skipped the following hook, as it is not compatible with ${platform}: \n${prettyPrintHook(javaHookInputParsing)}`)
                }
                javaHookInputSchema.parse(javaHookInputParsing);

                // normalizing the hook for internal use
                
                result.validHooks.push(javaHook)

            } else if ("objcClass" in hook) {
                const objcHookInputParsing = hook as ObjcHookInput
                objcHookInputParsing.type = "objc";
                if( platform !== "iOS" ){
                    throw Error(`Skipped the following hook, as it is not compatible with ${platform}: \n${prettyPrintHook(objcHookInputParsing)}`)
                }
                objcHookInputSchema.parse(objcHookInputParsing);

                // normalizing the hook for internal use


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
                frooky.log.error(`Hook is not according to schema: ${JSON.stringify(z.treeifyError(error), null, 2)}`);
            } else {
                frooky.log.error(error as string);
            }
        }
    });

    frooky.log.info("All hooks validated.")

    return result;
}
