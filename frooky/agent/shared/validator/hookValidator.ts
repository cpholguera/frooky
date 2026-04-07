import type { FrookyConfig, Hook, JavaHook, NativeHook, ObjCHook } from "frooky";
import z from "zod";
import { javaHookSchema } from "../../types/hook/javaHook.zod";
import { nativeHookSchema } from "../../types/hook/nativeHook.zod";
import { objCHookSchema } from "../../types/hook/objcHook.zod";

export function validateHooks(frookyConfig: FrookyConfig) {

    const validHooks: Hook[] = [];

    frookyConfig.hooks.forEach(hook => {
        try {
            if ("javaClass" in hook) {
                const javaHook = hook as JavaHook
                javaHookSchema.parse(javaHook);
                validHooks.push(javaHook)

            } else if ("objcClass" in hook) {
                const objcHook = hook as ObjCHook
                objCHookSchema.parse(objcHook);
                validHooks.push(objcHook)

            } else if ("nativeClass" in hook) {
                const nativeHook = hook as NativeHook
                nativeHookSchema.parse(nativeHook);
                validHooks.push(nativeHook)
            } else {
                throw new Error("Hook type is unknown. Make sure that it is either a Java, Objective-C or native hook.");
            }
        } catch (error) {
            if (error instanceof z.ZodError) {
                frooky.log.error(JSON.stringify(z.treeifyError(error), null, 2));
            } else {
                frooky.log.error(error);
            }
        }
    });
}
