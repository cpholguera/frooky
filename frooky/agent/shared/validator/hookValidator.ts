import type { Hook, HookMetadata, NativeHook, Platform } from "frooky";
import { isJavaHook, isNativeHook, isObjcHook } from "frooky";
import z from "zod";
import {
	type JavaHookInput,
	normalizeJavaHook,
} from "../inputParsing/javaHookInput";
import { normalizeNativeHook } from "../inputParsing/nativeHookInput";
import {
	normalizeObjcHook,
	type ObjcHookInput,
} from "../inputParsing/objcHookInput";
import { javaHookInputSchema } from "../inputParsing/zodSchemas/javaHook.input.zod";
import { nativeHookInputSchema } from "../inputParsing/zodSchemas/nativeHook.input.zod";
import { objcHookInputSchema } from "../inputParsing/zodSchemas/objcHook.input.zod";
import { prettyPrintHook } from "../utils";

export interface HookValidatorResult {
	validHooks: Hook[];
	invalidHooks: Hook[];
	totalHooks: number;
	totalErrors: number;
}

export function validateHooks(
	hooks: Hook[],
	platform: Platform,
	metadata?: HookMetadata,
): HookValidatorResult {
	const result: HookValidatorResult = {
		validHooks: [],
		invalidHooks: [],
		totalHooks: 0,
		totalErrors: 0,
	};

	hooks.forEach((hook) => {
		result.totalHooks += 1;

		// Merge config metadata into hook metadata
		if (metadata) {
			hook.metadata = { ...metadata, ...hook.metadata };
		}

		try {
			if (platform !== "Android") {
				throw new Error(
					`Skipped the following hook, as it is not compatible with ${platform}: \n${prettyPrintHook(hook)}`,
				);
			}
			if (isJavaHook(hook)) {
				javaHookInputSchema.parse(hook as JavaHookInput);
				const javaHook = normalizeJavaHook(hook);
				result.validHooks.push(javaHook);
			} else if (isObjcHook(hook)) {
				objcHookInputSchema.parse(hook as ObjcHookInput);
				const objcHook = normalizeObjcHook(hook);
				result.validHooks.push(objcHook);
			} else if (isNativeHook(hook)) {
				nativeHookInputSchema.parse(hook as NativeHook);
				const nativeHook = normalizeNativeHook(hook);
				result.validHooks.push(nativeHook);
			} else {
				throw new Error(
					"Hook type is unknown. Make sure that it is either a Java, Objective-C or native hook.",
				);
			}
		} catch (error) {
			result.totalErrors += 1;
			result.invalidHooks.push(hook);
			if (error instanceof z.ZodError) {
				frooky.log.error(
					`Hook is not according to schema: ${JSON.stringify(z.treeifyError(error), null, 2)}`,
				);
			} else {
				frooky.log.error(error as string);
			}
		}
	});

	frooky.log.info("All hooks validated.");

	return result;
}
