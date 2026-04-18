import type { NativeHook } from "frooky";
import {
	registerNativeHooks,
	resolveNativeSymbol,
} from "../../android/legacy/android-agent";
import type { HookOp, HookRunner } from "./hookRunner";

export interface NativeHookOp extends HookOp {
	symbol: string; // Todo needs to be refactored when legacy code is refactored
	symbolAddress: NativePointer;
}

export class NativeHookRunner implements HookRunner {
	executeHooking(hooks: NativeHook[]): void {
		var nativeHookOps: NativeHookOp[] = [];

		frooky.log.info(`Executing native hook operations`);
		hooks.forEach((h: NativeHook) => {
			// !!!!!!!!!!!!!!!!!!!!!!!!!!!!
			// TODO: JUMP to legacy code
			// Needs to be refactored later
			// Also, the naming is pretty confusing, should be refactored later
			// We should use the validators for the result set, just like with config and hook validations
			// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

			frooky.log.info(`Building hook operations for native`);
			nativeHookOps.push(...resolveNativeSymbol(h));
		});
		frooky.log.info(
			`Hook operations for the following hook built: ${JSON.stringify(nativeHookOps, null, 2)}`,
		);
		frooky.log.info(`Run native hooking`);
		registerNativeHooks(nativeHookOps);
	}
}
