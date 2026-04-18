import Java from "frida-java-bridge";
import { DEFAULT_STACK_TRACE_LIMIT } from "../../shared/config";
import { HookEvent } from "../../shared/event/hookEvent";
import type { MethodName } from "../../shared/hook/hook";
import type { HookOp, HookRunner } from "../../shared/hook/hookRunner";
import type { Param, ParamType } from "../../shared/hook/parameter";
import { uuidv4 } from "../../shared/utils";
import { JavaHookEvent } from "../event/javaHookEvent";
import type { JavaHook, JavaMethodDefinition, JavaOverload } from "./javaHook";

// contains everything needed to hook one java method
export interface JavaHookOp extends HookOp {
	javaClass: string;
	methodName: MethodName;
	params: Param[];
	javaMethod: Java.Method;
}

// builds JavaHookOps fro ALL overloads of a certain method
function buildHookOpsForAllOverloads(
	hook: JavaHook,
	handle: Java.MethodDispatcher,
	methodDefinition: JavaMethodDefinition,
	javaHookOps: JavaHookOp[],
): void {
	handle.overloads.forEach((javaMethod: Java.Method) => {
		const params: Param[] = [];
		javaMethod.argumentTypes.forEach((t: Java.Type) => {
			if (t.className) {
				params.push({ type: t.className });
			} else {
				frooky.log.warn(`No Frida type name for the VM type ${t.name} found.`);
			}
		});

		javaHookOps.push({
			javaClass: hook.javaClass,
			methodName: methodDefinition.name,
			params: params,
			javaMethod: javaMethod,
			stackTraceLimit: hook.stackTraceLimit ?? DEFAULT_STACK_TRACE_LIMIT,
			eventFilter: hook.eventFilter,
			category: hook.metadata?.category,
		});
	});
}

// only builds JavaHookOps for overloads which are explicitly declared
function buildHookOpsForDeclaredOverloads(
	hook: JavaHook,
	handle: Java.MethodDispatcher,
	methodDefinition: JavaMethodDefinition,
	javaHookOps: JavaHookOp[],
): void {
	methodDefinition.overloads?.forEach((declaredOverload: JavaOverload) => {
		const paramList: ParamType[] = [];
		declaredOverload.params.forEach((p: Param) => {
			paramList.push(p.type);
		});
		try {
			const javaMethod: Java.Method = handle.overload(...paramList);
			javaHookOps.push({
				javaClass: hook.javaClass,
				methodName: methodDefinition.name,
				params: declaredOverload.params,
				javaMethod: javaMethod,
				stackTraceLimit: hook.stackTraceLimit ?? DEFAULT_STACK_TRACE_LIMIT,
				eventFilter: hook.eventFilter,
				category: hook.metadata?.category,
			});
		} catch (e) {
			frooky.log.warn(
				`Failed to get overload for method '${methodDefinition.name}' in class '${hook.javaClass}': ${e}.`,
			);
		}
	});
}

// builds a list of JavaHookOp. Each JavaHookOp contains all information to hook ONE java method
function buildHookOperations(hook: JavaHook): JavaHookOp[] {
	if (!hook.methods) {
		frooky.log.warn(`Java hook did not specify an methods.`);
		return [];
	}

	const hookOps: JavaHookOp[] = [];
	for (const method of hook.methods) {
		try {
			const handle: Java.MethodDispatcher = Java.use(hook.javaClass)[
				method.name
			];
			if (!method.overloads) {
				buildHookOpsForAllOverloads(hook, handle, method, hookOps);
			} else {
				buildHookOpsForDeclaredOverloads(hook, handle, method, hookOps);
			}
		} catch (e) {
			frooky.log.warn(
				`Failed to resolve method '${method.name}' in class '${hook.javaClass}': ${e}.`,
			);
		}
	}
	return hookOps;
}

// actually hooks the java method
function registerHookOperation(javaHookOp: JavaHookOp) {
	const Exception = Java.use("java.lang.Exception");
	const System = Java.use("java.lang.System");

	javaHookOp.javaMethod.implementation = function (...args: any[]) {
		const stackTrace: string[] = [];

		if (javaHookOp.stackTraceLimit > 0) {
			const st = Exception.$new().getStackTrace();
			st.forEach((stElement: string, index: number) => {
				if (index < javaHookOp.stackTraceLimit) {
					stackTrace.push(stElement.toString());
				}
			});
		}

		// const returnType = parseReturnValue(methodHeader);

		let instanceId: string;
		if (this && this.$className && typeof this.$h === "undefined") {
			instanceId = "static";
		} else {
			try {
				instanceId = System.identityHashCode(this);
			} catch (e) {
				console.error("Error in identityHashCode", e);
				instanceId = "error";
			}
		}

		const event = new JavaHookEvent(javaHookOp.javaClass);
		event.category = javaHookOp.category;
		if (stackTrace.length > 0) {
			event.stackTrace = stackTrace;
		}

		// = {
		// 	id: uuidv4(),
		// 	type: "hook",
		// 	time: new Date().toISOString(),
		// 	class: javaHookOp.class,
		// 	method: javaHookOp.methodName,
		// 	instanceId: instanceId,
		// 	// inputParameters: decodeArguments(parameterTypes, arguments),
		// };

		// if (stackTrace.length > 0) {event }

		try {
			// call original method
			const returnValue = javaHookOp.javaMethod.apply(this, args);
			// event.returnValue = decodeArguments([returnType], [returnValue]);
			frooky.addEvent(event);
			return returnValue;
		} catch (e) {
			// event.exception = e.toString();
			frooky.addEvent(event);
			throw e;
		}
	};
}

export class JavaHookRunner implements HookRunner {
	executeHooking(hooks: JavaHook[]): void {
		frooky.log.info(`Executing Android hook operations`);

		var hookOps: JavaHookOp[] = [];

		hooks.forEach((h: JavaHook) => {
			hookOps.push(...buildHookOperations(h));
		});

		frooky.log.info(
			`Hook operations for the following hook built: ${JSON.stringify(hookOps, null, 2)}`,
		);
		frooky.log.info(`Run Android hooking`);

		hookOps.forEach((hookOp: JavaHookOp) => {
			registerHookOperation(hookOp);
		});
	}
}
