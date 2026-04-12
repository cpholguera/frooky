import Java from "frida-java-bridge";
import type { MethodName } from "../../shared/hook/hook";
import type { HookEntry, HookRunner } from "../../shared/hook/hookRunner";
import type { Param, ParamType } from "../../shared/hook/parameter";
import { uuidv4 } from "../../shared/utils";
import type { JavaHook, JavaOverload } from "./javaHook";

export interface JavaHookEntry extends HookEntry {
  class: string;
  methodName: MethodName;
  params: Param[];
  javaMethod: Java.Method;
}

function buildHookOperations(hook: JavaHook): JavaHookEntry[] {
  const entries: JavaHookEntry[] = [];
  let handle: Java.Wrapper;

  if (!hook.methods) {
    frooky.log.warn(`Java hook did not specify an methods.`);
    return [];
  }

  for (const method of hook.methods) {
    try {
      handle = Java.use(hook.javaClass)[method.name];
      if (!method.overloads) {
        // build hook operations for all overloads
        handle.overloads.forEach((javaMethod: Java.Method) => {
          const params: Param[] = [];
          javaMethod.argumentTypes.forEach((t: Java.Type) => {
            if (t.className) {
              params.push({
                type: t.className,
              });
            } else {
              frooky.log.warn(`No Frida type name for the VM type ${t.name} found.`);
            }
          });

          entries.push({
            class: hook.javaClass,
            methodName: method.name,
            params: params,
            javaMethod: javaMethod,
          });

          console.log(JSON.stringify(entries, null, 2));
        });
      } else {
        // only build hook operations for the declared overloads
        method.overloads.forEach((o: JavaOverload) => {
          const paramList: ParamType[] = [];
          o.params.forEach((p: Param) => {
            paramList.push(p.type);
          });
          try {
            const javaMethod: Java.Method = handle.overload(...paramList);
            entries.push({
              class: hook.javaClass,
              methodName: method.name,
              params: o.params,
              javaMethod: javaMethod,
            });
          } catch (e) {
            frooky.log.warn(`Failed to get overload for method '${method.name}' in class '${hook.javaClass}': ${e}.`);
          }
        });
      }
    } catch (e) {
      frooky.log.warn(`Failed to resolve method '${method.name}' in class '${hook.javaClass}': ${e}.`);
    }
  }

  return entries;
}

function registerHook(hookEntries: JavaHookEntry[]) {
  const Exception = Java.use("java.lang.Exception");
  const System = Java.use("java.lang.System");

  hookEntries.forEach((hookEntry: JavaHookEntry) => {
    hookEntry.javaMethod.implementation = function () {
      const st = Exception.$new().getStackTrace();
      const stackTrace: string[] = [];
      st.forEach((stElement: string, index: number) => {
        if (index < 10) {
          stackTrace.push(stElement.toString());
        }
        // if (hookEntry.maxFrames === -1 || index < hookEntry.maxFrames) {
        //   stackTrace.push(stElement.toString());
        // }
      });

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

      const event = {
        id: uuidv4(),
        type: "hook",
        time: new Date().toISOString(),
        class: hookEntry.class,
        method: hookEntry.methodName,
        instanceId: instanceId,
        stackTrace: stackTrace,
        // inputParameters: decodeArguments(parameterTypes, arguments),
      };

      try {
        // call original method
        const returnValue = hookEntry.javaMethod.apply(this, arguments);
        // event.returnValue = decodeArguments([returnType], [returnValue]);
        send(event);
        return returnValue;
      } catch (e) {
        // event.exception = e.toString();
        send(event);
        throw e;
      }
    };
  });
}

export class JavaHookRunner implements HookRunner {
  executeHooking(hooks: JavaHook[]): void {
    var javaHookEntryArray: JavaHookEntry[] = [];

    frooky.log.info(`Executing Android hook operations`);

    hooks.forEach((h: JavaHook) => {
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!
      // TODO: JUMP to legacy code
      // Needs to be refactored later
      // Also, the naming is pretty confusing, should be refactored later
      // We should use the validators for the result set, just like with config and hook validations
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

      javaHookEntryArray.push(...buildHookOperations(h));
    });
    frooky.log.info(`Hook operations for the following hook built: ${JSON.stringify(javaHookEntryArray, null, 2)}`);
    frooky.log.info(`Run Android hooking`);
    registerHook(javaHookEntryArray);
  }
}
