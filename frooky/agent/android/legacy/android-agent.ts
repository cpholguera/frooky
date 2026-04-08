import Java from "frida-java-bridge"
import { decodeArgByDescriptor, filtersPass } from "./native_decoder.js"
import { decodeArguments } from "./android-decoder.js"
import { uuidv4 } from "../../shared/utils.js"
import { Hook, JavaHook, JavaOverload, NativeHook } from "frooky";
import { JavaHookOperation, JavaOperationBuilderResult, JavaOperationsResult } from "android/hook/JavaHookRunner.js";
import { OperationBuilderResult } from "shared/hook/HookRunner.js";
import type { NativeSymbol } from "../../types/hook/nativeHook.js"
import { NativeHookOperation } from "shared/hook/NativeHookRunner.js";


/**
 * Decodes the parameter types of a Java method.
 * @param {string} methodHeader - Java method (e.g., `function setBlockModes([Ljava.lang.String;): android.security.keystore.KeyGenParameterSpec$Builder`)
 * @returns {[string]} The decoded parameter types (e.g., "['[Ljava.lang.String;']")
 */
function parseParameterTypes(methodHeader) {
  let regex = /\((.*?)\)/;
  let parameterString = regex.exec(methodHeader)[1];
  if (parameterString === "") {
    return [];
  }
  return parameterString.replace(/ /g, "").split(",");
}

/**
 * Decodes the type of the return value of a Java method.
 * @param {string} methodHeader - Java method (e.g., "function setBlockModes([Ljava.lang.String;): android.security.keystore.KeyGenParameterSpec$Builder")
 * @returns {string} The decoded parameter types (e.g., "android.security.keystore.KeyGenParameterSpec$Builder")
 */
function parseReturnValue(methodHeader) {
  return methodHeader.split(":")[1].trim();
}


/**
 * Checks if a hook definition is for a native function.
 * @param {object} hook - Hook definition object.
 * @returns {boolean} True if the hook targets a native function.
 */
function isNativeHook(hook) {
  return hook.native === true;
}

/**
 * Resolves the address of a native symbol for Interceptor.attach.
 * @param {object} hook - Native hook definition with symbol and optional module.
 * @returns {NativePointer|null} The address of the symbol, or null if not found.
 */
  ////////
  //////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ///////
  ////////
  //////// Works as before, but needs to be refactored later
  ///////
  ////////
  //////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ///////
export function resolveNativeSymbol(hook: NativeHook): JavaOperationsResult {
    const nativeOps: NativeHookOperation[] = [];
    const errors: string[] = [];

  try {

    let mod = Process.getModuleByName(hook.module);

    hook.functions.forEach((s: NativeSymbol) => {

      try {
        if (typeof s === "string") {
          nativeOps.push({
            module: hook.module,
            moduleAddress: mod.base,
            symbol: s,
            symbolAddress: mod.getExportByName(s),
            hook: hook
          });
        } else {
          nativeOps.push({
            module: hook.module,
            moduleAddress: mod.base,
            symbol: s.symbol,
            symbolAddress: mod.getExportByName(s.symbol),
            hook: hook
          });
        }
      } catch (e) {
        errors.push(e as string)
        console.error("Failed to resolve native symbol '" + s + "'" +
          (hook.module ? " in module '" + hook.module + "'" : "") + ": " + e);
      }

    });

  } catch (e) {
    console.error("Failed to get module '" + hook.module + "': " + e);
  }


  return {
      operations: nativeOps,
      count: nativeOps.length,
      errors,
      errorCount: errors.length,
  }
}


/**
 * Registers a native function hook using Frida's Interceptor API.
 * @param {object} hook - Native hook definition.
 * @param {string} categoryName - OWASP MAS category for identification.
 */
  ////////
  //////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ///////
  ////////
  //////// Works as before, but needs to be refactored later
  ///////
  //////// type
      // export interface NativeHookOperation extends HookOperation {
      //     module: string
      //     moduleAddress: Pointer
      //     symbol: string;              // Todo needs to be refactored when legacy code is refactored
      //     symbolAddress: Pointer
      // }
  //////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ///////
export function registerNativeHook(hookOp: NativeHookOperation, category: string = "FROOKY") {
    // let maxFrames = typeof hook.maxFrames === 'number' ? hook.maxFrames : 8;
    let maxFrames = 10;

    Interceptor.attach(hookOp.symbolAddress, { 
      onEnter: function (args) {
        // Capture full native stack first (no truncation yet)
        let fullNativeStack = [];
        try {
          let btFull = Thread.backtrace(this.context, Backtracer.FUZZY);
          for (let i = 0; i < btFull.length; i++) {
            try {
              fullNativeStack.push(DebugSymbol.fromAddress(btFull[i]).toString());
            } catch (e2) {
              fullNativeStack.push(btFull[i].toString());
            }
          }
        } catch (e) {
          fullNativeStack.push("<backtrace unavailable: " + e + ">");
        }

        // Capture full Java stack (no truncation yet)
        let fullJavaStack = null;
        if (Java.available) {
          try {
            let Exception = Java.use("java.lang.Exception");
            let stJavaFull = Exception.$new().getStackTrace();
            let jstFull = [];
            for (let j = 0; j < stJavaFull.length; j++) {
              jstFull.push(stJavaFull[j].toString());
            }
            fullJavaStack = jstFull;
          } catch (je) {
            // ignore
          }
        }

        // Filtering uses full stacks before truncation
        // if (hook.filterEventsByStacktrace) {
        //   let combinedFull = (fullJavaStack && fullJavaStack.length ? fullJavaStack : fullNativeStack);
        //   let needle = hook.filterEventsByStacktrace;
        //   let found = false;
        //   for (let k = 0; k < combinedFull.length; k++) {
        //     if (combinedFull[k].indexOf(needle) !== -1) { found = true; break; }
        //   }
        //   if (!found) {
        //     return; // suppress event
        //   }
        // }

        // Apply maxFrames truncation only for emission. If filtering was used, emit full stack to ensure visibility of matching frame.
        function _truncate(arr) {
          // if (hook.filterEventsByStacktrace) return arr.slice();
          if (maxFrames === -1) return arr.slice();
          let out = [];
          for (let t = 0; t < arr.length && t < maxFrames; t++) out.push(arr[t]);
          return out;
        }
        let effectiveStack = fullJavaStack && fullJavaStack.length ? _truncate(fullJavaStack) : _truncate(fullNativeStack);

        // // Decode native args: if descriptors provided, decode only those; else auto decode up to 5
        // let decodedArgs = [];
        // try {
        //   let descriptors = Array.isArray(hook.args) ? hook.args : [];
        //   if (descriptors.length > 0) {
        //     for (let ai = 0; ai < descriptors.length; ai++) {
        //       let p = args[ai];
        //       if (p === undefined) break;
        //       decodedArgs.push(decodeArgByDescriptor(p, ai, descriptors[ai]));
        //     }
        //   } else {
        //     // Auto mode
        //     let autoCount = 5;
        //     for (let aj = 0; aj < autoCount; aj++) {
        //       let p2 = args[aj];
        //       if (p2 === undefined) break;
        //       let fallbackVal = null;
        //       try {
        //         try { fallbackVal = p2.readCString(); } catch (e1) {
        //           try { fallbackVal = p2.toInt32(); } catch (e2) {
        //             try { let bufF = Memory.readByteArray(p2, 64); fallbackVal = bufF ? _arrayBufferToHex(bufF) : p2.toString(); } catch (e3) { fallbackVal = p2.toString(); }
        //           }
        //         }
        //       } catch (eF) { fallbackVal = "<error: " + eF + ">"; }
        //       decodedArgs.push({ name: "args[" + aj + "]", type: "auto", value: fallbackVal });
        //     }
        //   }
        // } catch (eDec) {
        //   decodedArgs = [{ name: "args", type: "auto", value: "<arg-decode-error: " + eDec + ">" }];
        // }

        // // Apply per-arg filters (if present) before emitting
        // try {
        //   let descriptors2 = Array.isArray(hook.args) ? hook.args : [];
        //   if (!filtersPass(decodedArgs, descriptors2)) {
        //     if (hook.debug === true) {
        //       send({ type: 'native-filter-suppressed', symbol: hook.symbol, args: decodedArgs });
        //     }
        //     return; // suppress event when filters don't match
        //   }
        // } catch (eFilt) {
        //   // If filtering fails, default to emitting
        // }

        let event = {
          id: uuidv4(),
          type: "native-hook",
          category: category,
          time: new Date().toISOString(),
          module: hookOp.module || "<global>",
          symbol: hookOp.symbol,
          address: hookOp.symbolAddress.toString(),
          stackTrace: effectiveStack,
          // inputParameters: decodedArgs
        };

        send(event);
      },
      onLeave: function (retval) {
        // Optionally emit a separate event or extend the onEnter event
        // For now, we just log the return if needed
      }
    });
  }


  /**
   * Overloads a method. If the method is called, the parameters and the return value are decoded and together with a stack trace send back to the frida.re client.
   * @param {string} clazz - Java class (e.g., "android.security.keystore.KeyGenParameterSpec$Builder").
   * @param {string} method - Name of the method which should be overloaded (e.g., "setBlockModes").
   * @param {number} overloadIndex - If there are overloaded methods available, this number represents them (e.g., 0 for the first one)
   * @param {string} categoryName - OWASP MAS category for easier identification (e.g., "CRYPTO")
   * @param {number} maxFrames - Maximum number of stack frames to capture (default is 8, set to -1 for unlimited frames).
   */
    ////////
  //////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ///////
  ////////
  //////// Works as before, but needs to be refactored later
  ///////
  ////////
  //////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ///////
  export function registerHook(hookOps: JavaHookOperation) {

    let Exception = Java.use("java.lang.Exception");
    let System = Java.use('java.lang.System');

    let toHook;
    if (typeof hookOps.method === "string"){
      toHook = Java.use(hookOps.class)[hookOps.method];
    } else {
      toHook = Java.use(hookOps.class)[hookOps.method.name];
    }


    let methodHeader = toHook.overloads[hookOps.overloadIndex].toString();

    toHook.overloads[hookOps.overloadIndex].implementation = function () {

      let st = Exception.$new().getStackTrace();
      let stackTrace = [];
      st.forEach((stElement, index) => {
        if (hookOps.maxFrames === -1 || index < hookOps.maxFrames) {
          let stLine = stElement.toString();
          stackTrace.push(stLine);
        }
      });

      let parameterTypes = parseParameterTypes(methodHeader);
      let returnType = parseReturnValue(methodHeader);

      let instanceId;
      if (this && this.$className && typeof this.$h === 'undefined') {
        instanceId = 'static';
      } else {
        // call Java’s identityHashCode on the real object
        try {
          instanceId = System.identityHashCode(this);
        } catch (e) {
          console.error("Error in identityHashCode", e)
          instanceId = "error"
        }
      }

      const event = {
        id: uuidv4(),
        type: "hook",
        // category: categoryName,
        time: new Date().toISOString(),
        class: hookOps.class,
        method: hookOps.class,
        instanceId: instanceId,
        stackTrace: stackTrace,
        inputParameters: decodeArguments(parameterTypes, arguments),
      };

      try {
        let returnValue = this[hookOps.method].apply(this, arguments);
        event.returnValue = decodeArguments([returnType], [returnValue]);
        send(event)
        return returnValue;
      } catch (e) {
        event.exception = e.toString();
        send(event)
        throw e;
      }
    };
  }

  /**
   * Finds the overload index that matches the given argument types.
   * @param {Object} methodHandle - Frida method handle with overloads.
   * @param {string[]} argTypes - Array of argument type strings (e.g., ["android.net.Uri", "android.content.ContentValues"]).
   * @returns {number} The index of the matching overload, or -1 if not found.
   */
  function findOverloadIndex(methodHandle, argTypes) {
    for (let i = 0; i < methodHandle.overloads.length; i++) {
      let overload = methodHandle.overloads[i];
      let parameterTypes = parseParameterTypes(overload.toString());

      if (parameterTypes.length !== argTypes.length) {
        continue;
      }

      let match = true;
      for (let j = 0; j < argTypes.length; j++) {
        if (parameterTypes[j] !== argTypes[j]) {
          match = false;
          break;
        }
      }

      if (match) {
        return i;
      }
    }
    return -1;
  }

  /**
   * Builds a normalized list of hook operations for a single hook definition.
   * Each operation contains clazz, method, overloadIndex, and args array (decoded parameter types).
   * This centralizes selection logic used for both summary emission and hook registration.
   *
   * The function supports several hook configuration scenarios:
   * - If both `methods` and `overloads` are specified, the configuration is considered invalid and no operations are returned.
   * - If a single `method` and an explicit list of `overloads` are provided, only those overloads are considered.
   * - If only `methods` is provided, all overloads for each method are included.
   * - If only `method` is provided, all overloads for that method are included.
   * - If neither is provided, or if the configuration is invalid, no operations are returned.
   *
   * Error handling:
   * - If an explicit overload is not found, it is skipped and not included in the operations.
   * - If an exception occurs during processing, it is logged and the function returns the operations collected so far.
   *
   * @param {object} hook - Hook definition object. Supported formats:
   *   - { class: string, method: string }
   *   - { class: string, methods: string[] }
   *   - { class: string, method: string, overloads: Array<{ args: string[] }> }
   * @returns {{operations: Array<{clazz:string, method:string, overloadIndex:number, args:string[]}>, count:number}}
   *
   * @example
   * // Hook all overloads of a single method
   * buildHookOperations({ class: "android.net.Uri", method: "parse" });
   *
   * @example
   * // Hook all overloads of multiple methods
   * buildHookOperations({ class: "android.net.Uri", methods: ["parse", "toString"] });
   *
   * @example
   * // Hook specific overloads of a method
   * buildHookOperations({
   *   class: "android.net.Uri",
   *   method: "parse",
   *   overloads: [
   *     { args: ["java.lang.String"] },
   *     { args: ["android.net.Uri"] }
   *   ]
   * });
   *
   * @example
   * // Invalid configuration: both methods and overloads
   * buildHookOperations({
   *   class: "android.net.Uri",
   *   methods: ["parse"],
   *   overloads: [{ args: ["java.lang.String"] }]
   * });
   * // Returns { operations: [], count: 0 }
   */


  ////////
  //////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ///////
  ////////
  //////// Works as before, but needs to be refactored later
  ///////
  ////////
  //////// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ///////
export function buildHookOperations(hook: JavaHook): JavaOperationsResult {
  const operations: JavaHookOperation[] = [];
  const errors: string[] = [];

  const buildResult = (): JavaOperationsResult => ({
    operations,
    count: operations.length,
    errors,
    errorCount: errors.length,
  });

  try {
    if (!hook.methods) {
      return buildResult();
    }

    for (const javaMethod of hook.methods) {

      // single method string: overload everything
      if (typeof javaMethod === 'string') {
        try {
          const handle = Java.use(hook.javaClass)[javaMethod];

          for (let j = 0; j < handle.overloads.length; j++) {
            const paramsEach = parseParameterTypes(handle.overloads[j].toString());

            operations.push({
              hook,
              class: hook.javaClass,
              method: javaMethod,
              overloadIndex: j,
              args: paramsEach,
              maxFrames: 10,
            });
          }
        } catch (e) {
          const errMsg = `Failed to process method '${javaMethod}' in class '${hook.javaClass}': ${e}`;
          console.warn(`Warning: ${errMsg}`);
          errors.push(errMsg);
        }

      } else {

        // named method with explicit overloads
        let handle;
        try {
          handle = Java.use(hook.javaClass)[javaMethod.name];
        } catch (e) {
          const errMsg = `Failed to resolve method '${javaMethod.name}' in class '${hook.javaClass}': ${e}`;
          console.warn(`Warning: ${errMsg}`);
          errors.push(errMsg);
          continue;
        }

        javaMethod.overloads?.forEach((o: JavaOverload) => {
          try {
            const argsExplicit: string[] = Array.isArray(o.params)
              ? o.params.map((p) => (Array.isArray(p) ? p[0] as string : p as string))
              : [];

            const idx = findOverloadIndex(handle, argsExplicit);

            if (idx !== -1) {
              const params = parseParameterTypes(handle.overloads[idx].toString());

              operations.push({
                hook,
                class: hook.javaClass,
                method: javaMethod.name,
                overloadIndex: idx,
                args: params,
                maxFrames: 10,
              });
            } else {
              const errMsg = `Overload not found for ${hook.javaClass}:${javaMethod.name} with args [${argsExplicit.join(", ")}]`;
              console.warn(`[frida-android] Warning: ${errMsg}. This hook will be skipped.`);
              errors.push(errMsg);
            }
          } catch (e) {
            const errMsg = `Failed to process overload of '${javaMethod.name}' in class '${hook.javaClass}': ${e}`;
            console.warn(`Warning: ${errMsg}`);
            errors.push(errMsg);
          }
        });
      }
    }
  } catch (e) {
    const errMsg = `Error in buildHookOperations for hook: ${hook?.javaClass ?? "<unknown>"}: ${e}`;
    console.error(errMsg);
    errors.push(errMsg);
  }

  return buildResult();
}



  // /**
  //  * Takes an array of objects usually defined in the `hooks.js` file of a DEMO and loads all classes and functions stated in there.
  //  * @param {[object]} hook - Contains a list of objects which contains all methods which will be overloaded.
  //  *   Basic format: {class: "android.security.keystore.KeyGenParameterSpec$Builder", methods: ["setBlockModes"]}
  //  *   With overloads: {class: "android.content.ContentResolver", method: "insert", overloads: [{args: ["android.net.Uri", "android.content.ContentValues"]}]}
  //  * @param {string} categoryName - OWASP MAS category for easier identification (e.g., "CRYPTO")
  //  * @param {{operations: Array<{clazz:string, method:string, overloadIndex:number, args:string[]}>, count:number}} [cachedOperations] - Optional pre-computed hook operations to avoid redundant processing.
  //  */
  // function registerAllHooks(hook, categoryName, cachedOperations) {
  //   if (hook.methods && hook.overloads && hook.overloads.length > 0) {
  //     console.error(`Invalid hook configuration for ${hook.class}: 'overloads' is only supported with a singular 'method', not with 'methods'.`);
  //     return;
  //   }
  //   let built = cachedOperations || buildHookOperations(hook);
  //   built.operations.forEach((op) => {
  //     try {
  //       registerHook(op.clazz, op.method, op.overloadIndex, categoryName, hook.maxFrames);
  //     } catch (err) {
  //       console.error(err);
  //       console.error(`Problem when overloading ${op.clazz}:${op.method}#${op.overloadIndex}`);
  //     }
  //   });
  // }

  export function runFrookyAgent(target) {
    // // Main execution: separate native hooks from Java hooks
    // // Separate hooks into native and Java categories
    // let nativeHooks = [];
    // let javaHooks = [];
    // target.hooks.forEach((hook) => {
    //   if (isNativeHook(hook)) {
    //     nativeHooks.push(hook);
    //   } else {
    //     javaHooks.push(hook);
    //   }
    // });

    // // Prepare native summary upfront without attaching hooks yet
    // let nativeHooksSummary = [];
    // let nativeErrors = [];
    // nativeHooks.forEach((hook) => {
    //   try {
    //     // Attempt to resolve symbol to surface errors early, but do not attach
    //     let addr = resolveNativeSymbol(hook);
    //     if (!addr) {
    //       nativeErrors.push("Failed to resolve native symbol '" + hook.symbol + "'" + (hook.module ? " in module '" + hook.module + "'" : ""));
    //     }
    //     nativeHooksSummary.push({
    //       module: hook.module || "<global>",
    //       symbol: hook.symbol
    //     });
    //   } catch (e) {
    //     let errMsg = "Failed to resolve native hook for symbol '" + hook.symbol + "': " + e;
    //     console.error(errMsg);
    //     nativeErrors.push(errMsg);
    //   }
    // });

    // Register hooks inside Java.perform, but only after emitting both summaries
    // Enter Java.perform to allow Java stack augmentation (even if only native hooks)
    Java.perform(() => {
      const delay = 1000

      setTimeout(() => {
        // // Pre-compute hook operations once to avoid redundant processing
        // let hookOperationsCache = [];
        // javaHooks.forEach((hook) => {
        //   hookOperationsCache.push({
        //     hook: hook,
        //     built: buildHookOperations(hook)
        //   });
        // });

        // 1) Emit native summary
        if (nativeHooks.length > 0) {
          let nativeSummary = {
            type: "native-summary",
            hooks: nativeHooksSummary,
            totalHooks: nativeHooksSummary.length,
            errors: nativeErrors,
            totalErrors: nativeErrors.length
          };
          send(nativeSummary);
        }

        // // 2) Emit an initial summary of all overloads that will be hooked
        // try {
        //   // Aggregate map nested by class then method
        //   let aggregate = {};
        //   let totalHooks = 0;
        //   let errors = [];
        //   let totalErrors = 0;
        //   hookOperationsCache.forEach((cached) => {
        //     totalHooks += cached.built.count;
        //     if (cached.built.errors && cached.built.errors.length) {
        //       Array.prototype.push.apply(errors, cached.built.errors);
        //       totalErrors += cached.built.errors.length;
        //     }
        //     cached.built.operations.forEach((op) => {
        //       if (!aggregate[op.clazz]) {
        //         aggregate[op.clazz] = {};
        //       }
        //       if (!aggregate[op.clazz][op.method]) {
        //         aggregate[op.clazz][op.method] = [];
        //       }
        //       aggregate[op.clazz][op.method].push(op.args);
        //     });
        //   });

        //   let hooks = [];
        //   for (let clazz in aggregate) {
        //     if (!aggregate.hasOwnProperty(clazz)) continue;
        //     let methodsMap = aggregate[clazz];
        //     for (let methodName in methodsMap) {
        //       if (!methodsMap.hasOwnProperty(methodName)) continue;
        //       let entries = methodsMap[methodName].map(function (argsArr) {
        //         return { args: argsArr };
        //       });
        //       hooks.push({ class: clazz, method: methodName, overloads: entries });
        //     }
        //   }

        //   let summary = { type: "summary", hooks: hooks, totalHooks: totalHooks, errors: errors, totalErrors: totalErrors };
        //   send(summary);
        // } catch (e) {
        //   // If summary fails, don't block hooking
        //   console.error("Summary generation failed, but hooking will continue. Error:", e);
        // }

        // 3) Now that both summaries were emitted, attach native hooks
        if (nativeHooks.length > 0) {
          nativeHooks.forEach((hook) => {
            try {
              registerNativeHook(hook, target.category);
            } catch (e) {
              console.error("Failed to register native hook after summary for symbol '" + hook.symbol + "': " + e);
            }
          });
        }

        // 4) Register Java hooks using cached operations
        // hookOperationsCache.forEach((cached) => {
        //   registerAllHooks(cached.hook, target.category, cached.built);
        // });
      }, delay);
    });
  };