import Java from "frida-java-bridge";
import type { JavaOverload, NativeFunction, NativeHook } from "frooky";
import { DEFAULT_STACK_TRACE_LIMIT } from "../../shared/config.js";
import type { NativeHookOp } from "../../shared/hook/nativeHookRunner.js";
import { uuidv4 } from "../../shared/utils.js";

// /**
//  * Checks if a hook definition is for a native function.
//  * @param {object} hook - Hook definition object.
//  * @returns {boolean} True if the hook targets a native function.
//  */
// function isNativeHook(hook) {
//   return hook.native === true;
// }

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

export function registerNativeHooks(hookEntries: NativeHookOp[]) {
  hookEntries.forEach((hookEntry: NativeHookOp) => {
    registerNativeHook(hookEntry, "FROOKY");
  });
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
//////// Does not decode any arguments
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
export function registerNativeHook(hookEntry: NativeHookOp, category: string = "FROOKY") {
  // let maxFrames = typeof hook.maxFrames === 'number' ? hook.maxFrames : 8;
  const maxFrames = 10;

  Interceptor.attach(hookEntry.symbolAddress, {
    onEnter: function (args) {
      // Capture full native stack first (no truncation yet)
      const fullNativeStack = [];
      try {
        const btFull = Thread.backtrace(this.context, Backtracer.FUZZY);
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
          const Exception = Java.use("java.lang.Exception");
          const stJavaFull = Exception.$new().getStackTrace();
          const jstFull = [];
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
        const out = [];
        for (let t = 0; t < arr.length && t < maxFrames; t++) out.push(arr[t]);
        return out;
      }
      const effectiveStack = fullJavaStack && fullJavaStack.length ? _truncate(fullJavaStack) : _truncate(fullNativeStack);

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

      const event = {
        id: uuidv4(),
        type: "native-hook",
        category: category,
        time: new Date().toISOString(),
        module: hookEntry.module || "<global>",
        symbol: hookEntry.symbol,
        address: hookEntry.symbolAddress.toString(),
        stackTrace: effectiveStack,
        // inputParameters: decodedArgs
      };

      send(event);
    },
    onLeave: () => {
      // Optionally emit a separate event or extend the onEnter event
      // For now, we just log the return if needed
    },
  });
}
