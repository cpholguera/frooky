import type { NativeHook } from "frooky";
import { Pointer } from "frida-gum";
import type { HookOperation, HookRunner, OperationBuilderResult } from "./HookRunner"
import { resolveNativeSymbol } from "android/legacy/android-agent";


export interface NativeHookOperation extends HookOperation {
    module: string
    moduleAddress: Pointer
    symbol: string;              // Todo needs to be refactored when legacy code is refactored
    symbolAddress: Pointer
}



export class NativeHookRunner implements HookRunner {

  operationsBuilder(hooks: NativeHook[]): OperationBuilderResult[] {
    frooky.log.info(`Building hook operations for native`)


    var operationBuilderResultArray: OperationBuilderResult[] = [];
    hooks.forEach((h: NativeHook) => {
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!! 
      // TODO: JUMP to legacy code
      // Needs to be refactored later
      // Also, the naming is pretty confusing, should be refactored later
      // We should use the validators for the result set, just like with config and hook validations
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


      console.log(JSON.stringify(h))


      operationBuilderResultArray.push(resolveNativeSymbol(h))

      
    })

    frooky.log.info(`Hook operations for the following hooks built: ${JSON.stringify(operationBuilderResultArray)}`)

    return operationBuilderResultArray;


  }

  executeHooking(operations: NativeHookOperation[]): void {
    frooky.log.info(`Executing native hook operations`)
  }

} 