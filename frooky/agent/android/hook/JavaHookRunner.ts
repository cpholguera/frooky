import type { JavaHook } from "frooky";
import { buildHookOperations, registerHook } from "../legacy/android-agent"
import type { HookOperation, HookRunner, OperationBuilderResult } from "../../shared/hook/HookRunner"


export interface JavaHookOperation extends HookOperation {
  hook: JavaHook
  class: string,
  method: any,        // Todo needs to be refactored when legacy code is refactored
  overloadIndex: number,
  args: string[],
  maxFrames: number,
}



export class JavaHookRunner implements HookRunner {

  operationsBuilder(hooks: JavaHook[]): OperationBuilderResult[] {
    frooky.log.info(`Building hook operations for Android`)

    var operationBuilderResultArray: OperationBuilderResult[] = [];
    hooks.forEach((h: JavaHook) => {
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!! 
      // TODO: JUMP to legacy code
      // Needs to be refactored later
      // Also, the naming is pretty confusing, should be refactored later
      // We should use the validators for the result set, just like with config and hook validations
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      operationBuilderResultArray.push(buildHookOperations(h))
    })

    frooky.log.info(`Android hook operations for the following hooks built: ${JSON.stringify(operationBuilderResultArray)}`)

    return operationBuilderResultArray;
  }

  executeHooking(hookOps: JavaHookOperation[]): void {
    frooky.log.info(`Executing Android hook operations`)
    hookOps.forEach((hookOp: JavaHookOperation) => {
      registerHook(hookOp)
    })
  }


} 