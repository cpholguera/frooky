import type { JavaHook } from "frooky";
import { buildHookOperations } from "../legacy/android-agent"
import type { HookOperation, HookRunner, OperationBuilderResult } from "../../shared/hook/HookRunner"


export interface JavaHookOperation extends HookOperation {
    class: string;
    method: any;        // Todo needs to be refactored when legacy code is refactored
    overloadIndex: number;
    args: string[];
}



export class JavaHookRunner implements HookRunner {

  operationsBuilder(hooks: JavaHook[]): OperationBuilderResult[] {
    var OperationBuilderResultArray: OperationBuilderResult[] = [];
    hooks.forEach((h: JavaHook) => {
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!! 
      // TODO: JUMP to legacy code
      // Needs to be refactored later
      // Also, the naming is pretty confusing, should be refactored later
      // We should use the validators for the result set, just like with config and hook validations
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      OperationBuilderResultArray.push(buildHookOperations(h))
    })

    frooky.log.info(`Hook operations for the following hooks built: ${JSON.stringify(OperationBuilderResultArray)}`)

    return OperationBuilderResultArray;
  }

  executeHooking(operations: HookOperation[]): void {
    throw new Error("Method not implemented.");
  }

} 