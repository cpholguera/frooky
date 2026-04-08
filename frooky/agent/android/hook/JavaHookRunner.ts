import type { JavaHook } from "frooky";
import { buildHookOperations } from "../legacy/android-agent"
import type { HookOperation, HookRunner, OperationBuilderResult } from "../../shared/hook/HookRunner"


export interface JavaHookOperation extends HookOperation {
    class: string;
    method: any;
    overloadIndex: number;
    args: string[];
}

export class JavaHookRunner implements HookRunner {

  operationsBuilder(hooks: JavaHook[]): OperationBuilderResult {
    var operationsArray: JavaHookOperation = [];
    hooks.forEach((h: JavaHook) => {
      // TODO: JUMP to legacy code
      // Needs to be refactored later
      operationsArray.push(buildHookOperations(h))
    })


    console.log(JSON.stringify(operationsArray))

    return operationsArray;
  }

  executeHooking(operations: HookOperation[]): void {
    throw new Error("Method not implemented.");
  }

} 