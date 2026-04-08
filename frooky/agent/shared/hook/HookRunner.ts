// stub, implements shared hook resolver functions
import type { Hook } from  "frooky";

export interface HookOperation {
  hook: Hook; 
}

export interface OperationBuilderResult {
  operations: HookOperation[];
  count: number;
  errors: string[]; 
  errorCount: number;
}


export abstract class HookRunner {
  abstract operationsBuilder(hooks: Hook[]): OperationBuilderResult;
  abstract executeHooking(operations: HookOperation[]): void;
}