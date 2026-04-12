// stub, implements shared hook resolver functions
import type { Hook } from "frooky";

// Hook Operation
// Contains all information to hook one method or function
export interface HookOp {
  module?: string;
  moduleAddress?: NativePointer;
}

export abstract class HookRunner {
  abstract executeHooking(hooks: Hook[]): void;
}
