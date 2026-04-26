// stub, implements shared hook resolver functions
import type { Hook, HookMetadata, HookSettings } from "frooky";

// Hook Operation
// Contains all information to hook one method or function
export interface HookOp {
  settings: HookSettings;
  metadata?: HookMetadata;
  module?: string;
  moduleAddress?: NativePointer;
}

export interface HookRunner {
  executeHooking(hooks: Hook[]): void;
}
