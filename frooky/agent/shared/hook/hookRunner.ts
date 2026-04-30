// stub, implements shared hook resolver functions
import type { Hook, HookSettings } from "frooky";
import type { DecoderSettings } from "../decoders/decoderSettings";

// Hook Operation
// Contains all information to hook one method or function
export interface HookOp {
  hookSettings: HookSettings;
  decoderSettings: DecoderSettings;
  module?: string;
  moduleAddress?: NativePointer;
}

export interface HookRunner {
  executeHooking(hooks: Hook[]): Promise<void>;
}
