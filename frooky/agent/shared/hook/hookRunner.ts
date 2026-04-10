// stub, implements shared hook resolver functions
import type { Hook } from "frooky";

export interface HookEntry {
  module?: string;
  moduleAddress?: NativePointer;
}

export abstract class HookRunner {
  abstract executeHooking(hooks: Hook[]): void;
}
