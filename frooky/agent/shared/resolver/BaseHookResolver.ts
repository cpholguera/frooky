// stub, implements shared hook resolver functions
import type { Hook } from  "frooky";

export interface HookResolver {
  resolve(hook: Hook): void;
}