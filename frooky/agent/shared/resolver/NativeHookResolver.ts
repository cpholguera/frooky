import type { Hook } from "frooky";
import type { HookResolver } from "./BaseHookResolver"
 
export class NativeHookResolver implements HookResolver  {
    resolve(hook: Hook): void {
        throw new Error("Method not implemented.");
    }
}
