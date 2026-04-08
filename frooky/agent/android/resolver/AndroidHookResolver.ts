import type { Hook } from "frooky";
import type { HookResolver } from "../../shared/resolver/BaseHookResolver"
 
export class AndroidHookResolver implements HookResolver  {
    resolve(hook: Hook): void {
        throw new Error("Method not implemented.");
    }
}
