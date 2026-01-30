import {MethodObject} from "./methodObject";
import {Prerequisite} from "./prerequisite";

class Hook {
    class: string;
    private readonly method?: string | MethodObject;
    private readonly methods?: MethodObject[];
    private readonly prerequisite?: Prerequisite;
    private readonly prerequisites?: Prerequisite[];

    getMethods(): MethodObject[] {
        if (this.method !== undefined) {
            return [typeof this.method === 'string' ? MethodObject.noOverloads(this.method) : this.method];
        }
        if (this.methods !== undefined) {
            return this.methods;
        }
        return [];
    }

    getPrerequisites(): Prerequisite[] {
        return this.prerequisites ?? [this.prerequisite];
    }
}