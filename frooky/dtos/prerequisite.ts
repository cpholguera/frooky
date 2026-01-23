import {MethodObject} from "./methodObject";

export class Prerequisite {
    class: string;
    private readonly method?: string | MethodObject;
    private readonly methods?: MethodObject[];

    getMethods(): MethodObject[] {
        if (this.method !== undefined) {
            return [typeof this.method === 'string' ? MethodObject.noOverloads(this.method) : this.method];
        }
        if (this.methods !== undefined) {
            return this.methods;
        }
        return [];
    }

}