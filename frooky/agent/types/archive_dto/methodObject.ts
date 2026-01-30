import {OverloadObject} from "./overloadObject";

type Overload = string | string[] | OverloadObject

export class MethodObject {
    name: string;
    private readonly overload?: Overload;
    private readonly overloads?: Overload[];

    private constructor(name: string, overload?: Overload, overloads?: Overload[]) {
        this.name = name;
        this.overload = overload;
        this.overloads = overloads;
    }

    static noOverloads(name: string): MethodObject {
        return new MethodObject(name);
    }

    static withOverload(name: string, overload: Overload): MethodObject {
        return new MethodObject(name, overload);
    }

    static withOverloads(name: string, overloads: Overload[]): MethodObject {
        return new MethodObject(name, undefined, overloads);
    }

    getOverloads(): OverloadObject[] | undefined {
        if (this.overload !== undefined) {
            return [this.normalizeOverload(this.overload)];
        }

        if (this.overloads !== undefined) {
            return this.overloads.map(it =>
                this.normalizeOverload(it)
            );
        }

        return undefined;
    }

    private normalizeOverload(overload: Overload): OverloadObject {
        if (typeof this.overload === 'string') {
            return OverloadObject.fromParam(this.overload);
        } else if (Array.isArray(this.overload)) {
            return OverloadObject.fromParams(this.overload);
        } else {
            return this.overload;
        }
    }

}