export class OverloadObject {
    private readonly param?: string;
    private readonly params?: string[];

    private constructor(param?: string, params?: string[]) {
        this.param = param;
        this.params = params;
    }

    static fromParam(param: string): OverloadObject {
        return new OverloadObject(param, undefined);
    }

    static fromParams(params: string[]): OverloadObject {
        return new OverloadObject(undefined, params);
    }

    getParams(): string[] | undefined {
        return this.params ?? (this.param ? [this.param] : undefined);
    }
}