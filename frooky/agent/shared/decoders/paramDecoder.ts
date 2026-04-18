// argument
export type Arg = {
	name: string;
	type: string;
	value: unknown;
};

export interface ParamDecoder {
	decode: (input: unknown, args?: Arg[]) => unknown;
}
