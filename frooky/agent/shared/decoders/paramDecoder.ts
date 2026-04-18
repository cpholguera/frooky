// argument
export type DecodedValue = {
	name?: string;
	type?: string;
	value: unknown;
};

export interface ParamDecoder {
	decode: (input: unknown, args?: DecodedValue[]) => unknown;
}
