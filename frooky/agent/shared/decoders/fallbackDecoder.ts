import type { Arg, ParamDecoder } from "./paramDecoder";

export class FallbackDecoder implements ParamDecoder {
	decode(input: unknown, args?: Arg[]): unknown {
		return "No decoder has been implemented for this parameter type";
	}
}
