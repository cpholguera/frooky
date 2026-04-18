import { Arg, ParamDecoder } from "./paramDecoder";

export class NullDecoder implements ParamDecoder {
    decode(input: unknown, args?: Arg[]): unknown {
        return "No decoder has been implemented for this parameter type";
    }
}