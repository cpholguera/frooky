import type {
	ParamDefinition,
	ParamName,
	ParamOptions,
	ParamType,
} from "../hook/parameter";

/**
 * Extended parameter type for YAML input parsing.
 *
 * The following examples all describe the same parameter:
 *
 * 1. As a simple type.
 * 2. As a tuple of [type, options].
 * 3. As a tuple of [type, name, options].
 * 4. As a structured object with type, name, and options.
 *
 * @example "java.lang.String"
 * @example ["java.lang.String", { decodeAt: "exit" }]
 * @example ["java.lang.String", "value", { decodeAt: "exit" }]
 * @example { type: "java.lang.String", name: "value", options: { decodeAt: "exit" } }
 *
 * @public
 */
export type ParamInput =
	| ParamType
	| ParamDefinition
	| [ParamType, ParamName]
	| [ParamType, ParamOptions]
	| [ParamType, ParamName, ParamOptions];

export function normalizeParam(input: ParamInput): ParamDefinition {
	if (typeof input === "string") {
		return { type: input };
	}

	// Check array before plain object, since arrays are also objects
	if (Array.isArray(input)) {
		const [first, second, third] = input;

		if (input.length === 3) {
			return {
				type: first,
				name: second as string,
				options: third as ParamOptions,
			};
		}

		if (typeof second === "object") {
			return { type: first, options: second };
		}

		return { type: first, name: second };
	}

	return input as ParamDefinition;
}
