/**
 * Represents the result of a decode operation.
 */
export type DecodedValue = {
  /** The resolved type name of the decoded value. */
  type: string;
  /** The decoded value; absent if decoding failed. */
  value: unknown;
};
