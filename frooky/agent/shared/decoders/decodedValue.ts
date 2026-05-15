/**
 * Represents the result of a decode operation.
 */
export type DecodedValue = {
  /** The resolved type of the decoded value. */
  type: string;
  /** The name of the decoded value. */
  name?: string;
  /** The decoded value; absent if decoding failed. */
  value: unknown;
};
