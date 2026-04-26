/**
 * Represents the result of a decode operation.
 */
export type DecodedValue = {
  /** The resolved type name of the decoded value. */
  type: string;
  /** Parameter name, typically sourced from the frooky hook declaration. */
  name?: string;
  /** Populated when decoding fails. */
  error?: Error;
  /** The decoded value; absent if decoding failed. */
  value?: unknown;
};
