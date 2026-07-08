/**
 * Represents the result of a decoded value.
 */
export interface DecodedValue {
  /** The declared type of the decoded value. */
  type: string;
  /** The name of the decoded value. */
  name?: string;
  /** The decoded value. Can be nested */
  value: any;
}
