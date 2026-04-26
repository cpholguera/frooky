export type DecodedValue = {
  // type of the decoded value
  type: string;
  // optional name, usually from the frooky declaration
  name?: string;
  // error in case the value could not be decoded
  error?: Error;
  value?: unknown;
};
