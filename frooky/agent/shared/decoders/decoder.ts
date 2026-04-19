// decoded values
export type DecodedValue = {
  name?: string;
  type?: string;
  error?: Error;
  value: unknown;
};

export type Decoder = {
  decode: (...args: any[]) => DecodedValue;
};
