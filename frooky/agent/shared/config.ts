export const DEFAULT_DECODER_SETTINGS = {
  fastDecode: false,
  magicDecode: false,
  maxRecursion: 5,
  decodeLimit: 1000,
};

export const DEFAULT_HOOK_SETTINGS = {
  stackTraceLimit: 10,
  eventFilter: [],
  decoderSettings: DEFAULT_DECODER_SETTINGS,
};

// specifies the interval between cached events are send back to the host
export const SEND_INTERVAL = 100;
