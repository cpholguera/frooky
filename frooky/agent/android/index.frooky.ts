// This file is used when the agent is run by frooky. Hooks are dynamically loaded using rpc at runtime.

import type { FrookyConfig } from 'frooky';
import { FrookyApp } from 'android/Frooky';

rpc.exports = {
  runFrookyAgent(frookyConfig: FrookyConfig) {
    globalThis.frooky = new FrookyApp("Android", true);
    frooky.addFrookyConfig(frookyConfig);
    frooky.run(); 
  }
};
