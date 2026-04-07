// This file is used when the agent is run by frooky. Hooks are dynamically loaded using rpc at runtime.

import type { FrookyConfig } from 'frooky';
import { FrookyApp } from "../FrookyApp";

rpc.exports = {
  runFrookyAgent(frookyConfig: FrookyConfig) {
    globalThis.frooky = new FrookyApp("Android");
    frooky.addFrookyConfig(frookyConfig);
    frooky.run(); 
  }
};
