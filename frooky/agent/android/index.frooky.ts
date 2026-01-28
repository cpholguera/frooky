// This file is used when the agent is run by frooky. Hooks are dynamically loaded using rpc at runtime.

import { runFrookyAgent } from './android-agent.ts'

rpc.exports = {
  runFrookyAgent(target: any) {
    runFrookyAgent(target)
  }
};
