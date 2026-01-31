// This file is used when the agent is run by frida. Hooks embedded into the agent at build time.

import { runFrookyAgent } from './android-agent.ts'
import { target } from './_hooks.ts';

runFrookyAgent(target);
