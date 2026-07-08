// run-tests.js

import frida from "frida";
import minimist from "minimist";
import fs from "node:fs";

const argv = minimist(process.argv.slice(2), {
  string: ["appIdentifier", "agentPath"],
  boolean: ["help", "usb"],
  alias: {
    i: "appIdentifier",
    p: "agentPath",
    h: "help",
    u: "usb",
  },
});

const help = argv.help;
const usb = argv.usb;
const agentPath = argv.agentPath;
const appIdentifier = Number.isFinite(Number(argv.appIdentifier)) ? Number(argv.appIdentifier) : argv.appIdentifier;

if (help) {
  showHelp();
}

validateInput(argv);

async function runTests() {
  let session;
  let device;
  let pid;
  let wasSpawned = false;

  device = usb ? await frida.getUsbDevice() : await frida.getLocalDevice();

  if (Number.isFinite(appIdentifier)) {
    pid = appIdentifier;
    session = await device.attach(pid);
  } else {
    try {
      pid = await device.spawn(appIdentifier);
      wasSpawned = true;
      session = await device.attach(pid);
    } catch {
      const processes = await device.enumerateProcesses();
      const target =
        processes.find((proc) => proc.name === appIdentifier) ||
        processes.find((proc) => proc.name.toLowerCase() === String(appIdentifier).toLowerCase()) ||
        processes.find((proc) => proc.name.toLowerCase().includes(String(appIdentifier).toLowerCase()));

      if (!target) {
        throw new Error(`Unable to spawn or attach to process using '${appIdentifier}'. If attaching by name, launch the app first.`);
      }

      pid = target.pid;
      session = await device.attach(pid);
    }
  }

  const script = await session.createScript(fs.readFileSync(agentPath, "utf8"));

  let testComplete = false;
  let exitCode = 1;

  script.message.connect((message) => {
    if (message.type === "send") {
      const payload = message.payload;

      if (payload.type === "test-result") {
        const printResult = (result) => {
          const indent = "  ".repeat(result.depth ?? 0);
          if (result.kind === "suite") {
            if (result.passed) {
              console.log(`${indent}${result.name}`);
            } else {
              const error = result.error ? `: ${result.error}` : "";
              console.error(`${indent}❌ ${result.name}${error}`);
            }
          } else {
            if (result.passed) {
              console.log(`${indent}✅ ${result.name}`);
            } else {
              const error = result.error ? `: ${result.error}` : "";
              console.error(`${indent}❌ ${result.name}${error}`);
            }
          }
          for (const child of result.children ?? []) {
            printResult(child);
          }
        };
        printResult(payload.result);
      } else if (payload.type === "test-complete") {
        testComplete = true;

        if (payload.success) {
          console.log("\n✅ All tests passed.");
          exitCode = 0;
        } else {
          console.error("\n❌ Some tests failed.");
          exitCode = 1;
        }
      }
    } else if (message.type === "error") {
      console.error("Script error:", message.stack);
      testComplete = true;
      exitCode = 1;
    }
  });

  await script.load();
  if (wasSpawned) {
    await device.resume(pid);
  }

  const timeout = 30000;
  const startTime = Date.now();

  while (!testComplete && Date.now() - startTime < timeout) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  if (!testComplete) {
    console.error("Tests timed out");
    exitCode = 1;
  }

  await session.detach();
  process.exit(exitCode);
}

runTests().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

function showHelp() {
  console.log(`
    Options:
    -p, --agentPath <name>        Required: Path to the testing framework for Frida (compiled JavaScript)
    -i, --appIdentifier <value>   Required: pid, bundle/package id, or app name
    -u, --usb                     Use USB device mode
    -h, --help                    Show this help message

    Examples: Target is USB device mode:
    node run-tests.js -i org.owasp.mastestapp -u -p test-framework.js
    node run-tests.js -i 4926 -u -p test-framework.js
    node run-tests.js -i MASTestApp -u -p test-framework.js

    Example: Target is local simulator:
    node run-tests.js -i org.owasp.mastestapp.MASTestApp-iOS -p test-framework.js 
    `);
  process.exit(0);
}

function validateInput(argv) {
  if (!argv.appIdentifier) {
    console.error("App Identifier (-i/--appIdentifier) is required");
    process.exit(1);
  }
  if (!argv.agentPath) {
    console.error("Agent path (-p/--agentPath) is required");
    process.exit(1);
  }
}
