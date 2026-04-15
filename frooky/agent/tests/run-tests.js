// run-tests.js

import fs from "node:fs";
import frida from "frida";
import minimist from "minimist";

const argv = minimist(process.argv.slice(2), {
  string: ["appIdentifier", "agentPath", "out"],
  boolean: ["help", "usb"],
  alias: {
    i: "appIdentifier",
    p: "agentPath",
    h: "help",
    u: "usb",
    o: "out",
  },
});

const out = argv.out;
const help = argv.help;
const usb = argv.usb;
const agentPath = argv.agentPath;
const appIdentifier = Number.isFinite(Number(argv.appIdentifier)) ? Number(argv.appIdentifier) : argv.appIdentifier;

if (help) {
  showHelp();
}

validateInput(argv);

const result = {
  _write(line) {
    if (out) {
      fs.appendFileSync(out, line + "\n", "utf8");
    }
  },
  log(...args) {
    const line = args.join(" ");
    console.log(line);
    this._write(line);
  },
  error(...args) {
    const line = args.join(" ");
    console.error(line);
    this._write(line);
  },
};

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
        const printResult = (res) => {
          const indent = "  ".repeat(res.depth ?? 0);
          if (res.passed) {
            result.log(`${indent}✅ PASS: ${res.name}`);
          } else {
            const error = res.error ? `: ${res.error}` : "";
            result.log(`${indent}❌ FAIL: ${res.name}${error}`);
          }
          for (const child of res.children ?? []) {
            printResult(child);
          }
        };
        printResult(payload.result);
      } else if (payload.type === "test-complete") {
        testComplete = true;

        if (payload.success) {
          result.log("\n✅ PASS: All tests passed.");
          exitCode = 0;
        } else {
          result.log("\n❌ FAIL: Some tests failed.");
          exitCode = 1;
        }
      }
    } else if (message.type === "error") {
      result.error("Script error:", message.stack);
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
    result.error("Tests timed out");
    exitCode = 1;
  }

  await session.detach();
  process.exit(exitCode);
}

runTests().catch((err) => {
  result.error("Fatal error:", err);
  process.exit(1);
});

function showHelp() {
  console.log(`
    Options:
    -p, --agentPath <name>        Required: Path to the testing framework for Frida (compiled JavaScript)
    -i, --appIdentifier <value>   Required: pid, bundle/package id, or app name
    -u, --usb                     Use USB device mode
    -o, --out <file>              Optional: path to output file for results
    -h, --help                    Show this help message

    Examples: Target is USB device mode:
    node run-tests.js -i org.owasp.mastestapp -u -p test-framework.js
    node run-tests.js -i 4926 -u -p test-framework.js
    node run-tests.js -i MASTestApp -u -p test-framework.js

    Example: Target is local simulator:
    node run-tests.js -i org.owasp.mastestapp.MASTestApp-iOS -p test-framework.js

    Example: Write results to file:
    node run-tests.js -i MASTestApp -u -p test-framework.js -o results.txt
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
