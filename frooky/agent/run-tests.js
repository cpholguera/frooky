// run-tests.js
import path from 'path';
import fs from 'fs';
import frida from 'frida';
import minimist from 'minimist';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const argv = minimist(process.argv.slice(2), {
    string: ['platform', 'appIdentifier'],
    boolean: ['help', 'usb'],
    alias: {
        p: 'platform',
        h: 'help',
        u: 'usb',
    }
});

validateInput();

const helpOption = argv.help;
const usbOption = argv.usb;
const platformOption = argv.platform;
const appIdentifier = Number.isFinite(Number(argv.appIdentifier))
  ? Number(argv.appIdentifier)
  : argv.appIdentifier;


if (helpOption) {
    showHelp();
}

async function runTests() {

    let session;
    let device;
    let pid;

    if (usbOption) {
        device = await frida.getUsbDevice();
        pid = await device.spawn(appIdentifier);
        session = await device.attach(pid);
    } else {
        pid = appIdentifier
        device = await frida.getLocalDevice();
        session = await device.attach(pid);
    }


    const distDir = path.join(__dirname, 'dist');
    const agentPath = path.join(distDir, `agent-test-${platformOption}.js`)

    const script = await session.createScript(
        fs.readFileSync(agentPath, 'utf8')
    );


    let testComplete = false;
    let exitCode = 1;


    script.message.connect(message => {
        if (message.type === 'send') {
            const payload = message.payload;

            if (payload.type === 'test-result') {
                // Print individual test results as they arrive
                if (payload.passed) {
                    console.log(`  ✅ PASS: ${payload.name}`);
                } else {
                    console.error(`  ❌ FAIL: ${payload.name}: ${payload.error}`);
                }
            } else if (payload.type === 'test-complete') {
                testComplete = true;

                if (payload.success) {
                    console.log('\n✅ PASS: All tests passed.');
                    exitCode = 0;
                } else {
                    console.error('\n❌ FAIL: Some tests failed.');
                    exitCode = 1;
                }
            }
        } else if (message.type === 'error') {
            console.error('Script error:', message.stack);
            testComplete = true;
            exitCode = 1;
        }
    });
    
    await script.load();
    await device.resume(pid);

    // Wait for test completion (with timeout)
    const timeout = 30000;
    const startTime = Date.now();

    while (!testComplete && (Date.now() - startTime) < timeout) {
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (!testComplete) {
        console.error('Tests timed out');
        exitCode = 1;
    }

    await session.detach();
    process.exit(exitCode);
}

runTests().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});

function showHelp() {
    console.log(`
    Options:
    -p, --platform <name>     Platform (android, ios)
    -h, --help                Show this help message
    `);
    process.exit(0);
}

function validateInput() {
    const validPlatforms = ['android', 'ios'];
    if (!validPlatforms.includes(platformOption)) {
        console.error(`Platform must be one of: ${validPlatforms.join(', ')}`);
        process.exit(1);
    }
    if (!argv.appIdentifier) {
        console.error('App Identifier (--appIdentifier) is required');
        process.exit(1);
    }
    if (!argv.usb && isNaN(argv.appIdentifier)) {
        console.error('App identifier (--appIdentifier) must be a numeric PID if used locally');
        process.exit(1);
    }
}
