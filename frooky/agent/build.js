const fs = require('fs');
const { execSync, spawn } = require('child_process');
const path = require('path');
const chokidar = require('chokidar');
const minimist = require('minimist');
const { glob } = require('glob');

// Parse arguments
const argv = minimist(process.argv.slice(2), {
    string: ['p', 'T'],
    boolean: ['w'],
    alias: {
        p: 'platform',
        w: 'watch',
        T: 'type'
    },
    default: {
        T: 'full'
    }
});

const platform = argv.platform;
const isWatchMode = argv.watch;
const typeOption = argv.T;

// Validate platform
const validPlatforms = ['android', 'ios'];
if (!platform || !validPlatforms.includes(platform)) {
    console.error('Usage: node build.js -p <platform> [-w] [-T <type>] <hook-pattern> ');
    console.error(`Platform must be one of: ${validPlatforms.join(', ')}`);
    console.error('Example: node build.js -p android -w -T full hooks/*.js');
    process.exit(1);
}

// Handle hook files
const hookPatterns = argv._;
if (argv.hooks) {
    hookPatterns = Array.isArray(argv.hooks) ? argv.hooks : [argv.hooks];
}


// Expand glob patterns to actual files
let hookFiles = [];
for (const pattern of hookPatterns) {
    const matches = glob.sync(pattern);
    if (matches.length === 0) {
        console.error(`No files matched pattern: ${pattern}`);
        process.exit(1);
    }
    hookFiles.push(...matches);
}

if (hookFiles.length === 0) {
    console.error('No hook files specified.');
    process.exit(1);
}

// Verify all hook files exist
hookFiles.forEach(file => {
    if (!fs.existsSync(file)) {
        console.error(`Hook file not found: ${file}`);
        process.exit(1);
    }
});

const tmpDir = path.join(__dirname, 'tmp');
if (!fs.existsSync(tmpDir)) {
    fs.mkdirSync(tmpDir);
}

const hooksFilePath = path.join(tmpDir, '_hooks.ts');

// TODO: Patch when fixing https://github.com/cpholguera/frooky/issues/29
// Function to merge and generate _hooks.ts
function generateHooksFile() {
    const mergedHooks = {
        category: null,
        hooks: []
    };

    console.log(`Combining hooks...`);

    hookFiles.forEach(file => {
        try {
            const content = fs.readFileSync(file, 'utf8');
            const json = JSON.parse(content);

            // Use the first category found
            if (!mergedHooks.category && json.category) {
                mergedHooks.category = json.category;
            }

            // Merge hooks arrays
            if (json.hooks && Array.isArray(json.hooks)) {
                mergedHooks.hooks = mergedHooks.hooks.concat(json.hooks);
            }
        } catch (error) {
            console.error(`Error reading ${file}:`, error.message);
            process.exit(1);
        }
    });

    console.log(`Combined ${mergedHooks.hooks.length} hook(s)`);

    // Generate TypeScript file
    const tsContent = `export const target = ${JSON.stringify(mergedHooks, null, 2)};\n`;

    try {
        fs.writeFileSync(hooksFilePath, tsContent);
        console.log(`Hoooks location: ${hooksFilePath}`);
    } catch (error) {
        console.error('Error writing _hooks.ts:', error.message);
        process.exit(1);
    }
}

// Generate initial hooks file
generateHooksFile();

if (isWatchMode) {
    // Watch mode: use spawn for frida-compile and chokidar for hook files
    console.log(`Starting watch mode for ${platform} agent...`);
    console.log(`Watching hook files: ${hookFiles.join(', ')}`);

    // Start frida-compile in watch mode
    const fridaProcess = spawn('frida-compile', [
        `${path.join(__dirname, platform, 'index.ts')}`,
        '-o', path.join(tmpDir, '_agent.js'),
        '-w',
        '-T', typeOption
    ], { stdio: 'inherit'});

    // Watch hook files for changes
    const watcher = chokidar.watch(hookFiles, {
        persistent: true,
        ignoreInitial: true
    });

    watcher.on('change', (filePath) => {
        console.log(`\nHook file changed: ${filePath}`);
        generateHooksFile();
        // frida-compile will automatically detect _hooks.ts change and rebuild
    });

    // Handle process termination
    process.on('SIGINT', () => {
        console.log('\nStopping watch mode...');
        watcher.close();
        fridaProcess.kill();
        process.exit(0);
    });

} else {
    // Single build mode
    const agentPath = path.join(tmpDir, '_agent.js')
    const command = `frida-compile ${path.join(__dirname, platform, 'index.ts')} -o ${agentPath} -T ${typeOption}`;
    
    try {
        console.log(`Building ${platform} agent...`);
        execSync(command, { stdio: 'inherit' });
        console.log(`Build ${platform} agent complete.`);
        console.log(`Agent location: ${agentPath}`);
    } catch (error) {
        console.error('Build failed:', error.message);
        process.exit(1);
    }
}