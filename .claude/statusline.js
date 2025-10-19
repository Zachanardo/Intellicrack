#!/usr/bin/env node

// Read JSON from stdin
let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
    try {
        const data = JSON.parse(input);

        // ANSI color codes
        const cyan = '\x1b[36m';
        const brightMagenta = '\x1b[38;5;213m';  // 256-color bright pink/magenta
        const green = '\x1b[32m';
        const brightRed = '\x1b[1;91m';  // Bold bright red for maximum brightness
        const reset = '\x1b[0m';

        // Extract values
        const model = data.model?.display_name || 'Unknown';
        const projectName = data.workspace?.current_dir?.split(/[\/\\]/).pop() || 'Unknown';

        // Get cost
        const cost = data.cost?.total_cost_usd || 0;
        const formattedCost = `$${cost.toFixed(4)}`;

        // Output the status line with colors
        console.log(`${brightMagenta}${projectName}${reset} ${brightRed}|${reset} ${cyan}[${model}]${reset} ${brightRed}|${reset} ${green}${formattedCost}${reset}`);
    } catch (error) {
        // Fallback output if JSON parsing fails
        console.log('[Claude] Intellicrack | $0.0000');
    }
});
