#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
    try {
        const data = JSON.parse(input);

        const cyan = '\x1b[36m';
        const brightMagenta = '\x1b[38;5;213m';
        const green = '\x1b[32m';
        const brightGreen = '\x1b[1;92m';
        const yellow = '\x1b[1;93m';
        const brightRed = '\x1b[1;91m';
        const orangeGold = '\x1b[38;5;214m';
        const reset = '\x1b[0m';

        const model = data.model?.display_name || 'Unknown';
        const projectName = data.workspace?.current_dir?.split(/[\/\\]/).pop() || 'Unknown';
        const sessionId = data.session_id || '';
        const transcriptPath = data.transcript_path || '';

        const cost = data.cost?.total_cost_usd || 0;
        const formattedCost = `$${cost.toFixed(4)}`;

        const linesAdded = data.cost?.total_lines_added || 0;
        const linesRemoved = data.cost?.total_lines_removed || 0;

        const totalTokens = calculateSessionTokens(sessionId, transcriptPath);
        const contextPercentage = calculateContextPercentage(transcriptPath);

        const formattedTokens = formatTokenCount(totalTokens);
        const { text: contextText, color: contextColor } = formatContextPercentage(contextPercentage);

        const contextColored = contextColor === 'green' ? green : contextColor === 'yellow' ? yellow : brightRed;

        console.log(
            `${brightMagenta}${projectName}${reset} ${brightRed}|${reset} ` +
            `${cyan}[${model}]${reset} ${brightRed}|${reset} ` +
            `Tokens: ${orangeGold}${formattedTokens}${reset} ${brightRed}|${reset} ` +
            `${green}${formattedCost}${reset} ${brightRed}|${reset} ` +
            `Context: ${contextColored}${contextText}${reset} ${brightRed}|${reset} ` +
            `Lines added: ${brightGreen}${linesAdded}${reset} ${brightRed}|${reset} ` +
            `Lines removed: ${brightRed}${linesRemoved}${reset}`
        );
    } catch (error) {
        console.log('[Claude] Intellicrack | $0.0000');
    }
});

function calculateSessionTokens(sessionId, transcriptPath) {
    if (!sessionId || !transcriptPath || !fs.existsSync(transcriptPath)) {
        return 0;
    }

    const cacheDir = path.join(os.tmpdir(), 'claude-statusline-tokens');
    const cacheFile = path.join(cacheDir, `${sessionId}.json`);

    try {
        if (!fs.existsSync(cacheDir)) {
            fs.mkdirSync(cacheDir, { recursive: true });
        }

        const now = Date.now();
        let cache = null;

        if (fs.existsSync(cacheFile)) {
            try {
                const cacheData = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
                if (now - cacheData.timestamp < 1000) {
                    return cacheData.totalTokens;
                }
                cache = cacheData;
            } catch (e) {
                cache = null;
            }
        }

        const processedHashes = new Set(cache?.processedHashes || []);
        let totalTokens = cache?.totalTokens || 0;

        const content = fs.readFileSync(transcriptPath, 'utf8');
        const lines = content.trim().split('\n').filter(line => line.trim());

        for (const line of lines) {
            try {
                const entry = JSON.parse(line);
                const messageId = entry.message_id || entry.message?.id;
                const requestId = entry.requestId || entry.request_id;

                if (!messageId || !requestId) continue;

                const hash = `${messageId}:${requestId}`;
                if (processedHashes.has(hash)) continue;

                const tokens = extractTokensFromEntry(entry);
                if (tokens.totalTokens <= 0) continue;

                totalTokens += tokens.totalTokens;
                processedHashes.add(hash);
            } catch (e) {
                continue;
            }
        }

        fs.writeFileSync(cacheFile, JSON.stringify({
            timestamp: now,
            totalTokens,
            processedHashes: Array.from(processedHashes)
        }));

        return totalTokens;
    } catch (error) {
        return 0;
    }
}

function calculateContextPercentage(transcriptPath) {
    if (!transcriptPath || !fs.existsSync(transcriptPath)) {
        return 0;
    }

    try {
        const content = fs.readFileSync(transcriptPath, 'utf8');
        const lines = content.trim().split('\n').filter(line => line.trim());

        let totalContextTokens = 0;
        const processedHashes = new Set();

        for (const line of lines) {
            try {
                const entry = JSON.parse(line);
                const messageId = entry.message_id || entry.message?.id;
                const requestId = entry.requestId || entry.request_id;

                if (messageId && requestId) {
                    const hash = `${messageId}:${requestId}`;
                    if (processedHashes.has(hash)) continue;
                    processedHashes.add(hash);
                }

                const tokens = extractTokensFromEntry(entry);
                totalContextTokens += tokens.totalTokens;
            } catch (e) {
                continue;
            }
        }

        const contextLimit = 200000;
        const percentage = (totalContextTokens / contextLimit) * 100;
        return Math.min(percentage, 100);
    } catch (error) {
        return 0;
    }
}

function extractTokensFromEntry(entry) {
    const tokens = {
        inputTokens: 0,
        outputTokens: 0,
        cacheCreationTokens: 0,
        cacheReadTokens: 0,
        totalTokens: 0
    };

    const sources = [];
    const isAssistant = entry.type === 'assistant';

    if (isAssistant) {
        if (entry.message?.usage) sources.push(entry.message.usage);
        if (entry.usage) sources.push(entry.usage);
    } else {
        if (entry.usage) sources.push(entry.usage);
        if (entry.message?.usage) sources.push(entry.message.usage);
    }
    sources.push(entry);

    for (const source of sources) {
        if (!source || typeof source !== 'object') continue;

        const inputFields = ['input_tokens', 'inputTokens', 'prompt_tokens'];
        const outputFields = ['output_tokens', 'outputTokens', 'completion_tokens'];
        const cacheCreationFields = ['cache_creation_tokens', 'cache_creation_input_tokens', 'cacheCreationInputTokens'];
        const cacheReadFields = ['cache_read_input_tokens', 'cache_read_tokens', 'cacheReadInputTokens'];

        const input = extractField(source, inputFields);
        const output = extractField(source, outputFields);
        const cacheCreation = extractField(source, cacheCreationFields);
        const cacheRead = extractField(source, cacheReadFields);

        if (input > 0 || output > 0) {
            tokens.inputTokens = input;
            tokens.outputTokens = output;
            tokens.cacheCreationTokens = cacheCreation;
            tokens.cacheReadTokens = cacheRead;
            tokens.totalTokens = input + output;
            break;
        }
    }

    return tokens;
}

function extractField(obj, fieldNames) {
    for (const field of fieldNames) {
        const value = obj[field];
        if (value && value > 0) {
            return parseInt(value, 10);
        }
    }
    return 0;
}

function formatTokenCount(tokens) {
    if (tokens >= 1000000) {
        return `${(tokens / 1000000).toFixed(1)}M`;
    } else if (tokens >= 1000) {
        return `${(tokens / 1000).toFixed(1)}k`;
    }
    return tokens.toString();
}

function formatContextPercentage(percentage) {
    const formatted = percentage.toFixed(1) + '%';
    let color = 'green';

    if (percentage >= 80) {
        color = 'red';
    } else if (percentage >= 50) {
        color = 'yellow';
    }

    return { text: formatted, color };
}
