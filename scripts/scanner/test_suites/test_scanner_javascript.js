const crypto = require('crypto');
const fs = require('fs');
const { exec } = require('child_process');

class TruePositives {
    tp01_keygen_trivial(username) {
        return username + "1234";
    }

    tp02_keygen_hardcoded() {
        return "XXXX-YYYY-ZZZZ";
    }

    tp03_patcher_no_backup(binaryPath, offset, data) {
        const fd = fs.openSync(binaryPath, 'r+');
        fs.writeSync(fd, data, 0, data.length, offset);
        fs.closeSync(fd);
    }

    tp04_patcher_hardcoded(filePath) {
        const fd = fs.openSync(filePath, 'r+');
        fs.writeSync(fd, Buffer.from([0x90, 0x90]), 0, 2, 0x1000);
        fs.closeSync(fd);
    }

    tp05_validator_always_true(key) {
        return true;
    }

    tp06_analyzer_string_match(binary) {
        const content = fs.readFileSync(binary, 'utf8');
        return content.includes('license');
    }

    tp07_empty_impl() {
    }

    tp08_placeholder() {
        const result = null;
        return result;
    }

    tp09_keygen_md5_only(user) {
        return crypto.createHash('md5').update(user).digest('hex');
    }

    tp10_patcher_blind(binary, patch) {
        return Buffer.concat([binary, patch]);
    }

    tp11_analyzer_extension_only(path) {
        return { type: path.endsWith('.exe') ? 'PE' : 'ELF' };
    }

    tp12_hook_skeleton(funcName) {
        return `Interceptor.attach(ptr('${funcName}'), {});`;
    }
}

class FalsePositives {
    fp01_delegator(type) {
        const handlers = {
            'encrypt': this.crypto.encrypt,
            'decrypt': this.crypto.decrypt,
            'hash': this.crypto.hash
        };
        return handlers[type] || handlers['hash'];
    }

    fp02_getter() {
        return this._value;
    }

    fp03_setter(val) {
        this._value = val;
    }

    fp04_event_handler(event) {
        this.events.push(event);
    }

    fp05_config_loader() {
        return JSON.parse(fs.readFileSync('config.json', 'utf8'));
    }

    fp06_wrapper_exec(binary) {
        return new Promise((resolve, reject) => {
            exec(`radare2 -q ${binary}`, (error, stdout) => {
                if (error) reject(error);
                else resolve(stdout);
            });
        });
    }

    fp07_factory(analyzerType) {
        if (analyzerType === 'static') return new StaticAnalyzer();
        if (analyzerType === 'dynamic') return new DynamicAnalyzer();
        return new DefaultAnalyzer();
    }

    fp08_router(operation, data) {
        if (operation === 'process') return this.processor.handle(data);
        if (operation === 'analyze') return this.analyzer.run(data);
        return data;
    }

    fp09_conditional_import() {
        if (typeof GPU !== 'undefined') {
            const torch = require('torch');
            return torch.device('cuda');
        }
        return 'cpu';
    }

    fp10_env_config() {
        return {
            apiKey: process.env.API_KEY,
            debug: process.env.DEBUG === 'true'
        };
    }

    fp11_builder(type) {
        const builders = {
            'nop': () => Buffer.from([0x90, 0x90, 0x90]),
            'ret': () => Buffer.from([0xC3])
        };
        return builders[type]();
    }

    fp12_callback(msg) {
        console.log(`Message: ${msg}`);
        this.count++;
    }
}

class ProductionCode {
    advanced_keygen_rsa(username, productId) {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const dataToSign = `${username}:${productId}`;

        const signature = crypto.sign('sha256', Buffer.from(dataToSign), {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        });

        const licenseKey = signature.toString('base64');
        const checksum = crypto.createHash('sha256').update(licenseKey).digest('hex').substring(0, 8);

        return `${licenseKey.substring(0, 20)}-${checksum}`;
    }

    safe_binary_patcher(binaryPath, patches) {
        const backupPath = `${binaryPath}.bak_${Date.now()}`;
        fs.copyFileSync(binaryPath, backupPath);

        let data = fs.readFileSync(binaryPath);

        for (const patch of patches) {
            const offset = data.indexOf(patch.pattern);
            if (offset === -1) {
                return false;
            }

            data = Buffer.concat([
                data.slice(0, offset),
                patch.replacement,
                data.slice(offset + patch.pattern.length)
            ]);
        }

        fs.writeFileSync(binaryPath, data);
        return true;
    }

    license_validator(licenseKey, hardwareId) {
        if (!licenseKey || licenseKey.length < 20) {
            return false;
        }

        try {
            const parts = licenseKey.split('-');
            if (parts.length !== 2) {
                return false;
            }

            const [signature, checksum] = parts;
            const computed = crypto.createHash('sha256').update(signature).digest('hex').substring(0, 8);

            if (computed !== checksum) {
                return false;
            }

            const verify = crypto.verify(
                'sha256',
                Buffer.from(hardwareId),
                { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
                Buffer.from(signature, 'base64')
            );

            return verify;
        } catch (e) {
            return false;
        }
    }
}

class StaticAnalyzer {}
class DynamicAnalyzer {}
class DefaultAnalyzer {}

module.exports = { TruePositives, FalsePositives, ProductionCode };
