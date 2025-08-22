/*
 * AI-Generated Script
 * Prompt: Create a Frida script that hooks CreateFileW API calls and logs all file access attempts. Focus on detecting license file reads.
 * Generated: 2025-08-17T04:17:22.995050
 * Model: none
 * Confidence: 0.7999999999999999
 * Description: Create a Frida script that hooks CreateFileW API calls and logs all file access attempts
 */

                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        console.log('[>] ' + exp.name + ' called');
                    }
                });
            } catch(e) {}
        }
    });
});
