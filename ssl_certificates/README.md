# SSL/TLS Certificate Authority Files

This directory contains Certificate Authority (CA) files used by Intellicrack's SSL/TLS interception module for security research purposes.

## Files

- **ca.crt**: Self-signed root certificate authority certificate
- **ca.key**: Private key for the certificate authority

## Purpose

These files are used by the SSL interceptor module (`intellicrack/core/network/ssl_interceptor.py`) to:
- Generate SSL certificates on-the-fly for intercepted connections
- Enable analysis of encrypted network traffic
- Support legitimate security research and authorized penetration testing

## Security Notice

⚠️ **IMPORTANT**: These files contain cryptographic keys and should be:
- Kept secure and not shared publicly
- Only used for authorized security testing
- Protected with appropriate file permissions
- Regenerated periodically for security

## Legal Notice

These certificates are for legitimate security research purposes only. Users must comply with all applicable laws and only use these tools on systems they own or have explicit permission to test.

## License

These certificate files are part of Intellicrack and are covered under the GNU General Public License v3.0. See the LICENSE file in the project root for details.