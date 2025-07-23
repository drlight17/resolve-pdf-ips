# resolve-pdf-ips

Small PHP script to extract IP and domain addresses from PDFs (e.g. FSTEC or RKN reports), where dots are obfuscated as `[.]`, and generate a `.rsc` file for importing into MikroTik RouterOS address lists.

### Prerequisites:
- PHP 8.1+ (with `php-cli`)
- `pdftotext` (from Poppler tools)

> ⚠️ This script uses `pdftotext`, not `smalot/pdfparser`, because it's faster and doesn't require XML extension.

### How to install:

```bash
git clone https://github.com/drlight17/resolve-pdf-ips 
cd resolve-pdf-ips
```
Install pdftotext (if not already installed):
```bash
# On Ubuntu/Debian:
sudo apt install poppler-utils

# On CentOS/RHEL:
sudo yum install poppler-utils
```
### Usage:
Extract IPs from a PDF:
```bash
php resolve_pdf_ips.php your_report.pdf
```
This will create:

* output_ips.txt — list of cleaned public IPs
* resolve_log.txt — log of processing

Generate a .rsc file for MikroTik:
```bash
php resolve_pdf_ips.php your_report.pdf --mikrotik
```
or
```bash
php resolve_pdf_ips.php your_report.pdf -m
```
Use a custom address list name:
```bash
php resolve_pdf_ips.php your_report.pdf -m --list-name=fstec_ban
```
This creates: fstec_ban.rsc

Example output (fstec_ban.rsc):
```rsc
/ip firewall address-list
add address=1.2.3.4 list=fstec_ban comment="autogen from PDF"
add address=2001:db8::1 list=fstec_ban comment="autogen from PDF"
```
Import to MikroTik:
Upload the .rsc file and run in RouterOS terminal:
```rsc
/import fstec_ban.rsc
```
Force set localization to Russian (default is current console locale):
```bash
php resolve_pdf_ips.php your_report.pdf --locale=ru
```
Batch processing. The following exambple will process all pdf files in the folder `/folder/with/pdf/files/`
```bash
php resolve_pdf_ips.php /folder/with/pdf/files/*.pdf
```
Notes:
* Ignores private, loopback, multicast, and reserved IPs (like 192.168.x.x, 127.0.0.1, 0.0.0.0)
* Domains are resolved to A and AAAA records
* Works best with text-based PDFs (not scanned images)
* Spinner [\|/-] shows progress during processing
