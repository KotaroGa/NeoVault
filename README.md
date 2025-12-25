
## 🔐 NEOVAULT - Secure File Vault

> **MATRIX EDITION** | `>_ CLI OPERATIONAL`

![Matrix](https://img.shields.io/badge/STATUS-CLI_OPERATIONAL-green)
![Python](https://img.shields.io/badge/PYTHON-3.8+-blue)
![Platform](https://img.shields.io/badge/PLATFORM-Win%20|%20Linux%20|%20macOS-black)
![Version](https://img.shields.io/badge/VERSION-0.3.1-red)


 - SYSTEM: Neovault v0.3.1 online
 - MISSION: Protect Digital Assets
 - STATUS: CLI Interface Active
 - PROTOCOLS: AES-256-GCM | PBKDF2-HMAC-SHA256


### 🚀 QUICK START

```bash
# Clone the repository
git clone https://github.com/KotaroGa/neovault.git
cd neovault

# Checkout latest release
git checkout v0.3.1

# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate
# Activate (Windows)
# .venv\Scripts\activate

# Install package in development mode
pip install -e .

# Test global command
nvault --version
nvault generate --length 16
```
> [!NOTE]
>##### Only `generate` command is currently available globally. Other commands require direct Python execution until  v0.3.2.

### 🔮 FEATURES IMPLEMENTED
- ✅ SETUP.PY & PYPROJECT.TOML COMPLETE
- ✅ PIP INSTALLABLE PACKAGE (pip install -e .)
- ✅ GLOBAL NVAULT COMMAND
- ✅ BASIC GENERATE FUNCTIONALITY
- 🔲 OTHER CLI COMMANDS (v0.3.2)

- ✅ CREATE VAULTS - nvault create <vault.nvault>
- ✅ ADD SECRETS   - nvault add <name> --content "secret"
- ✅ LIST ENTRIES  - nvault list [--details]
- ✅ SEARCH VAULT  - nvault search <query>
- ✅ GET ENTRIES   - nvault get <name> [--show]
- ✅ REMOVE ITEMS  - nvault remove <name> [--force]
- ✅ GEN PASSWORDS - nvault generate [--length N]
- ✅ SHELL MODE    - nvault shell

- ✅ AES-256-GCM ENCRYPTION ENGINE
- ✅ PBKDF2 KEY DERIVATION (600K iterations)
- ✅ COMPLETE VAULT MANAGEMENT
- ✅ ENTRY METADATA SUPPORT
- ✅ SECURE VAULT PERSISTENCE

- ✅ CRYPTOGRAPHIC PRIMITIVES
- ✅ KEY DERIVATION FUNCTIONS
- ✅ BASIC FILE OPERATIONS
- ✅ INTEGRATION TESTING


### 🚧 FEATURES IN PROGRESS
- 🔄 COMPLETE CLI COMMAND INTEGRATION (0.3.2)
- 🔄 UNIT TESTS FOR CLI MODULE (v0.3.3)
- 🔲 MATRIX-STYLE GUI (v0.4.0)
- 🔲 PASSWORD STRENGTH VALIDATOR
- 🔲 PORTABLE EXECUTABLES


### ⚙️ TECH STACK
- >_ BACKEND: Python 3.8+
- >_ CRYPTO: cryptography (AES-256-GCM)
- >_ CLI: Argparse + Getpass
- >_ GUI: CustomTkinter (PLANNED)
- >_ BUILD: PyInstaller (FUTURE)


### 🐉 WARNING
- >_ THIS IS VERSION 0.3.1 - DEVELOPMENT
- >_ PACKAGING COMPLETE, CLI PARTIAL
- >_ ONLY `GENERATE` COMMAND AVAILABLE GLOBALLY
- >_ DO NOT USE FOR PRODUCTION DATA
- >_ SECURITY AUDIT PENDING
- >_ ALWAYS BACKUP YOUR FILES
- >_ REPORT ISSUES ON GITHUB

---
>##### NeoVault - Because your secrets deserve a guardian. 🔐
---
> [!TIP]
>##### If you like my work and want to support it, you can do so with cryptocurrencies.  
>##### Your contributions help maintain projects and continue creating free content ❤️

[🟢] BITCOIN (BTC): `bc1qlhup35a64qq0e6uc2v07s64tzjrmj8j9e24jmr`  
[🟢] ETHEREUM (ETH): `0x6D4DB084eaC2cF9D4BbF04FdCBd3e737FDD36dcc`  
[🟢] SOLANA (SOL): `51ueAbc6TC52UExxTKRZuN6hMPUtu7aoYSKuiWnLSci2`