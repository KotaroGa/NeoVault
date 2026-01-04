## 🔐 NEOVAULT - Secure File Vault

> **MATRIX EDITION** | `>_ CLI OPERATIONAL`

![Matrix](https://img.shields.io/badge/STATUS-CLI_OPERATIONAL-green)
![CI Tests](https://github.com/KotaroGa/NeoVault/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/PYTHON-3.8+-blue)
![Platform](https://img.shields.io/badge/PLATFORM-Win%20|%20Linux%20|%20macOS-black)
<<<<<<< HEAD
![Version](https://img.shields.io/badge/VERSION-0.3.2-red)


 - SYSTEM: Neovault v0.3.2 online
=======
![Version](https://img.shields.io/badge/VERSION-0.3.3-red)


 - SYSTEM: Neovault v0.3.3 online
>>>>>>> develop
 - MISSION: Protect Digital Assets
 - STATUS: CLI & Testing Suite Active ✅
 - PROTOCOLS: AES-256-GCM | PBKDF2-HMAC-SHA256


### 🚀 QUICK START

```bash
# Clone the repository
git clone https://github.com/KotaroGa/NeoVault.git
cd neovault

# Checkout latest release
<<<<<<< HEAD
git checkout v0.3.2
=======
git checkout v0.3.3
>>>>>>> develop

# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate
# Activate (Windows)
# .venv\Scripts\activate

# Install package in development mode
pip install -e .
<<<<<<< HEAD
```
=======

# Test the system
nvault --version
nvault generate --length 16
nvault create secrets.nvault
nvault add password --content "SuperSecret123!" --vault secrets.nvault
nvault list --vault secrets.nvault
```
> [!NOTE]
>##### All CLI Commands are now available globally
>>>>>>> develop

### 🔮 FEATURES IMPLEMENTED
- ✅ ALL 8 CLI COMMANDS GLOBAL
- ✅ CREATE, ADD, LIST, SEARCH, GET, REMOVE
- ✅ INTERACTIVE SHELL MODE
- ✅ COMPLETE VAULT MANAGEMENT

- ✅ SETUP.PY & PYPROJECT.TOML COMPLETE
- ✅ PIP INSTALLABLE PACKAGE (pip install -e .)
- ✅ GLOBAL NVAULT COMMAND

- ✅ BASIC GENERATE FUNCTIONALITY
<<<<<<< HEAD
=======
- ✅ 60+ UNIT & INTEGRATION TESTS
- ✅ GITHUB ACTIONS CI/CD PIPELINE
- ✅ TEST COVERAGE REPORTING
- ✅ MULTI-PYTHON SUPPORT (3.10-3.12)
- ✅ CRYPTOGRAPHIC VALIDATION TESTS
- ✅ END-TO-END WORKFLOW TESTS
>>>>>>> develop

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

- ✅ KEY DERIVATION FUNCTIONS
- ✅ BASIC FILE OPERATIONS
- ✅ INTEGRATION TESTING


### 🚧 FEATURES IN PROGRESS
<<<<<<< HEAD
- [x] COMPLETE CLI COMMAND INTEGRATION (0.3.2)
- [ ] UNIT TESTS FOR CLI MODULE (v0.3.3)
- [ ] MATRIX-STYLE GUI (v0.4.0)
- [ ] PASSWORD STRENGTH VALIDATOR
- [ ] PORTABLE EXECUTABLES
=======
- 🔲 MATRIX-STYLE GUI (v0.4.0)
- 🔲 PASSWORD STRENGTH VALIDATOR
- 🔲 PORTABLE EXECUTABLES
- 🔲 TWO-FACTOR AUTHENTICATION
- 🔲 AUDIT LOGGING
>>>>>>> develop


### 💻 BASIC USAGE EXAMPLE

```bash
# Create a vault
nvault create secrets.nvault

# Add entries
nvault add email --content "my@email.com" --vault secrets.nvault
nvault add password --content "SecurePass123!" --metadata '{"service":"Gmail"}' --vault secrets.nvault

# List contents
nvault list --details --vault secrets.nvault

# Generate password
nvault generate --length 16 --no-symbols
```

### ⚙️ TECH STACK
- >_ ZuN6hMPUtu7aBACKEND: Python 3.10+
- >_ CRYPTO: cryptography (AES-256-GCM)
- >_ CLI: Argparse + Getpass
- >_ TESTING: pytest + coverage
- >_ CI/CD: GitHub Actions
- >_ GUI: CustomTkinter (v0.4.0)
- >_ BUILD: PyInstaller (FUTURE)


### 🐉 WARNING
<<<<<<< HEAD
- >_ THIS IS VERSION 0.3.2 - DEVELOPMENT
=======
- >_ THIS IS VERSION 0.3.3 - DEVELOPMENT
- >_ CLI COMPLETE WITH ALL COMMANDS ✅
- >_ TESTING SUITE ACTIVE (60+ TESTS) ✅
>>>>>>> develop
- >_ DO NOT USE FOR PRODUCTION DATA
- >_ SECURITY AUDIT PENDING
- >_ ALWAYS BACKUP YOUR FILES
- >_ REPORT ISSUES ON GITHUB

---
>[!TIP]
>###### If you like my work and want to support it, you can do so with cryptocurrencies.  
>###### Your contributions help maintain projects and continue creating free content ❤️
>###### [🟢] BITCOIN (BTC): `bc1qlhup35a64qq0e6uc2v07s64tzjrmj8j9e24jmr`  
>###### [🟢] ETHEREUM (ETH): `0x6D4DB084eaC2cF9D4BbF04FdCBd3e737FDD36dcc`  
>###### [🟢] SOLANA (SOL): `51ueAbc6TC52UExxTKRZuN6hMPUtu7aoYSKuiWnLSci2`

<<<<<<< HEAD
---
### NeoVault - Because your secrets deserve a guardian. 🔐
=======
> [🟢] BITCOIN (BTC): `bc1qlhup35a64qq0e6uc2v07s64tzjrmj8j9e24jmr`  
> [🟢] ETHEREUM (ETH): `0x6D4DB084eaC2cF9D4BbF04FdCBd3e737FDD36dcc`  
> [🟢] SOLANA (SOL): `51ueAbc6TC52UExxTKRoYSKuiWnLSci2`
>>>>>>> develop
