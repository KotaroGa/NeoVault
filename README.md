## 🔐 NEOVAULT - Secure File Vault

> **MATRIX EDITION** | `>_ GUI & CLI OPERATIONAL`

![Matrix](https://img.shields.io/badge/STATUS-GUI_OPERATIONAL-green)
![Python](https://img.shields.io/badge/PYTHON-3.10+-blue)
![Platform](https://img.shields.io/badge/PLATFORM-Win%20|%20Linux%20|%20macOS-black)
![Version](https://img.shields.io/badge/VERSION-0.4.0-red)
![Tests](https://img.shields.io/badge/TESTS-60%2B%20passing-brightgreen)
![GUI](https://img.shields.io/badge/GUI-MATRIX_STYLE-00FF41)

 - SYSTEM: Neovault v0.4.0 online
 - MISSION: Protect Digital Assets  
 - PROTOCOLS: AES-256-GCM | PBKDF2-HMAC-SHA256
 - INTERFACE: CLI + MATRIX GUI


### 🚀 QUICK START

```bash
# Clone the repository
git clone https://github.com/KotaroGa/NeoVault.git
cd neovault

# Checkout latest release
git checkout v0.4.0

# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate
# Activate (Windows)
# .venv\Scripts\activate

# Install package in development mode
pip install -e .

# Test CLI system
nvault --version
nvault generate --length 16

# Launch Matrix GUI
nvault-gui

# Or use CLI commands
nvault create secrets.nvault
nvault add password --content "SuperSecret123!" --vault secrets.nvault
nvault list --vault secrets.nvault
```
> [!NOTE]
>##### Dual Interface available: CLI for script, GUI for visual management


### 🖥️ MATRIX GUI (v0.4.0)
>_ LAUNCH: nvault-gui
>_ THEME: Green/black terminal style
>_ ARCHITECTURE: MVC with controllers
>_ STATUS: Fully operational

#### Features:
- ✅ Matrix green/black terminal aesthetic
- ✅ Sidebar navigation with 5 functional sections
- ✅ Vault manager with real file system integration
- ✅ Password generator with strength calculation
- ✅ System status monitoring (CPU/Memory)
- ✅ Persistent terminal logging area
- ✅ Dynamic content switching
- ✅ CustomTkinter-based interface

#### Screens:
- 📁 VAULTS - View and manage vault files
- 🔑 GENERATE - Create secure passwords
- 🔍 SEARCH - Search interface (placeholder)
- ⚙️ SETTINGS - System configuration (placeholder)
- 🖥️ TERMINAL - System terminal (placeholder)



### 🔮 FEATURES IMPLEMENTED
- ✅ MATRIX-STYLE GUI INTERFACE
- ✅ MVC CONTROLLERS ARCHITECTURE
- ✅ REAL-TIME SYSTEM MONITORING
- ✅ PASSWORD GENERATOR WITH STRENGTH RATING
- ✅ VAULT FILE BROWSER
- ✅ PERSISTENT TERMINAL LOGGING

- ✅ SETUP.PY & PYPROJECT.TOML COMPLETE
- ✅ PIP INSTALLABLE PACKAGE (pip install -e .)
- ✅ GLOBAL NVAULT COMMAND

- ✅ BASIC GENERATE FUNCTIONALITY
- ✅ 60+ UNIT & INTEGRATION TESTS
- ✅ TEST COVERAGE REPORTING
- ✅ MULTI-PYTHON SUPPORT (3.10-3.12)
- ✅ CRYPTOGRAPHIC VALIDATION TESTS
- ✅ END-TO-END WORKFLOW TESTS

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
- 🔲 BACKEND INTEGRATION (GUI ↔ Core)
- 🔲 ADVANCED VAULT BROWSER
- 🔲 PASSWORD STRENGTH VALIDATOR
- 🔲 PORTABLE EXECUTABLES
- 🔲 TWO-FACTOR AUTHENTICATION
- 🔲 AUDIT LOGGING
- 🔲 MATRIX ANIMATIONS (Rain effect)


### ⚙️ TECH STACK
- >_ BACKEND: Python 3.10+
- >_ CRYPTO: cryptography (AES-256-GCM)
- >_ CLI: Argparse + Getpass
- >_ GUI: CustomTkinter 5.2.0+
- >_ CONTROLLERS: MVC Architecture
- >_ SYSTEM: psutil for monitoring
- >_ TESTING: pytest + coverages
- >_ BUILD: PyInstaller (FUTURE)


### 🐉 WARNING
- >_ THIS IS VERSION 0.4.0 - DEVELOPMENT
- >_ CLI COMPLETE WITH ALL COMMANDS ✅
- >_ GUI FUNCTIONAL WITH BASIC FEATURES ✅
- >_ TESTING SUITE ACTIVE (60+ TESTS) ✅
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

> [🟢] BITCOIN (BTC): `bc1qlhup35a64qq0e6uc2v07s64tzjrmj8j9e24jmr`  
> [🟢] ETHEREUM (ETH): `0x6D4DB084eaC2cF9D4BbF04FdCBd3e737FDD36dcc`  
> [🟢] SOLANA (SOL): `51ueAbc6TC52UExxTKRoYSKuiWnLSci2`