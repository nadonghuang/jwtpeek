<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Zero_Deps-✅-success?style=for-the-badge" alt="Zero Deps"/>
  <img src="https://img.shields.io/badge/Platform-Terminal-9B59B6?style=for-the-badge" alt="Platform"/>
</p>

<h1 align="center">🔍 jwtpeek</h1>

<p align="center">
  <strong>Peek into JWT tokens — decode, inspect & verify with beautiful terminal output.</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Install</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-examples">Examples</a> •
  <a href="#-license">License</a>
</p>

---

## ✨ Features

- 🔍 **Instant Decode** — Paste any JWT and see header, payload & signature broken down
- 🎨 **Colored Output** — Algorithm types, expiration status, and claims highlighted in your terminal
- ✅ **Signature Verification** — Verify HMAC signatures (HS256 / HS384 / HS512) with a secret key
- ⏱ **Smart Timestamps** — Human-readable times with relative duration ("2小时后", "3天前")
- 📋 **Claim Analysis** — Auto-detects 40+ standard JWT claim names with Chinese annotations
- 📊 **JSON Output** — Machine-readable output mode for scripting and automation
- 🔒 **Expiration Check** — Visual status badges: ✅ valid, ⚠ expired, ℹ no expiration
- 📡 **Pipe-Friendly** — Read tokens from stdin, integrate with your workflow
- 🚀 **Zero Dependencies** — Pure Python, no external packages required
- 🎯 **Bearer Detection** — Automatically strips `Bearer ` prefix from tokens

## 📦 Installation

### Quick Run (no install)

```bash
# Download and run directly
curl -sL https://raw.githubusercontent.com/nadonghuang/jwtpeek/main/jwtpeek.py | python3 - <token>
```

### Install via pip

```bash
pip install jwtpeek
```

### Install from source

```bash
git clone https://github.com/nadonghuang/jwtpeek.git
cd jwtpeek
pip install -e .
```

## 🚀 Usage

### Basic — Decode a token

```bash
jwtpeek <your-jwt-token>
```

### Pipe from stdin

```bash
echo $JWT_TOKEN | jwtpeek
```

### Verify signature

```bash
jwtpeek verify <token> --secret my-secret-key
```

### Check token age & expiration

```bash
jwtpeek age <token>
```

### JSON output (for scripting)

```bash
jwtpeek --json <token>
# or payload only
jwtpeek --json-only <token>
```

### Compact summary view

```bash
jwtpeek --compact <token>
```

## 📸 Examples

### Full decode output

```
  🔍 jwtpeek  — JWT Token Inspector

┌─ JWT Token ──────────────────────────────────────────
│ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9···4fwpMe  HEADER
│ eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4g···2fQ  PAYLOAD
│ SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c        SIGNATURE
└──────────────────────────────────────────────────────

╭──────────────────────────────────────╮
│ 🔑 JWT Header                        │
├──────────────────────────────────────┤
│   Algorithm: HS (HMAC)                │
│   Type:      JWT                      │
╰──────────────────────────────────────╯

╭──────────────────────────────────────╮
│ 📦 JWT Payload                        │
├──────────────────────────────────────┤
│ 📋 sub  (Subject)       1234567890    │
│ 📋 name                 John Doe      │
│ 📅 iat  (Issued At)     2018-01-18 ···│
│ 🟢 exp  (Expires At)    2025-06-15 ···│
│ 📋 iss  (Issuer)        auth0.com     │
│ 📋 role                 admin         │
╰──────────────────────────────────────╯

  ✅ TOKEN VALID
```

### Signature verification

```bash
$ jwtpeek verify <token> --secret my-secret

  ✅ SIGNATURE VALID

  Token signature verified successfully with HS256
```

## 🛠 Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.7+ |
| Dependencies | Zero — stdlib only |
| CLI Parser | `argparse` |
| Crypto | `hmac` + `hashlib` |
| Encoding | `base64` (url-safe) |
| Terminal UI | ANSI escape codes |

## 📁 Project Structure

```
jwtpeek/
├── jwtpeek.py            # Core library + CLI (single file!)
├── pyproject.toml        # Package configuration
├── examples/
│   └── gen_test_token.py # Generate test tokens
├── LICENSE               # MIT
├── .gitignore
└── README.md
```

## 🔧 Supported Algorithms

| Algorithm | Type | Decode | Verify |
|-----------|------|--------|--------|
| HS256 | HMAC SHA-256 | ✅ | ✅ |
| HS384 | HMAC SHA-384 | ✅ | ✅ |
| HS512 | HMAC SHA-512 | ✅ | ✅ |
| RS256 | RSA SHA-256 | ✅ | 🔜 |
| RS384 | RSA SHA-384 | ✅ | 🔜 |
| RS512 | RSA SHA-512 | ✅ | 🔜 |
| ES256 | ECDSA P-256 | ✅ | 🔜 |
| none | No signature | ✅ | ✅ |

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with ⚡ by <a href="https://github.com/nadonghuang">nadonghuang</a>
  <br/>
  <sub>If you find this useful, please give it a ⭐!</sub>
</p>
