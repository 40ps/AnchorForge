# AnchorForge v0.2 alpha (PoC)

**Scalable, Off-Chain Verifiable Audit Trails on Bitcoin SV**

AnchorForge is a Proof of Concept (PoC) **to demonstrate** how the Bitcoin SV blockchain can act as a public ledger for high-frequency data integrity anchors. Unlike traditional solutions, AnchorForge enables **off-chain verification (SPV)** that scales without requiring access to blockchain except (for an initial list of blockheaders).

Note: This is a PoC. For real efficency, the concept needs to be reimplemented with C++ (or similar) using professional API access for the anchoring, removing the verbosity in data, protocols, a professional wallet.

## ⚠️ Experimental Software Notice
This project is an early-stage Proof of Concept. It is **not** professional or production-ready software.
- **Financial Risk:** Involves real BSV coins and private key management. Private keys are stored locally in unencrypted files.
- **Taxation:** Transactions (even self-spends) may have tax implications depending on your jurisdiction.
- **No Warranty:** Provided "as is" under the MIT License. See [DISCLAIMER.md](DISCLAIMER.md) for details.

---

## 🔗 Project Genesis & Live Proofs
AnchorForge protocol v0.2 was started Jan 2026. First transaction originate 2025. You can inspect them on any BSV block explorer:

### Bitcoin SV Mainnet
## v0.2
- **Genesis Address:** `1C5TbM266MoCZyKBkHF6nVRihqzZW3iTA8`
- **First Anchor TX:** `41bd1084bb877acb31df59f76c10adeba98e3c399e6c7a6a48a9f9282786dc33`
## v0.1
- **Genesis Address:** `1Z3YVKKVQeE9jDgvdNgiLgTizdC7iqypa`(7200 tx)
- **First Anchor TX:** `5cd8197616fab4a6579ccdd3a782e229c84c0238975aefdb3ea1007a8b1ef6c8`

### Bitcoin SV Testnet
- **Genesis Address:** `mj2GaHeg72bq3egeeib4hJiZfWmKuaSy6g`
- **First overall TX:** `370b94987b775c17e2cefa6a0f0f7a6e32945ef83f64affde32275390cd06a13`

---


## 🔒 Security & Privacy Notice
**Your private keys and audit data are your responsibility.**
- **Local Storage:** All keys and logs should be stored locally in the `local_config/` and `database/` folders.
- **Git Shield:** Make strict use of `.gitignore` that prevents your `.env` and `.json` logs from being uploaded.
- **Pre-Flight Check:** Never share your `local_config/.env` file. If you fork this repo, ensure your keys remain in the ignored `local_config/` directory.

For detailed information on how to keep your installation secure, see [Security & Privacy Guide](docs/security_and_privacy.md).

---
## 🛠 Core Concepts
- **Self-Spending Anchors:** Transactions are sent to your own address to minimize fees and maintain control.
- **TLV Protocol:** A flexible Tag-Length-Value format allowing multiple signatures (ECDSA/X.509) and metadata in one TX.
- **SPV Verification:** Prove data integrity and blockchain inclusion using only Merkle Proofs and block headers.

## 📚 Documentation
Comprehensive guides are available in the `/docs` directory:
1. [Quickstart Guide](docs/quickstart.md) - Setup, Bank funding, and your first anchor.
2. [CLI Tool Manual](docs/cli_manual.md) - Detailed reference for all command-line tools.
3. [Architecture & Protocol](docs/architecture.md) - Deep dive into the TLV system and SPV logic.
4. [Protocol Standard v0.2](docs/protocol_standard_v02.md) - Technical byte-level specification.
5. [Project History](docs/history.md) - Milestones.
6. [Acknowledgements](ACKNOWLEDGEMENTS.md) - Acknowledgements.

### Configuration
Copy the template
```bash
cp .env.example local_config/.env
```
Edit local_config/.env and fill in your values (private keys, URLs, etc)

**Security Note:**
- Never commit or share local_config/.env
- it is gitignored by default

## 🚀 Examples & Stress-Tests
Check the `/examples` folder for automated logging demonstrations (1 request/3 sec to stay API friendly) :
- (`af_anchor.py`: Logs single events and provides dedicated main example case)
- `main_batch_iss.py`: Anchoring International Space Station location data.
- `main_batch_coingecko.py`: Creating verifiable BSV price audit trails.
*See [Examples Guide](docs/examples.md) for usage details.*

## 👤 Author
**Wolfgang Lohmann:**
Website/GitHub: https://github.com/40ps"
---
*Developed for educational purposes to demonstrate the power of Bitcoin SV for scalable data integrity.*
