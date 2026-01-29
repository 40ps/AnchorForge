# Security & Privacy (Data Protection)

AnchorForge is designed with a "Safety-First" approach regarding your private keys and local audit data. 

## 1. How your data is protected
The project includes a pre-configured `.gitignore` file. This file acts as a shield, ensuring that sensitive information never leaves your local machine.

### Automatically Ignored Paths:
- **`local_config/.env`**: Contains your private keys and API credentials.
- **`cache/wallet/`**: Contains your local UTXO set (your "digital cash").
- **`database/`**: Contains your local audit logs and Merkle proofs.
- **`runtime/`**: Contains temporary session data and batch statuses.

## 2. Why 'local_config' is excluded
The `local_config` directory is the central "Vault" of your AnchorForge installation. 
- We provide a template file: `local_config/.env.template`.
- You must create your own `local_config/.env` from this template.
- **Git is instructed to ignore the .env file**, so even if you run `git add .`, your keys will not be staged for a commit.

## 3. Safety Checklist for Users
Before you share your fork or contribute code, always double-check:
1. **Run `git status`**: Ensure no `.env` or `.json` files from `local_config` or `database` are listed under "Changes to be committed".
2. **Check your Keystore**: If you manually placed keys in `local_config/Keystore/`, verify they are covered by the ignore rules.
3. **Use the Template**: Never rename the template and put keys in it; always create a fresh `.env` copy.

---
*Remember: You are your own bank. If you accidentally upload your .env file to a public repository, your funds and your identity's integrity are at risk.*
