# Legal Disclaimer and Risk Warning

**PLEASE READ THIS DOCUMENT CAREFULLY BEFORE USING ANCHORFORGE.**

## 1. Proof of Concept (PoC) Status
AnchorForge is an experimental Proof of Concept (PoC) provided for educational and demonstrational purposes only. It is NOT professional or production-ready software. The protocol (currently v0.2) and the codebase are under active development and may contain significant bugs, security vulnerabilities, or logic errors.

## 2. Financial Risks and Wallet Security
AnchorForge manages real Bitcoin SV (BSV) digital currency and private keys. 
* **Unencrypted Keys:** This software stores private keys in plaintext within local `.env` files or unencrypted JSON "stores". This is inherently insecure and does not meet industry standards for securing significant financial assets.
* **Loss of Funds:** Any bug in the transaction orchestration, UTXO management, or script logic could lead to a permanent loss of funds.
* **No Recovery:** The author has no access to your keys and cannot recover any lost digital assets.

## 3. Tax Implications
Digital currency transactions, including the payment of network fees and "self-spend" transactions used by this protocol, may constitute taxable events in many jurisdictions. 
* It is your sole responsibility to track your transactions and consult with a qualified tax professional to ensure compliance with your local laws.

## 4. No Liability and MIT License
AnchorForge is licensed under the MIT License. 
* **"As Is" Basis:** The software is provided "as is", without warranty of any kind, express or implied.
* **Disclaimer of Liability:** In no event shall the author or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software. Do not use this software for any illegal activities, do not post illegal content.

## 5. Use at Your Own Risk
By using this software, you acknowledge that you understand the risks associated with blockchain technology, private key management, and experimental software. You agree that you are using AnchorForge entirely at your own risk.