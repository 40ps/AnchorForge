# Technical Debt

### TD-001 Side-effect-free Config loading

Current:
Config import creates runtime directories.

Goal:
Introduce read-only config loader.

Reason:
af_status compatibility exception should disappear.

Priority:
M