# Backup and recovery preparation

`create_encrypted_backup` accepts explicitly supplied bytes and typed metadata only. It requires an injected authenticated `BackupCipher`; without one it rejects persistence. The cipher boundary is for Mandar/OpenBao integration. No keys are hardcoded or stored beside an artifact.

Each artifact records original-byte and ciphertext SHA-256 values. Reads verify org/asset metadata, ciphertext integrity, authenticated decryption, and original-byte hash. An encrypted offline snapshot is **not** a verified restorable device backup.

Recovery specifications are conditional template inverses. They require known prior state and an approved out-of-band path, warn about drift and management loss, and remain `BLOCKED`. They are not tested rollback promises. Ansible/Ansible Runner, PowerShell automation, vendor APIs, OpenBao deployment, live backup collection, and restore execution are intentionally not implemented.
