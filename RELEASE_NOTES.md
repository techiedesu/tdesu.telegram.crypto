## 0.1.0

Initial release. Extracted from SedBot MTProto server.

### Modules
- AesIge: AES-256-IGE encryption/decryption (MTProto message encryption)
- KeyDerivation: MTProto 2.0 AES key+IV derivation from auth_key and msg_key
- DiffieHellman: 2048-bit DH key exchange (generate g^b, compute auth_key, validate params)
- Rsa: Raw RSA encryption for DH handshake (production key included)
- Padding: Random padding (12-1024 bytes, aligned to 16)
- AuthKeyId: auth_key_id computation (SHA1-based)
