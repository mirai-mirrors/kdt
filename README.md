# KDT
Mirai's experimental, post-quantum successor to GPG 🔒

---

KDT is the experimental Kyber-Dilithium Toolset - like GPG, but post-quantum! It's not ready for production use just yet, but our aim is that it'll help usher in a "new era" of communications safety, and one that's not vulnerable to quantum attacks.

## To-dos
- [x] Store keyset and private keys in local files
- [x] Asymmetric encryption and decryption (CRYSTALS-Kyber-backed 256 bit AES)
- [ ] Wrap encryption with RSA to undoubtedly achieve the verified cryptographic strength of RSA (because CRYSTALS-Kyber's security hasn't been completely verified)
- [x] Signing and signature verification (CRYSTALS-Dilithium)
- [ ] Improve user friendliness

---

Developed with <3 by [Mirai](https://git.disroot.org/mirai).

![Mirai organisation logo](https://git.disroot.org/avatars/8c879ce5f27a376a3f79b11a4e59c9fcb622d43de8a08dde39333aecf673ac9c)

みらい • ˶ᵔ ᵕ ᵔ˶ • Mirai
