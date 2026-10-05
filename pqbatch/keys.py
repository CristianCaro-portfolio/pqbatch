"""Thin, uniform wrappers over the signature algorithms in `cryptography`."""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

ALGORITHMS = {
    # name: (private key class, signature bytes, quantum safe)
    "ed25519": (ed25519.Ed25519PrivateKey, 64, False),
    "mldsa44": (mldsa.MLDSA44PrivateKey, 2420, True),
    "mldsa65": (mldsa.MLDSA65PrivateKey, 3309, True),
    "mldsa87": (mldsa.MLDSA87PrivateKey, 4627, True),
}
ALG_IDS = {name: i for i, name in enumerate(ALGORITHMS)}
ALG_NAMES = {i: name for name, i in ALG_IDS.items()}


@dataclass
class VerifyKey:
    alg: str
    key: object

    @property
    def sig_len(self) -> int:
        return ALGORITHMS[self.alg][1]

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self.key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def to_pem(self) -> bytes:
        return self.key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


@dataclass
class SignKey:
    alg: str
    key: object

    @classmethod
    def generate(cls, alg: str) -> "SignKey":
        return cls(alg, ALGORITHMS[alg][0].generate())

    @property
    def sig_len(self) -> int:
        return ALGORITHMS[self.alg][1]

    @property
    def quantum_safe(self) -> bool:
        return ALGORITHMS[self.alg][2]

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message)

    def public(self) -> VerifyKey:
        return VerifyKey(self.alg, self.key.public_key())

    def to_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def _alg_of(key: object) -> str:
    """Map a loaded key object to its algorithm name, e.g. MLDSA65PublicKey -> mldsa65."""
    kind = type(key).__name__.lower().replace("privatekey", "").replace("publickey", "")
    if kind not in ALGORITHMS:
        raise ValueError(f"unsupported key type {type(key).__name__}")
    return kind


def load_sign_key(pem: bytes) -> SignKey:
    key = serialization.load_pem_private_key(pem, None)
    return SignKey(_alg_of(key), key)


def load_verify_key(pem: bytes) -> VerifyKey:
    key = serialization.load_pem_public_key(pem)
    return VerifyKey(_alg_of(key), key)
