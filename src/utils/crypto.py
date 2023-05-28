import requests
import functools
import base64
from typing import Tuple
from nacl.bindings import crypto_kx_keypair, crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt, randombytes, crypto_secretbox_NONCEBYTES
from ..version import __version__


PHASE_KMS_URI = "https://kms.phase.dev/"


def xor_bytes(a, b) -> bytes:
    """
    Computes the XOR of two byte arrays byte by byte.

    Args:
        a (bytes): The first byte array
        b (bytes): The second byte array.

    Returns:
        bytes: A byte array representing the XOR of the two input byte arrays.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def reconstruct_secret(shares) -> str:
    """
    Reconstructs a secret given an array of shares.

    Args:
        shares (list): A list of hex-encoded secret shares.

    Returns:
        str: The reconstructed secret as a hex-encoded string.
    """
    return functools.reduce(xor_bytes, [bytes.fromhex(share) for share in shares]).hex()


def random_key_pair() -> Tuple[bytes, bytes]:
    """
    Generates a random key exchange keypair.

    Returns:
        Tuple[bytes, bytes]: A tuple of two bytes objects representing the public and
        private keys of the keypair.
    """
    keypair = crypto_kx_keypair()
    return keypair


def encrypt_raw(plaintext, key) -> bytes:
    """
    Encrypts plaintext with the given key and returns the ciphertext with appended nonce

    Args:
        plaintext (bytes): Plaintext to be encrypted
        key (bytes): The encryption key to be used

    Returns:
        bytes: ciphertext + nonce
    """
    try:
        nonce = randombytes(crypto_secretbox_NONCEBYTES)
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, None, nonce, key)
        return ciphertext + nonce
    except Exception:
        raise ValueError('Encryption error')


def encrypt_b64(plaintext, key_bytes) -> str:
    """
    Encrypts a string using a key. Returns ciphertext as a base64 string

    Args:
        plaintext (str): The plaintext to encrypt.
        key (bytes): The key to use for encryption.

    Returns:
        str: The ciphertext obtained by encrypting the string with the key, encoded with base64.
    """

    plaintext_bytes = bytes(plaintext, 'utf-8')
    ciphertext = encrypt_raw(plaintext_bytes, key_bytes)
    return base64.b64encode(ciphertext).decode('utf-8')


def decrypt_raw(ct, key) -> bytes:
    """
    Decrypts a ciphertext using a key.

    Args:
        ct (bytes): The ciphertext to decrypt.
        key (bytes): The key to use for decryption, as a hexadecimal string.

    Returns:
        bytes: The plaintext obtained by decrypting the ciphertext with the key.
    """

    try:
        nonce = ct[-24:]
        ciphertext = ct[:-24]

        plaintext_bytes = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, None, nonce, key)

        return plaintext_bytes
    except Exception:
        raise ValueError('Decryption error')


def decrypt_b64(ct, key) -> bytes:
    """
    Decrypts a base64 ciphertext using a key.

    Args:
        ct (str): The ciphertext to decrypt, as a base64 string.
        key (str): The key to use for decryption, as a hexadecimal string.

    Returns:
        str: The plaintext obtained by decrypting the ciphertext with the key.
    """

    ct_bytes = base64.b64decode(ct)
    key_bytes = bytes.fromhex(key)

    plaintext_bytes = decrypt_raw(ct_bytes, key_bytes)

    return plaintext_bytes.decode('utf-8')


def fetch_app_key(appToken, wrapKey, appId, dataSize) -> str:
    """
    Fetches the application key share from Phase KMS.

    Args:
        appToken (str): The token for the application to retrieve the key for.
        wrapKey (str): The key used to encrypt the wrapped key share.
        appId (str): The identifier for the application to retrieve the key for.
        dataSize (int): The size of the data to be decrypted.

    Returns:
        str: The unwrapped share obtained by decrypting the wrapped key share.
    Raises:
        Exception: If the app token is invalid (HTTP status code 404).
    """

    headers = {
        "Authorization": f"Bearer {appToken}",
        "EventType": "decrypt",
        "PhaseNode": f"python:{__version__}",
        "PhSize": f"{dataSize}"
    }

    response = requests.get(f"{PHASE_KMS_URI}{appId}", headers=headers)

    if response.status_code == 404:
        raise Exception("Invalid app token")
    else:
        json_data = response.json()
        wrapped_key_share = json_data["wrappedKeyShare"]
        unwrapped_key = decrypt_raw(bytes.fromhex(
            wrapped_key_share), bytes.fromhex(wrapKey))
        return unwrapped_key.decode("utf-8")
