
import functools
from typing import Tuple
from nacl.bindings import crypto_kx_server_session_keys, crypto_kx_client_session_keys, crypto_kx_keypair, crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt, randombytes, crypto_secretbox_NONCEBYTES
import re
import requests
from dataclasses import dataclass


@dataclass
class AppSecret:
    prefix: str
    pss_version: str
    app_token: str
    keyshare0: str
    keyshare1_unwrap_key: str

PHASE_KMS_URI = "https://kms.phase.dev/"
LIB_VERSION = "0.0.1"

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
    nonce = randombytes(crypto_secretbox_NONCEBYTES)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)
    return ciphertext + nonce

def decrypt_raw(ct, key) -> bytes:
    """
    Decrypts a ciphertext using a key.

    Args:
        ct (str): The ciphertext to decrypt, as a hexadecimal string.
        key (str): The key to use for decryption, as a hexadecimal string.

    Returns:
        bytes: The plaintext obtained by decrypting the ciphertext with the key.
    """
    nonce = bytes.fromhex(ct)[-24:]
    ciphertext = bytes.fromhex(ct)[:-24]
    key_bytes = bytes.fromhex(key)

    plaintext_bytes = crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, None, nonce, key_bytes)

    return plaintext_bytes


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
        "PhaseNode": f"python:{LIB_VERSION}",
        "PhSize": f"{dataSize}"
    }

    response = requests.get(f"{PHASE_KMS_URI}{appId}", headers=headers)


    if response.status_code == 404:
        raise Exception("Invalid app token")
    else:
        json_data = response.json()
        wrapped_key_share = json_data["wrappedKeyShare"]
        unwrapped_key = decrypt_raw(wrapped_key_share, wrapKey)
        return unwrapped_key.decode("utf-8")

class Phase:
    _app_id = ''
    _app_pub_key = ''
    _app_secret = None
    
    def __init__(self, app_id, app_secret):
        app_id_pattern = re.compile(r"^phApp:v(\d+):([a-fA-F0-9]{64})$")
        app_secret_pattern = re.compile(r"^pss:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64,128}):([a-fA-F0-9]{64})$")

        if not app_id_pattern.match(app_id):
            raise ValueError("Invalid Phase APP_ID")
        
        if not app_secret_pattern.match(app_secret):
            raise ValueError("Invalid Phase APP_SECRET")
        
        self._app_id = app_id
        self._app_pub_key = app_id.split(':')[2]
        app_secret_segments = app_secret.split(':')

        self._app_secret = AppSecret(*app_secret_segments)


    def encrypt(self, plaintext, tag="") -> str | None:
        """
        Encrypts a plaintext string.

        Args:
            plaintext (str): The plaintext to encrypt.
            tag (str, optional): A tag to include in the encrypted message. The tag will not be encrypted.

        Returns:
            str: The encrypted message, formatted as a string that includes the public key used for the one-time keypair, 
            the ciphertext, and the tag. Returns `None` if an error occurs.
        """
        try:
            one_time_keypair = random_key_pair()
            symmetric_keys = crypto_kx_client_session_keys(one_time_keypair[0], one_time_keypair[1], bytes.fromhex(self._app_pub_key))

            ciphertext = encrypt_raw(plaintext.encode("utf-8"), symmetric_keys[1]).hex()
            pub_key = one_time_keypair[0].hex()

            return f"ph:{LIB_VERSION}:{pub_key}:{ciphertext}:{tag}"
        except ValueError as err:
            print(err)
            return None
    
    def decrypt(self, phase_ciphertext) -> str | None:
        """
        Decrypts a Phase ciphertext string.

        Args:
            phase_ciphertext (str): The encrypted message to decrypt.

        Returns:
            str: The decrypted plaintext as a string. Returns `None` if an error occurs.

        Raises:
            ValueError: If the ciphertext is not in the expected format (e.g. wrong prefix, wrong number of fields).
        """
        try:  
            [prefix, version, client_pub_key_hex, ct, tag] = phase_ciphertext.split(':') 
            if prefix != 'ph' or  len(phase_ciphertext.split(':')) != 5:
                raise ValueError('Ciphertext is invalid')
            client_pub_key = bytes.fromhex(client_pub_key_hex)

            keyshare1 = fetch_app_key(self._app_secret.app_token, self._app_secret.keyshare1_unwrap_key, self._app_id, len(ct)/2)

            app_priv_key = reconstruct_secret([self._app_secret.keyshare0, keyshare1])
                      
            session_keys = crypto_kx_server_session_keys(bytes.fromhex(self._app_pub_key), bytes.fromhex(app_priv_key), client_pub_key)
            
            plaintext_bytes = decrypt_raw(ct, session_keys[0].hex())

            return plaintext_bytes.decode("utf-8") 
            
        except ValueError as err:
            print(err)
            return None
