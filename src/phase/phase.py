import re
from nacl.bindings import crypto_kx_server_session_keys, crypto_kx_client_session_keys
from dataclasses import dataclass
from .utils.crypto import decrypt_b64, encrypt_b64, fetch_app_key, random_key_pair, reconstruct_secret
from .version import __version__, __ph_version__


@dataclass
class AppSecret:
    prefix: str
    pss_version: str
    app_token: str
    keyshare0: str
    keyshare1_unwrap_key: str


class Phase:
    _app_id = ''
    _app_pub_key = ''
    _app_secret = None

    def __init__(self, app_id, app_secret):
        app_id_pattern = re.compile(r"^phApp:v(\d+):([a-fA-F0-9]{64})$")
        app_secret_pattern = re.compile(
            r"^pss:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64,128}):([a-fA-F0-9]{64})$")

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
            symmetric_keys = crypto_kx_client_session_keys(
                one_time_keypair[0], one_time_keypair[1], bytes.fromhex(self._app_pub_key))
            ciphertext = encrypt_b64(plaintext, symmetric_keys[1])
            pub_key = one_time_keypair[0].hex()

            return f"ph:{__ph_version__}:{pub_key}:{ciphertext}:{tag}"
        except ValueError as err:
            raise ValueError(f"Something went wrong: {err}")

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
            [prefix, version, client_pub_key_hex, ct,
                tag] = phase_ciphertext.split(':')
            if prefix != 'ph' or len(phase_ciphertext.split(':')) != 5:
                raise ValueError('Ciphertext is invalid')
            client_pub_key = bytes.fromhex(client_pub_key_hex)

            keyshare1 = fetch_app_key(
                self._app_secret.app_token, self._app_secret.keyshare1_unwrap_key, self._app_id, len(ct)/2)

            app_priv_key = reconstruct_secret(
                [self._app_secret.keyshare0, keyshare1])

            session_keys = crypto_kx_server_session_keys(bytes.fromhex(
                self._app_pub_key), bytes.fromhex(app_priv_key), client_pub_key)

            plaintext = decrypt_b64(ct, session_keys[0].hex())

            return plaintext

        except ValueError as err:
            raise ValueError(f"Something went wrong: {err}")
