"""
Config Encryption at Rest
~~~~~~~~~~~~~~~~~~~~~~~~~

Encrypts / decrypts the CleanShift agent config file using
Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).

Encrypted files are prefixed with ``CSENC1:`` followed by the
Fernet token.  Plaintext files remain valid YAML and are
auto-detected by :func:`is_encrypted`.

Key storage
-----------
The Fernet key is persisted in a separate file (default
``/root/.cleanshift/.config_key``) with 0600 permissions.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from typing import Optional

import yaml
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("cleanshift.config_crypto")

# ─── Constants ──────────────────────────────────────────────────────

MAGIC_PREFIX = b"CSENC1:"
"""Byte prefix written before the Fernet token in encrypted config files."""

DEFAULT_KEY_PATH = Path("/root/.cleanshift/.config_key")
"""Default location for the Fernet key file."""


# ─── Exceptions ─────────────────────────────────────────────────────

class ConfigKeyMissing(Exception):
    """Raised when the encryption key file cannot be found."""

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        super().__init__(
            f"Config encryption key not found at {key_path}. "
            "Please re-register this agent from the CleanShift dashboard "
            "or run: cleanshift config encrypt"
        )


class ConfigDecryptionError(Exception):
    """Raised when decryption of the config file fails."""

    def __init__(self, reason: str = "") -> None:
        detail = f" ({reason})" if reason else ""
        super().__init__(
            f"Failed to decrypt config file{detail}. "
            "The encryption key may have changed or the file is corrupt. "
            "Please re-register this agent from the CleanShift dashboard."
        )


# ─── Key Management ────────────────────────────────────────────────

def generate_config_key() -> bytes:
    """Generate a new Fernet key (URL-safe base64, 32 bytes).

    Returns
    -------
    bytes
        A freshly generated Fernet key.
    """
    return Fernet.generate_key()


def _write_key_file(key: bytes, key_path: Path) -> None:
    """Atomically create a key file with owner-only permissions.

    Uses ``O_CREAT | O_WRONLY | O_EXCL`` to prevent race conditions.
    If the file already exists this is a no-op (the existing key is kept).
    """
    key_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd = os.open(
            str(key_path),
            os.O_CREAT | os.O_WRONLY | os.O_EXCL,
            stat.S_IRUSR | stat.S_IWUSR,  # 0600
        )
    except FileExistsError:
        logger.debug("Key file already exists at %s — keeping existing key", key_path)
        return

    try:
        os.write(fd, key)
    finally:
        os.close(fd)

    logger.info("Encryption key written to %s", key_path)


def _read_key_file(key_path: Path) -> bytes:
    """Read the Fernet key from *key_path*.

    Raises
    ------
    ConfigKeyMissing
        If *key_path* does not exist.
    """
    if not key_path.exists():
        raise ConfigKeyMissing(key_path)

    key = key_path.read_bytes().strip()
    return key


# ─── Encrypt / Decrypt Primitives ──────────────────────────────────

def encrypt_config(config_dict: dict, key: bytes) -> bytes:
    """Encrypt a config dict to a Fernet-encrypted blob.

    The config is first serialised to JSON (compact), then encrypted.

    Parameters
    ----------
    config_dict : dict
        The full agent configuration dictionary.
    key : bytes
        A valid Fernet key.

    Returns
    -------
    bytes
        The encrypted payload (**without** the ``CSENC1:`` prefix).
    """
    plaintext = json.dumps(config_dict, separators=(",", ":")).encode("utf-8")
    f = Fernet(key)
    return f.encrypt(plaintext)


def decrypt_config(encrypted_data: bytes, key: bytes) -> dict:
    """Decrypt a Fernet blob back to a config dict.

    Parameters
    ----------
    encrypted_data : bytes
        The Fernet token bytes (without ``CSENC1:`` prefix).
    key : bytes
        The Fernet key used for encryption.

    Returns
    -------
    dict
        The decrypted configuration dictionary.

    Raises
    ------
    ConfigDecryptionError
        If decryption or deserialisation fails.
    """
    try:
        f = Fernet(key)
        plaintext = f.decrypt(encrypted_data)
        return json.loads(plaintext)
    except InvalidToken:
        raise ConfigDecryptionError("invalid token — wrong key or corrupted data")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigDecryptionError(f"payload deserialisation failed: {exc}")


# ─── File Detection ────────────────────────────────────────────────

def is_encrypted(config_path: Path) -> bool:
    """Check whether a config file is encrypted.

    Looks for the ``CSENC1:`` magic prefix at the start of the file.
    Returns ``False`` for non-existent files.
    """
    if not config_path.exists():
        return False

    with open(config_path, "rb") as fh:
        header = fh.read(len(MAGIC_PREFIX))

    return header == MAGIC_PREFIX


# ─── High-Level Disk I/O ───────────────────────────────────────────

def save_encrypted_config(
    config_dict: dict,
    config_path: Path,
    key_path: Path = DEFAULT_KEY_PATH,
) -> None:
    """Encrypt *config_dict* and write it to *config_path*.

    If the key file does not exist yet a new key is generated and
    written to *key_path*.

    Parameters
    ----------
    config_dict : dict
        Configuration dictionary to persist.
    config_path : Path
        Destination file for the encrypted config.
    key_path : Path
        Path to the Fernet key file.
    """
    # Ensure key exists
    if not key_path.exists():
        key = generate_config_key()
        _write_key_file(key, key_path)
    else:
        key = _read_key_file(key_path)

    token = encrypt_config(config_dict, key)

    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "wb") as fh:
        fh.write(MAGIC_PREFIX + token)

    # Restrict permissions — encrypted config still sensitive
    try:
        os.chmod(str(config_path), 0o600)
    except OSError:
        pass

    logger.info("Encrypted config saved to %s", config_path)


def load_encrypted_config(
    config_path: Path,
    key_path: Path = DEFAULT_KEY_PATH,
) -> dict:
    """Load and decrypt a config file from disk.

    Parameters
    ----------
    config_path : Path
        Path to the encrypted config file (must start with ``CSENC1:``).
    key_path : Path
        Path to the Fernet key file.

    Returns
    -------
    dict
        The decrypted configuration dictionary.

    Raises
    ------
    ConfigKeyMissing
        If the key file is absent.
    ConfigDecryptionError
        If decryption fails.
    FileNotFoundError
        If *config_path* does not exist.
    """
    key = _read_key_file(key_path)

    raw = config_path.read_bytes()
    if raw.startswith(MAGIC_PREFIX):
        token = raw[len(MAGIC_PREFIX):]
    else:
        # Shouldn't happen if caller checked is_encrypted(), but handle gracefully
        raise ConfigDecryptionError("file does not start with CSENC1: prefix")

    return decrypt_config(token, key)


# ─── Migration Helpers ──────────────────────────────────────────────

def migrate_plaintext_config(
    config_path: Path,
    key_path: Path = DEFAULT_KEY_PATH,
) -> bool:
    """Read a plaintext YAML config, encrypt it, and overwrite in place.

    Parameters
    ----------
    config_path : Path
        Path to the existing plaintext YAML config file.
    key_path : Path
        Path where the Fernet key will be stored.

    Returns
    -------
    bool
        ``True`` if migration succeeded, ``False`` otherwise.
    """
    if not config_path.exists():
        logger.warning("Config file not found at %s — nothing to migrate", config_path)
        return False

    if is_encrypted(config_path):
        logger.info("Config at %s is already encrypted — skipping migration", config_path)
        return True

    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            config_dict = yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.error("Failed to parse plaintext config at %s: %s", config_path, exc)
        return False

    try:
        save_encrypted_config(config_dict, config_path, key_path)
    except Exception as exc:
        logger.error("Failed to encrypt config: %s", exc)
        return False

    logger.info("Successfully migrated plaintext config at %s to encrypted format", config_path)
    return True


def decrypt_config_to_yaml(
    config_path: Path,
    key_path: Path = DEFAULT_KEY_PATH,
) -> str:
    """Decrypt an encrypted config and return it as a YAML string.

    Useful for the ``cleanshift config decrypt`` dev command.

    Parameters
    ----------
    config_path : Path
        Path to the encrypted config file.
    key_path : Path
        Path to the Fernet key file.

    Returns
    -------
    str
        The config as formatted YAML text.
    """
    config_dict = load_encrypted_config(config_path, key_path)
    return yaml.dump(config_dict, default_flow_style=False, sort_keys=False)
