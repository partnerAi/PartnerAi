import os
import sys
import json
import zlib
import argparse
import logging
import tempfile
import platform
from getpass import getpass
from typing import Tuple, Optional, List, Dict, Any
from pathlib import Path
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("Error: Missing 'cryptography' module. Install it by running:")
    print("  pip install cryptography")
    print("Or, if using Anaconda:")
    print("  conda install cryptography")
    sys.exit(1)
import hashlib
import base64
import hmac

# Configuration
DEFAULT_CONFIG = {
    "PBKDF2_ITERATIONS": 600_000,
    "DKLEN": 64,
    "SALT_LENGTH": 16,
    "HMAC_ALGORITHM": "sha256",
    "FILE_VERSION": b"\x01\x01",  # v1.1
    "COMPRESS": True,
}
SUPPORTED_HMAC_ALGOS = {"sha256", "sha512"}

# Logging
logger = logging.getLogger("fort_knox")

def configure_logging(verbose: bool, debug: bool) -> None:
    """Configure logger with stdout handler."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose or debug else logging.INFO)

def debug_environment() -> None:
    """Log system and Python environment details for debugging."""
    logger.debug(f"Python version: {sys.version}")
    logger.debug(f"Platform: {platform.platform()}")
    logger.debug(f"Current directory: {os.getcwd()}")
    logger.debug(f"Python executable: {sys.executable}")
    logger.debug(f"Path environment: {os.environ.get('PATH', 'Not set')}")

# Crypto Utilities
def validate_password_strength(password: str) -> None:
    """Ensure password meets security requirements."""
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        raise ValueError("Password needs both uppercase and lowercase letters")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must include at least one digit")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        raise ValueError("Password requires at least one special character")

def derive_keys(password: str, salt: bytes, iterations: int, dklen: int, hmac_algo: str) -> Tuple[Fernet, bytes]:
    """Derive Fernet and HMAC keys via PBKDF2-HMAC."""
    if not password:
        raise ValueError("Password cannot be empty")
    validate_password_strength(password)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("Salt must be at least 8 bytes")
    if dklen < 32:
        raise ValueError("Derived key length must be at least 32 bytes")
    if iterations < 100_000:
        raise ValueError("PBKDF2 iterations must be at least 100,000")
    
    key_material = hashlib.pbkdf2_hmac(hmac_algo, password.encode("utf-8"), salt, iterations, dklen)
    fernet_key = base64.urlsafe_b64encode(key_material[:32])
    return Fernet(fernet_key), key_material[32:]

def compute_hmac(data: bytes, key: bytes, algo: str) -> bytes:
    """Calculate HMAC digest."""
    return hmac.new(key, data, getattr(hashlib, algo)).digest()

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare bytes in constant time."""
    return hmac.compare_digest(a, b)

# File Format
def build_header(version: bytes, salt: bytes, hmac_digest: bytes, hmac_algo: str, compress: bool) -> bytes:
    """Build file header with version, algo, compression, salt, and HMAC."""
    algo_bytes = hmac_algo.encode("ascii")
    return b"".join([
        version,
        bytes([len(algo_bytes)]),
        algo_bytes,
        b"\x01" if compress else b"\x00",
        salt,
        hmac_digest
    ])

def parse_file_header(data: bytes, config: Dict[str, Any]) -> Tuple[bytes, bytes, bytes, bytes, str, bool]:
    """Parse file header, returning (version, salt, hmac, encrypted_data, hmac_algo, compress)."""
    version_len = len(config["FILE_VERSION"])
    salt_len = config["SALT_LENGTH"]
    
    pos = version_len
    if len(data) < pos + 1:
        raise ValueError("File too short to read HMAC algorithm length")
    algo_len = int.from_bytes(data[pos:pos + 1], "big")
    pos += 1
    if algo_len > 32 or len(data) < pos + algo_len + 1:
        raise ValueError("Invalid HMAC algorithm length")
    hmac_algo = data[pos:pos + algo_len].decode("ascii")
    if hmac_algo not in SUPPORTED_HMAC_ALGOS:
        raise ValueError(f"Unsupported HMAC algorithm in file: {hmac_algo}")
    pos += algo_len
    compress = data[pos:pos + 1] == b"\x01"
    pos += 1
    
    hmac_len = hashlib.new(hmac_algo).digest_size
    if len(data) < pos + salt_len + hmac_len + 1:
        raise ValueError("File too short or corrupted")
    
    salt = data[pos:pos + salt_len]
    hmac_value = data[pos + salt_len:pos + salt_len + hmac_len]
    encrypted_data = data[pos + salt_len + hmac_len:]
    return version, salt, hmac_value, encrypted_data, hmac_algo, compress

# Core Functions
def encrypt_data(password: str, payload: Any, out_path: str, config: Dict[str, Any]) -> None:
    """Encrypt and save JSON payload to file."""
    out_path = str(Path(out_path).resolve())  # Resolve absolute path
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    
    try:
        if config["COMPRESS"]:
            payload_bytes = zlib.compress(payload_bytes)
            logger.debug("Payload compressed")
    except zlib.error as e:
        logger.warning(f"Compression failed ({e}); disabling compression")
        config["COMPRESS"] = False

    salt = os.urandom(config["SALT_LENGTH"])
    fernet, hmac_key = derive_keys(password, salt, config["PBKDF2_ITERATIONS"], config["DKLEN"], config["HMAC_ALGORITHM"])
    logger.debug("Keys derived")

    encrypted = fernet.encrypt(payload_bytes)
    mac = compute_hmac(salt + encrypted, hmac_key, config["HMAC_ALGORITHM"])
    header = build_header(config["FILE_VERSION"], salt, mac, config["HMAC_ALGORITHM"], config["COMPRESS"])
    full_blob = header + encrypted

    tmp_dir = os.path.dirname(out_path)
    Path(tmp_dir).mkdir(parents=True, exist_ok=True)
    
    # Check disk space (rough estimate)
    statvfs = os.statvfs(tmp_dir) if hasattr(os, 'statvfs') else None
    if statvfs and statvfs.f_bavail * statvfs.f_frsize < len(full_blob) * 2:
        raise OSError("Insufficient disk space for writing file")
    
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_fortknox_", dir=tmp_dir)
    try:
        with os.fdopen(fd, "wb") as tmpf:
            tmpf.write(full_blob)
            tmpf.flush()
            os.fsync(tmpf.fileno())
        os.replace(tmp_path, out_path)
        logger.info(f"Data saved to '{out_path}'. Size: {os.path.getsize(out_path)} bytes")
    except (OSError, PermissionError) as e:
        logger.error(f"Cannot write file '{out_path}' (check permissions or disk space): {e}")
        raise
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError as e:
                logger.warning(f"Failed to delete temp file '{tmp_path}': {e}")

def decrypt_data(password: str, in_path: str, config: Dict[str, Any]) -> Any:
    """Decrypt and parse JSON payload from file."""
    in_path = str(Path(in_path).resolve())
    try:
        with open(in_path, "rb") as f:
            blob = f.read()
    except (OSError, PermissionError) as e:
        raise FileNotFoundError(f"Cannot read file '{in_path}' (check permissions or path): {e}")
    
    version, salt, hmac_value, encrypted_data, hmac_algo, compress = parse_file_header(blob, config)
    if version != config["FILE_VERSION"]:
        raise ValueError(f"Unsupported file version: {version.hex()}")

    fernet, hmac_key = derive_keys(password, salt, config["PBKDF2_ITERATIONS"], config["DKLEN"], hmac_algo)
    if not constant_time_compare(compute_hmac(salt + encrypted_data, hmac_key, hmac_algo), hmac_value):
        raise ValueError("HMAC verification failed: file tampered or wrong password")

    decrypted = fernet.decrypt(encrypted_data)
    try:
        payload_bytes = zlib.decompress(decrypted) if compress else decrypted
    except zlib.error as e:
        raise ValueError("Decompression failed: file corrupted") from e
    
    try:
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError("Invalid JSON payload") from e

# Mock Data
def get_mock_whistleblower_data() -> List[Dict[str, Any]]:
    """Generate mock whistleblower data."""
    keywords = {"whistleblower", "ethics", "safety", "fraud", "integrity"}
    mock_reviews = [
        {"review": "AI safety concerns ignored, violating integrity.", "keywords": ["safety", "integrity"]},
        {"review": "Ethics violations reported, management silent.", "keywords": ["ethics", "whistleblower"]},
        {"review": "No whistleblower protection in place.", "keywords": ["whistleblower"]},
        {"review": "Financial audit manipulated (fraud).", "keywords": ["ethics", "fraud"]},
        {"review": "Reactor 5 risk analysis ignored, safety issue.", "keywords": ["safety"]},
        {"review": "Unrelated operational review.", "keywords": []}
    ]
    results = [
        {"review": r["review"], "keywords": [k for k in r["keywords"] if k in keywords]}
        for r in mock_reviews if any(k in r["keywords"] for k in keywords)
    ]
    logger.info(f"Filtered {len(results)} reviews from {len(mock_reviews)}")
    return results

# CLI
def build_config_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    """Parse CLI arguments into configuration."""
    cfg = DEFAULT_CONFIG.copy()
    if args.iterations is not None:
        if (iterations := int(args.iterations)) < 100_000:
            raise ValueError("PBKDF2 iterations must be at least 100,000")
        cfg["PBKDF2_ITERATIONS"] = iterations
    if args.dklen is not None:
        if (dklen := int(args.dklen)) < 32:
            raise ValueError("Derived key length must be at least 32 bytes")
        cfg["DKLEN"] = dklen
    if args.salt_length is not None:
        if (salt_length := int(args.salt_length)) < 8:
            raise ValueError("Salt length must be at least 8 bytes")
        cfg["SALT_LENGTH"] = salt_length
    if args.hmac_algo not in SUPPORTED_HMAC_ALGOS:
        raise ValueError(f"HMAC algorithm must be one of: {', '.join(SUPPORTED_HMAC_ALGOS)}")
    cfg["HMAC_ALGORITHM"] = args.hmac_algo
    cfg["COMPRESS"] = not args.no_compress
    return cfg

def safe_getpass(prompt: str) -> str:
    """Get password, falling back to input() if getpass fails."""
    try:
        return getpass(prompt, stream=sys.stderr)
    except (EOFError, KeyboardInterrupt, Exception) as e:
        logger.debug(f"getpass failed ({e}); using standard input")
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            logger.error("Password input interrupted")
            sys.exit(3)

def main(argv: Optional[List[str]] = None) -> int:
    """Execute Fort Knox CLI."""
    parser = argparse.ArgumentParser(description="Fort Knox: Secure data encryption/decryption")
    parser.add_argument("action", choices=["encrypt", "decrypt", "info"], help="Action: encrypt, decrypt, or info")
    parser.add_argument("--file", "-f", default="whistleblower_data.json.enc", help="Input/output file path")
    parser.add_argument("--iterations", "-i", type=int, help=f"PBKDF2 iterations (default: {DEFAULT_CONFIG['PBKDF2_ITERATIONS']}, min: 100,000)")
    parser.add_argument("--dklen", type=int, help=f"Key length in bytes (default: {DEFAULT_CONFIG['DKLEN']}, min: 32)")
    parser.add_argument("--salt-length", type=int, help=f"Salt length in bytes (default: {DEFAULT_CONFIG['SALT_LENGTH']}, min: 8)")
    parser.add_argument("--hmac-algo", default=DEFAULT_CONFIG["HMAC_ALGORITHM"], choices=list(SUPPORTED_HMAC_ALGOS), help="HMAC algorithm")
    parser.add_argument("--no-compress", action="store_true", help="Disable compression")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with environment info")
    
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code

    configure_logging(args.verbose, args.debug)
    if args.debug:
        debug_environment()
    
    try:
        cfg = build_config_from_args(args)
        hashlib.new(cfg["HMAC_ALGORITHM"])
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return 2
    except Exception:
        logger.error(f"Invalid HMAC algorithm: {cfg['HMAC_ALGORITHM']}")
        return 2

    try:
        if args.action == "encrypt":
            password = safe_getpass("Enter encryption password: ")
            if not password:
                logger.error("Password cannot be empty")
                return 3
            try:
                validate_password_strength(password)
            except ValueError as e:
                logger.error(f"Password validation failed: {e}")
                return 3
            encrypt_data(password, get_mock_whistleblower_data(), args.file, cfg)
            return 0

        elif args.action == "decrypt":
            password = safe_getpass("Enter decryption password: ")
            if not password:
                logger.error("Password cannot be empty")
                return 3
            payload = decrypt_data(password, args.file, cfg)
            logger.info("\n[FORT KNOX: DATA RETRIEVED]\n" + "-" * 70)
            for item in payload:
                print(f"Review: {item.get('review')}")
                print(f"Keywords: {', '.join(item.get('keywords', []))}\n" + "-" * 50)
            logger.info("Decryption successful")
            return 0

        else:  # info
            in_path = str(Path(args.file).resolve())
            try:
                with open(in_path, "rb") as f:
                    blob = f.read()
            except (OSError, PermissionError) as e:
                logger.error(f"Cannot read file '{in_path}' (check permissions or path): {e}")
                return 4
            version, salt, hmac_value, encrypted_data, hmac_algo, compress = parse_file_header(blob, cfg)
            logger.info(f"File: {in_path}")
            logger.info(f"Version: {version.hex()}")
            logger.info(f"HMAC Algorithm: {hmac_algo}")
            logger.info(f"Compressed: {compress}")
            logger.info(f"Salt (hex): {salt.hex()}")
            logger.info(f"HMAC (hex): {hmac_value.hex()}")
            logger.info(f"Encrypted payload size: {len(encrypted_data)} bytes")
            return 0

    except FileNotFoundError as e:
        logger.error(str(e))
        return 4
    except InvalidToken:
        logger.error("Decryption failed: incorrect password or corrupted file")
        return 5
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        return 6
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.debug:
            logger.exception("Stack trace:")
        return 1

if __name__ == "__main__":
    sys.exit(main())