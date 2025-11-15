"""
pCloud crypto support for encrypted filenames and folder keys.
Translated from pCloud's Go crypto implementation.
"""

import base64
import hmac
import struct
import hashlib
from hashlib import sha1, sha512
from typing import Tuple, Optional

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA


class FolderKey:
    """Represents a decrypted folder Content Encryption Key (CEK)."""
    
    def __init__(self, type_: int, flags: int, aes_key: bytes, hmac_key: bytes):
        self.type = type_
        self.flags = flags
        self.aes_key = aes_key
        self.hmac_key = hmac_key


class ParsedPrivateKey:
    """Represents a parsed pCloud private key blob."""
    
    def __init__(self, type_: int, flags: int, salt: bytes, key: bytes):
        self.type = type_
        self.flags = flags
        self.salt = salt
        self.key = key


class ParsedPublicKey:
    """Represents a parsed pCloud public key blob."""
    
    def __init__(self, type_: bytes, flags: bytes, key: bytes):
        self.type = type_
        self.flags = flags
        self.key = key


class KeyPair:
    """Represents a decrypted RSA key pair for pCloud crypto operations."""
    
    def __init__(
        self,
        private_key: ParsedPrivateKey,
        public_key: ParsedPublicKey,
        rsa_priv: RSA.RsaKey,
        rsa_pub: RSA.RsaKey
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.rsa_priv = rsa_priv
        self.rsa_pub = rsa_pub
    
    def decrypt_folder_key(self, encrypted_key: str) -> FolderKey:
        """Decrypt a folder's Content Encryption Key (CEK) using RSA-OAEP (SHA-1)."""
        if not self.rsa_priv:
            raise ValueError("Private key not loaded")
        
        enc = base64_url_decode(encrypted_key)
        cipher = PKCS1_OAEP.new(self.rsa_priv, hashAlgo=SHA1)
        dec = cipher.decrypt(enc)
        
        if len(dec) < 41:
            raise ValueError("Decrypted folder key too short")
        
        type_ = struct.unpack('<I', dec[0:4])[0]
        flags = struct.unpack('<I', dec[4:8])[0]
        aes_key = dec[8:40]
        hmac_key = dec[40:]
        
        return FolderKey(type_, flags, aes_key, hmac_key)


# Helper functions

def align_to_16(data: bytes) -> bytes:
    """Return a zero-padded copy of data aligned to a 16-byte boundary."""
    if len(data) % 16 == 0:
        return data
    aligned = bytearray(((len(data) // 16) + 1) * 16)
    aligned[:len(data)] = data
    return bytes(aligned)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte slices and return a new bytes object."""
    if len(a) != len(b):
        raise ValueError("xor_bytes: lengths must match")
    return bytes(x ^ y for x, y in zip(a, b))


def remove_padding(data: bytes) -> bytes:
    """Trim trailing zero bytes."""
    end = len(data)
    while end > 0 and data[end - 1] == 0:
        end -= 1
    return data[:end]


def base32_encode(data: bytes) -> str:
    """Encode bytes to Base32 without padding and convert to uppercase."""
    enc = base64.b32encode(data).decode('ascii')
    return enc.rstrip('=').upper()


def base32_decode(s: str) -> bytes:
    """Decode a Base32 string (case-insensitive, no padding required)."""
    s = s.upper()
    # Add padding if needed
    padding = (8 - len(s) % 8) % 8
    s += '=' * padding
    return base64.b32decode(s)


def base64_url_decode(s: str) -> bytes:
    """Decode a base64url string (no padding)."""
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))


def base64_url_encode(data: bytes) -> str:
    """Encode bytes to base64url (no padding)."""
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def swap32(n: int) -> int:
    """Reverse byte order of a 32-bit integer."""
    return (
        ((n >> 24) & 0xFF) |
        ((n >> 8) & 0xFF00) |
        ((n << 8) & 0xFF0000) |
        ((n << 24) & 0xFF000000)
    ) & 0xFFFFFFFF


def decrypt_pctr(block_cipher: AES, iv: bytes, src: bytes) -> bytes:
    """
    Implement pCloud's custom PCTR (parallel counter) mode for private key decryption.
    """
    dst = bytearray(len(src))
    counter = 0
    
    for i in range(0, len(src), 16):
        # Create counter block
        ctr = bytearray(16)
        struct.pack_into('>I', ctr, 0, swap32(counter))
        
        # XOR with IV
        ctr = bytes(ctr[j] ^ iv[j] for j in range(16))
        
        # Encrypt counter
        tmp = block_cipher.encrypt(ctr)
        
        # XOR with source
        end = min(i + 16, len(src))
        for j in range(i, end):
            dst[j] = tmp[j - i] ^ src[j]
        
        counter += 1
    
    return bytes(dst)


# Main crypto functions

def encrypt_filename(name: str, key: FolderKey) -> str:
    """
    Encrypt a filename using pCloud's encryption scheme.
    The encrypted name is Base32 encoded (upper-case, no padding).
    """
    name_bytes = name.encode('utf-8')
    aligned = align_to_16(name_bytes)
    
    if len(aligned) == 16:
        # Exactly one block: XOR with first 16 bytes of HMAC key, then AES-ECB
        xored = xor_bytes(aligned, key.hmac_key[:16])
        cipher = AES.new(key.aes_key, AES.MODE_ECB)
        out = cipher.encrypt(xored)
        return base32_encode(out)
    
    # Longer: HMAC of unpadded tail (after first 16), IV = first 16 bytes of HMAC
    data_after_first = aligned[16:]
    unpadded_after_first = remove_padding(data_after_first)
    
    h = hmac.new(key.hmac_key, unpadded_after_first, sha512)
    iv = h.digest()[:16]
    
    cipher = AES.new(key.aes_key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(aligned)
    
    return base32_encode(enc)


def decrypt_filename(encrypted_name: str, key: FolderKey) -> str:
    """Decrypt a Base32-encoded pCloud filename using the folder key."""
    enc_bytes = base32_decode(encrypted_name)
    cipher = AES.new(key.aes_key, AES.MODE_ECB)
    
    if len(enc_bytes) == 16:
        # One block: AES-ECB decrypt then XOR with first 16 of HMAC key, remove zero padding
        dec = cipher.decrypt(enc_bytes)
        xored = xor_bytes(dec, key.hmac_key[:16])
        unpadded = remove_padding(xored)
        result = unpadded.decode('utf-8')
        return result
    
    # Multi-block: first 16 bytes act as IV for the rest
    enc_iv = enc_bytes[:16]
    enc_data = enc_bytes[16:]
    
    cbc = AES.new(key.aes_key, AES.MODE_CBC, enc_iv)
    dec_data = cbc.decrypt(enc_data)
    
    unpadded = remove_padding(dec_data)
    
    # Compute HMAC to get IV for first block
    h = hmac.new(key.hmac_key, unpadded, sha512)
    iv = h.digest()[:16]
    
    cbc2 = AES.new(key.aes_key, AES.MODE_CBC, iv)
    first = cbc2.decrypt(enc_iv)
    
    result = first + unpadded
    
    # Validate UTF-8
    try:
        return result.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Decrypted text is not valid UTF-8 (likely wrong key)")


def parse_private_key(encoded_key: str) -> ParsedPrivateKey:
    """Parse a base64url-encoded pCloud private key blob."""
    data = base64_url_decode(encoded_key)
    
    if len(data) < 72:
        raise ValueError("Private key too short")
    
    type_ = struct.unpack('<I', data[0:4])[0]
    flags = struct.unpack('<I', data[4:8])[0]
    salt = data[8:72]
    key = data[72:]
    
    return ParsedPrivateKey(type_, flags, salt, key)


def parse_public_key(encoded_key: str) -> ParsedPublicKey:
    """Parse a base64url-encoded pCloud public key blob."""
    data = base64_url_decode(encoded_key)
    
    if len(data) < 8:
        raise ValueError("Public key too short")
    
    type_ = data[0:4]
    flags = data[4:8]
    key = data[8:]
    
    return ParsedPublicKey(type_, flags, key)


def decrypt_private_key(
    password: str,
    encoded_private_key: str,
    encoded_public_key: str
) -> KeyPair:
    """
    Decrypt the user's private key using their crypto password.
    PBKDF2-HMAC-SHA512 (20000 iters) derives AES key + IV; decrypt with custom PCTR.
    """
    priv_key = parse_private_key(encoded_private_key)
    pub_key = parse_public_key(encoded_public_key)
    
    # Derive AES key and IV using PBKDF2.
    derived = PBKDF2(
        password.encode('utf-8'),
        priv_key.salt,
        dkLen=48,
        count=20000,
        hmac_hash_module=SHA512
    )
    aes_key = derived[:32]
    iv = derived[32:48]
    
    # Decrypt private key using PCTR mode
    cipher = AES.new(aes_key, AES.MODE_ECB)
    dec = decrypt_pctr(cipher, iv, priv_key.key)
    
    if len(dec) < 4:
        raise ValueError("Decrypted key too short")
    
    # Trim ASN.1 to exact length based on DER header
    if dec[1] & 0x80 != 0:
        num_len = dec[1] & 0x7F
        key_len = 2 + num_len
        for i in range(num_len):
            key_len += dec[2 + i] << (8 * (num_len - 1 - i))
    else:
        key_len = dec[1] + 2
    
    if key_len > len(dec):
        key_len = len(dec)
    dec = dec[:key_len]
    
    # Parse RSA keys
    try:
        rsa_priv = RSA.import_key(dec)
    except Exception as e:
        raise ValueError(f"Failed to parse decrypted private key: {e}")
    
    try:
        rsa_pub = RSA.import_key(pub_key.key)
    except Exception as e:
        raise ValueError(f"Failed to parse public key: {e}")
    
    return KeyPair(priv_key, pub_key, rsa_priv, rsa_pub)
