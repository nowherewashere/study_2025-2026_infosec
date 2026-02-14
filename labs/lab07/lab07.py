#!/usr/bin/env python3
import argparse
import secrets
import sys
from typing import List, Optional, Tuple


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if len(data) != len(key):
        raise ValueError("data and key must have the same length for one-time pad")
    return bytes(d ^ k for d, k in zip(data, key))


def parse_hex(hex_text: str) -> bytes:
    compact = "".join(hex_text.split())
    if len(compact) % 2 != 0:
        raise ValueError("hex input must have an even number of digits")
    return bytes.fromhex(compact)


def decode_text(data: bytes, encoding: str) -> str:
    return data.decode(encoding, errors="replace")


def encode_text(text: str, encoding: str) -> bytes:
    return text.encode(encoding)


def encrypt(plaintext: str, key_bytes: bytes, encoding: str) -> str:
    plaintext_bytes = encode_text(plaintext, encoding)
    ciphertext = xor_bytes(plaintext_bytes, key_bytes)
    return ciphertext.hex()


def decrypt(ciphertext_hex: str, key_bytes: bytes, encoding: str) -> str:
    ciphertext = parse_hex(ciphertext_hex)
    plaintext_bytes = xor_bytes(ciphertext, key_bytes)
    return decode_text(plaintext_bytes, encoding)


def derive_key(ciphertext_hex: str, plaintext: str, encoding: str) -> bytes:
    ciphertext = parse_hex(ciphertext_hex)
    plaintext_bytes = encode_text(plaintext, encoding)
    return xor_bytes(ciphertext, plaintext_bytes)


def crib_search(
    ciphertext_hex: str,
    fragment: str,
    encoding: str,
    position: Optional[int],
) -> List[Tuple[int, bytes]]:
    ciphertext = parse_hex(ciphertext_hex)
    fragment_bytes = encode_text(fragment, encoding)

    if len(fragment_bytes) > len(ciphertext):
        raise ValueError("fragment is longer than ciphertext")

    results = []
    if position is not None:
        if position < 0 or position + len(fragment_bytes) > len(ciphertext):
            raise ValueError("position out of range for fragment length")
        key_fragment = xor_bytes(
            ciphertext[position : position + len(fragment_bytes)],
            fragment_bytes,
        )
        results.append((position, key_fragment))
        return results

    for offset in range(0, len(ciphertext) - len(fragment_bytes) + 1):
        key_fragment = xor_bytes(
            ciphertext[offset : offset + len(fragment_bytes)],
            fragment_bytes,
        )
        results.append((offset, key_fragment))
    return results


def format_key_fragment(key_fragment: bytes, encoding: str) -> str:
    hex_value = key_fragment.hex()
    try:
        decoded = key_fragment.decode(encoding)
        is_printable = decoded.isprintable()
    except UnicodeDecodeError:
        decoded = ""
        is_printable = False
    if is_printable:
        return f"{hex_value} ({decoded})"
    return hex_value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="One-time pad (gamma) encrypt/decrypt and crib tools."
    )
    parser.add_argument(
        "--encoding",
        default="utf-8",
        help="text encoding for plaintext/key (default: utf-8)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="encrypt plaintext with key",
    )
    encrypt_parser.add_argument("--plaintext", required=True, help="plaintext string")
    encrypt_key_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    encrypt_key_group.add_argument("--key", help="key string")
    encrypt_key_group.add_argument("--key-hex", help="key in hex")

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="decrypt ciphertext (hex) with key",
    )
    decrypt_parser.add_argument("--ciphertext-hex", required=True, help="ciphertext hex")
    decrypt_key_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    decrypt_key_group.add_argument("--key", help="key string")
    decrypt_key_group.add_argument("--key-hex", help="key in hex")

    key_parser = subparsers.add_parser(
        "key",
        help="derive full key from ciphertext (hex) and full plaintext",
    )
    key_parser.add_argument("--ciphertext-hex", required=True, help="ciphertext hex")
    key_parser.add_argument("--plaintext", required=True, help="plaintext string")

    crib_parser = subparsers.add_parser(
        "crib",
        help="derive key fragments for a plaintext fragment (crib)",
    )
    crib_parser.add_argument("--ciphertext-hex", required=True, help="ciphertext hex")
    crib_parser.add_argument("--fragment", required=True, help="plaintext fragment")
    crib_parser.add_argument(
        "--position",
        type=int,
        default=None,
        help="start position for the fragment (0-based)",
    )

    return parser


def resolve_key_bytes(key_text: Optional[str], key_hex: Optional[str], encoding: str) -> bytes:
    if key_hex is not None:
        return parse_hex(key_hex)
    if key_text is not None:
        return encode_text(key_text, encoding)
    raise ValueError("key is required")


def main() -> int:
    if len(sys.argv) == 1:
        phrase = "С Новым Годом, друзья!"
        key_bytes = secrets.token_bytes(len(phrase.encode("utf-8")))
        ciphertext_hex = encrypt(phrase, key_bytes, "utf-8")
        decrypted = decrypt(ciphertext_hex, key_bytes, "utf-8")
        derived_key = derive_key(ciphertext_hex, phrase, "utf-8")

        print("Открытый текст:")
        print(phrase)
        print()
        print("Случайный ключ (hex):")
        print(key_bytes.hex())
        print()
        print("Шифротекст (hex):")
        print(ciphertext_hex)
        print()
        print("Расшифровка:")
        print(decrypted)
        print()
        print("Подобранный ключ (hex):")
        print(derived_key.hex())
        return 0

    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            key_bytes = resolve_key_bytes(args.key, args.key_hex, args.encoding)
            ciphertext_hex = encrypt(args.plaintext, key_bytes, args.encoding)
            print(ciphertext_hex)
            return 0

        if args.command == "decrypt":
            key_bytes = resolve_key_bytes(args.key, args.key_hex, args.encoding)
            plaintext = decrypt(args.ciphertext_hex, key_bytes, args.encoding)
            print(plaintext)
            return 0

        if args.command == "key":
            key_bytes = derive_key(args.ciphertext_hex, args.plaintext, args.encoding)
            print(format_key_fragment(key_bytes, args.encoding))
            return 0

        if args.command == "crib":
            results = crib_search(
                args.ciphertext_hex,
                args.fragment,
                args.encoding,
                args.position,
            )
            for offset, key_fragment in results:
                formatted = format_key_fragment(key_fragment, args.encoding)
                print(f"{offset}: {formatted}")
            return 0

    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
