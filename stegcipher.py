#!/usr/bin/env python3

import argparse
import sys
import os
from getpass import getpass
from pathlib import Path

from core import encrypt_for_steg, decrypt_from_steg
from img_steg.embed import embed_payload, extract_payload

PROJECT_NAME = "StegCipher"
AUTHOR = "SYN606"
OUTPUT_DIR = "output"


def encrypt_flow(text: str, image_path_str: str) -> None:
    img_path = Path(image_path_str)

    if not img_path.exists():
        raise RuntimeError(f"Image not found: {img_path}")

    password = getpass("Enter password: ").encode()
    confirm = getpass("Confirm password: ").encode()

    if password != confirm:
        raise RuntimeError("Passwords do not match")

    plaintext = text.encode("utf-8")
    payload = encrypt_for_steg(plaintext, password)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    out_image = Path(OUTPUT_DIR) / f"{img_path.stem}_steg{img_path.suffix}"

    embed_payload(str(img_path), payload, str(out_image))

    print("[+] Encrypted & hidden successfully")
    print(f"[+] Output image: {out_image}")


def decrypt_flow(image_path_str: str) -> None:
    img_path = Path(image_path_str)

    if not img_path.exists():
        raise RuntimeError(f"Image not found: {img_path}")

    password = getpass("Enter password: ").encode()

    # Upper bound; real length validated by format layer
    raw_payload = extract_payload(str(img_path), payload_size_bytes=8192)

    plaintext = decrypt_from_steg(raw_payload, password)

    print("\n[+] Hidden message recovered:\n")
    print(plaintext.decode("utf-8", errors="replace"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegcipher",
        description=(f"{PROJECT_NAME} — Secure Image Steganography Tool\n"
                     f"Developed by {AUTHOR}"),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt text and hide it inside an image",
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Extract and decrypt hidden text from an image",
    )
    parser.add_argument(
        "-t",
        "--text",
        help="Text to hide (required for --encrypt)",
    )
    parser.add_argument(
        "-i",
        "--image",
        help="Input image path",
    )

    return parser


def main() -> None:
    parser = build_parser()

    # Show help if nothing is entered
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Prevent ambiguous usage
    if args.encrypt and args.decrypt:
        parser.error("Choose either --encrypt or --decrypt, not both")

    try:
        if args.encrypt:
            if not args.text or not args.image:
                raise RuntimeError("--encrypt requires --text and --image")
            encrypt_flow(args.text, args.image)

        elif args.decrypt:
            if not args.image:
                raise RuntimeError("--decrypt requires --image")
            decrypt_flow(args.image)

        else:
            parser.print_help()

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
