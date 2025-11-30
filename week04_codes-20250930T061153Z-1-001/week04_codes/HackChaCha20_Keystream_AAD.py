#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Hackstreamcipher_rev.py
# Revised interactive keystream extractor for ChaCha20-Poly1305 classrooms.
# - Accepts known plaintext and a ciphertext blob (which may be AAD||CT||TAG).
# - Optionally accepts an AAD file to strip from the front; otherwise tries heuristic alignment.
# - Strips trailing 16-byte Poly1305 tag when appropriate (heuristic or forced).
# - Computes KS = PT XOR CT_segment and uses it to decrypt other blobs (stripping their AAD if provided).
#
# Usage: run interactively, or provide files on the command line.
# This file was produced as a focused, clearer replacement for previous versions.
import argparse, sys
from pathlib import Path

TAG_LEN = 16

def readb(p: Path) -> bytes:
    return p.read_bytes()

def writeb(p: Path, data: bytes):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)

def strip_trailing_tag_if_present(b: bytes) -> bytes:
    if len(b) >= TAG_LEN:
        return b[:-TAG_LEN]
    return b

def compute_keystream_segment(pt: bytes, blob: bytes, aad: bytes|None=None, force_strip_tag: bool=False, auto_align: bool=False):
    # Remove AAD prefix if provided
    if aad is not None:
        if not blob.startswith(aad):
            print(f"[WARN] Provided AAD is not a prefix of blob; stripping by length anyway.", file=sys.stderr)
        blob_ct_region = blob[len(aad):]
    else:
        blob_ct_region = blob

    # Heuristic: decide whether to strip trailing tag
    if force_strip_tag:
        ct = strip_trailing_tag_if_present(blob_ct_region)
    else:
        # If blob length equals pt_len + TAG_LEN => likely CT||TAG
        if len(blob_ct_region) == len(pt) + TAG_LEN:
            ct = strip_trailing_tag_if_present(blob_ct_region)
        elif len(blob_ct_region) == len(pt):
            ct = blob_ct_region
        else:
            # ambiguous: try to auto-align if requested, else prefer no-strip but warn
            if auto_align and len(blob_ct_region) >= len(pt):
                # attempt to locate pt within ct region
                pos = blob_ct_region.find(pt)
                if pos != -1:
                    ct = blob_ct_region if len(blob_ct_region) == len(pt) else blob_ct_region
                    # we will handle alignment in caller by returning pos
                else:
                    # fallback to stripping if long enough
                    ct = strip_trailing_tag_if_present(blob_ct_region) if len(blob_ct_region) >= TAG_LEN else blob_ct_region
                    print("[WARN] ambiguous blob length; attempted heuristics (may be wrong).", file=sys.stderr)
            else:
                # default: if blob longer than pt and at least TAG_LEN, strip tag; otherwise treat raw
                if len(blob_ct_region) >= len(pt) + TAG_LEN:
                    ct = strip_trailing_tag_if_present(blob_ct_region)
                else:
                    ct = blob_ct_region

    # If lengths match, use direct XOR
    if len(pt) == len(ct):
        return 0, bytes(a ^ b for a, b in zip(pt, ct)), ct  # offset 0, keystream segment, ct used
    # If PT shorter and present inside CT, find alignment
    if len(pt) < len(ct):
        pos = ct.find(pt)
        if pos != -1:
            ks_seg = bytes(a ^ b for a, b in zip(pt, ct[pos:pos+len(pt)]))
            return pos, ks_seg, ct
        else:
            # if auto_align not possible, align at start
            ks_seg = bytes(a ^ b for a, b in zip(pt, ct[:len(pt)]))
            return 0, ks_seg, ct
    # PT longer than CT -> error
    raise ValueError(f"PT longer than CT region: PT={len(pt)} CT={len(ct)}")

def interactive():
    print("Hackstreamcipher_rev — interactive keystream extractor (AAD-aware)\n")
    # Known pair input
    known_pt_path = input("Path to known plaintext file: ").strip()
    known_blob_path = input("Path to known ciphertext blob (may be AAD||CT||TAG): ").strip()
    aad_file = input("Optional AAD file to strip from start of blob (press Enter to skip): ").strip()
    force_strip = input("Force strip trailing 16-byte tag? (y/N): ").strip().lower() == 'y'
    auto_align = input("Enable auto-align (search PT inside CT if PT shorter)? (y/N): ").strip().lower() == 'y'

    try:
        pt = readb(Path(known_pt_path))
        blob = readb(Path(known_blob_path))
        aad = readb(Path(aad_file)) if aad_file else None
    except Exception as e:
        print("Error reading files:", e); return

    try:
        offset, ks_seg, ct_used = compute_keystream_segment(pt, blob, aad=aad, force_strip_tag=force_strip, auto_align=auto_align)
    except Exception as e:
        print("Error computing keystream:", e); return

    print(f"Keystream segment recovered: len={len(ks_seg)} bytes at offset {offset}")
    preview = ks_seg[:64].hex()
    print("Preview (first 64 bytes hex):", preview)

    if input("Save keystream to file? (y/N): ").strip().lower() == 'y':
        outp = input("Keystream output path (default merged.ks): ").strip() or "merged.ks"
        writeb(Path(outp), ks_seg)
        print("Saved", outp)

    # Decrypt other blobs
    while True:
        other = input("Path to victim blob to decrypt (or empty to exit): ").strip()
        if not other:
            break
        other_aad = input("Optional AAD file for victim (press Enter to skip): ").strip()
        try:
            other_blob = readb(Path(other))
            other_aad_bytes = readb(Path(other_aad)) if other_aad else None
        except Exception as e:
            print("Error reading victim files:", e); continue
        # Remove aad prefix if given
        if other_aad_bytes is not None:
            other_ct_region = other_blob[len(other_aad_bytes):]
        else:
            other_ct_region = other_blob
        # Strip trailing tag if seems present (heuristic)
        if len(other_ct_region) >= len(ks_seg) + TAG_LEN:
            other_ct = strip_trailing_tag_if_present(other_ct_region)
        else:
            other_ct = other_ct_region
        # Use keystream (only available segment) at alignment offset (we assume same keystream alignment)
        # If offset > 0, attempt to decrypt starting at that offset
        start = offset
        if start + len(ks_seg) > len(other_ct):
            # Trim keystream to available ciphertext length at start
            usable = max(0, len(other_ct) - start)
            ks_for_use = ks_seg[:usable]
        else:
            ks_for_use = ks_seg
        # XOR
        decrypted = bytearray(len(other_ct))
        for i in range(len(ks_for_use)):
            decrypted[start + i] = other_ct[start + i] ^ ks_for_use[i]
        # Save decrypted plaintext (CT-length)
        outname = input("Output filename for decrypted plaintext (default recovered.pt): ").strip() or "recovered.pt"
        writeb(Path(outname), bytes(decrypted))
        print(f"Saved decrypted output (CT-length) to {outname}")

def main():
    ap = argparse.ArgumentParser(description="Hackstreamcipher_rev - keystream extractor (AAD-aware)")
    ap.add_argument("--pt", help="known plaintext file")
    ap.add_argument("--blob", help="known ciphertext blob (may be AAD||CT||TAG)")
    ap.add_argument("--aad", help="optional aad file to strip from front of blob")
    ap.add_argument("--force-strip", action="store_true", help="force strip trailing 16B tag")
    ap.add_argument("--auto-align", action="store_true", help="search for PT inside CT if PT shorter")
    ap.add_argument("--decrypt", nargs="*", help="victim blobs to decrypt (optional AAD files handled interactively)")
    ap.add_argument("--out-keystream", help="file to write the recovered keystream segment")
    args = ap.parse_args()

    if not args.pt or not args.blob:
        return interactive()

    try:
        pt = readb(Path(args.pt))
        blob = readb(Path(args.blob))
        aad = readb(Path(args.aad)) if args.aad else None
        offset, ks_seg, ct_used = compute_keystream_segment(pt, blob, aad=aad, force_strip_tag=args.force_strip, auto_align=args.auto_align)
    except Exception as e:
        print("Error:", e); sys.exit(1)

    print(f"Recovered keystream len={len(ks_seg)} offset={offset}")
    if args.out_keystream:
        writeb(Path(args.out_keystream), ks_seg); print("Wrote keystream to", args.out_keystream)

    # decrypt victims if provided
    if args.decrypt:
        for v in args.decrypt:
            try:
                other_blob = readb(Path(v))
            except Exception as e:
                print("Error reading victim:", v, e); continue
            # simple decrypt same as interactive: assume same offset and strip tag heuristically
            other_ct_region = other_blob
            if len(other_ct_region) >= len(ks_seg) + TAG_LEN:
                other_ct = strip_trailing_tag_if_present(other_ct_region)
            else:
                other_ct = other_ct_region
            start = offset
            if start + len(ks_seg) > len(other_ct):
                usable = max(0, len(other_ct) - start)
                ks_for_use = ks_seg[:usable]
            else:
                ks_for_use = ks_seg
            decrypted = bytearray(len(other_ct))
            for i in range(len(ks_for_use)):
                decrypted[start + i] = other_ct[start + i] ^ ks_for_use[i]
            outp = Path(v).with_suffix(".pt.bin")
            writeb(outp, bytes(decrypted))
            print("Decrypted", v, "->", outp)

if __name__ == "__main__":
    main()
