#!/usr/bin/env python3
import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SECRET = bytes.fromhex('8cefeb7b3b274629be7df7d453a64c29')
FOOTER_MAGIC = bytes.fromhex('00c0ffee')
MTS_NAME = 'DIR_842R7_RT8197G_MTS'


def die(msg: str) -> None:
    raise SystemExit(f'ERROR: {msg}')


def sh(cmd, **kw):
    print('+', ' '.join(map(str, cmd)))
    subprocess.check_call(list(map(str, cmd)), **kw)


def be16_sum(buf: bytes) -> int:
    if len(buf) & 1:
        buf += b'\x00'
    return sum(struct.unpack('>' + 'H' * (len(buf) // 2), buf)) & 0xffff


def be16_fixup_for_zero_sum(buf: bytes) -> bytes:
    # Return a 16-bit BE word which makes sum(buf + word) == 0.
    return ((-be16_sum(buf)) & 0xffff).to_bytes(2, 'big')


def parse_cr6b(d: bytes):
    if len(d) < 0x20 or d[:4] != b'cr6b':
        die('input is not a cr6b firmware')
    start, burn, length = struct.unpack('>III', d[4:16])
    return start, burn, length


def sqfs_info(sq: bytes):
    if sq[:4] != b'hsqs':
        die('not a SquashFS image')
    vals = struct.unpack('<I I I I I H H H H H H Q Q Q Q Q Q Q Q', sq[:96])
    labels = ['magic','inodes','mkfs_time','block_size','fragments','compression','block_log','flags','no_ids','s_major','s_minor','root_inode','bytes_used','id_table_start','xattr_id_table_start','inode_table_start','directory_table_start','fragment_table_start','lookup_table_start']
    return dict(zip(labels, vals))


def check_footer(d: bytes) -> bool:
    return len(d) >= 20 and d[-4:] == FOOTER_MAGIC and d[-20:-4] == hashlib.md5(SECRET + d[:-20]).digest()


def sign_footer(d: bytes) -> bytes:
    body = d[:-20]
    return body + hashlib.md5(SECRET + body).digest() + FOOTER_MAGIC


def patch_version(root: Path):
    version = root / 'VERSION'
    if not version.exists():
        die('/VERSION not found after unsquashfs')
    text = version.read_text(errors='replace')
    # Replace base name with MTS variant
    text = text.replace('DIR_842R7_RT8197G', 'DIR_842R7_RT8197G_MTS')
    text = text.replace('DIR_842R7_RT8197G_MTS', 'DIR_842R7_RT8197G')  # ensure idempotency
    version.write_text(text)
    print('patched /VERSION:')
    print(version.read_text())


def main():
    ap = argparse.ArgumentParser(description='Build MTS-accepted transition firmware from vanilla D-Link DIR-842R7 cr6b update')
    ap.add_argument('input', help='official D-Link web update .bin')
    ap.add_argument('-o', '--output', required=True, help='output transition .bin')
    ap.add_argument('--keep-workdir', action='store_true')
    ap.add_argument('--workdir')
    ap.add_argument('--mksquashfs-extra', nargs=argparse.REMAINDER, help='extra args passed to mksquashfs after default options')
    args = ap.parse_args()

    if not shutil.which('unsquashfs'):
        die('unsquashfs not found; install squashfs-tools')
    if not shutil.which('mksquashfs'):
        die('mksquashfs not found; install squashfs-tools')

    inp = Path(args.input).resolve()
    out = Path(args.output).resolve()
    d = inp.read_bytes()
    start, burn, length = parse_cr6b(d)
    print(f'input size     : 0x{len(d):x}')
    print(f'cr6b start/burn: 0x{start:08x}/0x{burn:08x}')
    print(f'cr6b len       : 0x{length:x}')
    print(f'footer ok      : {check_footer(d)}')

    sq_off = d.find(b'hsqs')
    if sq_off < 0:
        die('SquashFS magic hsqs not found')
    info = sqfs_info(d[sq_off:])
    sq_bytes = info['bytes_used']
    print(f'squashfs offset: 0x{sq_off:x}')
    print(f'squashfs used  : 0x{sq_bytes:x}')
    print(f'block size     : 0x{info["block_size"]:x}')
    print(f'compression    : {info["compression"]} (4 means xz)')
    print(f'flags          : 0x{info["flags"]:x}')

    work = Path(args.workdir).resolve() if args.workdir else Path(tempfile.mkdtemp(prefix='dir842r7-transition-'))
    work.mkdir(parents=True, exist_ok=True)
    sq_orig = work / 'orig.sqfs'
    sq_new = work / 'new.sqfs'
    root = work / 'rootfs'
    if root.exists():
        shutil.rmtree(root)
    sq_orig.write_bytes(d[sq_off:sq_off + sq_bytes])

    sh(['unsquashfs', '-no-progress', '-d', root, sq_orig])
    patch_version(root)

    # Original superblock: block_size=131072, compression=xz, no xattrs, export table present.
    # Do not use -no-fragments; /VERSION and many small files should go to fragments normally.
    cmd = [
        'mksquashfs', root, sq_new,
        '-noappend',
        '-comp', 'xz',
        '-b', str(info['block_size']),
        '-no-xattrs',
        '-all-root',
    ]
    if args.mksquashfs_extra:
        cmd.extend(args.mksquashfs_extra)
    sh(cmd)

    new_sq = sq_new.read_bytes()
    new_info = sqfs_info(new_sq)
    new_used = new_info['bytes_used']
    print(f'new squashfs file size : 0x{len(new_sq):x}')
    print(f'new squashfs bytes_used: 0x{new_used:x}')

    # Keep the original web-update total length. The rootfs area is replaced by new_sqfs,
    # then padded with 0xff up to the old squashfs end. If the rebuilt image is larger,
    # stop instead of silently changing partition geometry.
    if len(new_sq) > sq_bytes:
        die(f'rebuilt SquashFS is larger than original: 0x{len(new_sq):x} > 0x{sq_bytes:x}. Try different mksquashfs options or full length-changing rebuild.')

    out_d = bytearray(d)
    out_d[sq_off:sq_off + sq_bytes] = new_sq + b'\xff' * (sq_bytes - len(new_sq))

    # Outer checksum location is two bytes just before MD5 footer in these images.
    # Recompute it over [0x10 .. checksum_word_offset), then write fixup word.
    checksum_off = len(out_d) - 22
    out_d[checksum_off:checksum_off+2] = b'\x00\x00'
    out_d[checksum_off:checksum_off+2] = be16_fixup_for_zero_sum(bytes(out_d[0x10:checksum_off]))

    # Preserve cr6b length/total size; resign footer.
    out_bytes = sign_footer(bytes(out_d))
    if be16_sum(out_bytes[0x10:checksum_off+2]) != 0:
        die('internal checksum failed after rebuild')
    if not check_footer(out_bytes):
        die('footer signing failed')
    out.write_bytes(out_bytes)
    print(f'wrote: {out}')
    print(f'size : 0x{len(out_bytes):x}')
    print(f'sha256: {hashlib.sha256(out_bytes).hexdigest()}')
    print('workdir:', work)
    if not args.keep_workdir and not args.workdir:
        shutil.rmtree(work)


if __name__ == '__main__':
    main()
