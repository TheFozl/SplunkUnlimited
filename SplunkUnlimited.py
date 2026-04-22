#!/usr/bin/env python3
"""
SplunkUnlimited.py - splunkd file patcher to accept any license

Computes the SHA-256 hash of a splunkd binary, looks it up in the hash
database to retrieve the associated patch ID, then applies the
corresponding byte patch in-place (with automatic .bak backup).

Usage
-----
    python3 SplunkUnlimited.py <FILE> [options]

Exit codes
----------
    0  Success (or dry-run completed)
    1  File not found / unreadable
    2  Hash not found in hash database
    3  Patch ID not found in patch database
    4  Pattern not found in binary
    5  Pattern found multiple times, ambiguous, aborted
    6  Patch write failure (backup restored)
    7  Patch write failure (backup NOT restored)
"""

import argparse
import hashlib
import logging
import os
import shutil
import stat
import sys
import time
import traceback


HASH_ALGO = "sha256"
_CHUNK_SIZE = 65536
VERSION = "v1.0"


# ---------------------------------------------------------------------------
# Hash database
# ---------------------------------------------------------------------------
# Maps each known SHA-256 digest to its metadata and the patch to apply.
#
# Key   : SHA-256 hex digest of the original (unpatched) binary
# Value : dict
#     "version"  (str): human-readable version label
#     "platform" (str): target platform
#     "patch_id" (str): key into PATCH_DB below
# ---------------------------------------------------------------------------

HASH_DB = {
    "9e848e83d827b058db8cfba8e64494e8aef7849bf79d005a8c6fb50cd4857500": {
        "version":  "9.0.0",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "f962ba04475ddcaa843ae9fea1c98cca66f45cdaacfcca05b5ee6afcec30cc62": {
        "version":  "9.0.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "44fe04113ccb86487ff638a63dafcdce2bf227736d58cb6eac17bee5bd74fda5": {
        "version":  "9.0.2",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "b1d2892ee81b2d8990679ae387fc2891dad180cf102b984a055d52fbbd580746": {
        "version":  "9.0.3",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "9e55528c606faeee626d0ffdca2c058ef7e6ab0013a9749f1fc08f5af1639d0f": {
        "version":  "9.0.4",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "2d182f2760453aca807534127d6eb01256f25f917eeeb89536650677ba18f010": {
        "version":  "9.0.4.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "20e31ec64485353b185d18a87fd604cd3c87946bd0d6447c6b97a7dfe7c09e0b": {
        "version":  "9.0.5",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "28c36f7e3b742ff4294d2308d34ca1a503c168198e4271c0c990862655c0d499": {
        "version":  "9.0.5.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "23cc901275e6cd8ac80b1150b9698df640ee01ee6332fd8acaa5de566cec9382": {
        "version":  "9.0.6",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "c397ef0db043703263f676a2f8a5ce2c1fa1c772033115ef7eaac0e61e82018e": {
        "version":  "9.0.7",
        "platform": "linux64",
        "patch_id": "spl_lin64_2",
    },
    "2c394e0b5feb77468401d362a713caf5405f4998ce1705cb21d9a5cfbcac5bed": {
        "version":  "9.0.8",
        "platform": "linux64",
        "patch_id": "spl_lin64_2",
    },
    "2b5bca2b6c938bf0f7b3b2319f49297daf1c1503f591da6071889512cdfc67f1": {
        "version":  "9.0.9",
        "platform": "linux64",
        "patch_id": "spl_lin64_2",
    },
    "23ff4313ecc29d5325a869149898dbb39a78d039deb1f6415f5412da631f2244": {
        "version":  "9.0.10",
        "platform": "linux64",
        "patch_id": "spl_lin64_2",
    },
    "1376a93212b3c612ffa794b7d7fc29ef867cc285ba69ec27c350a16d1ca296e6": {
        "version":  "9.1.0",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "05ac43e801d4c900dacd34d1b06cc39423cb4e083a757cd576d7c32304ff1272": {
        "version":  "9.1.0.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "9f22d697bba58cf0fd6920da2cf25a7831981cdec05fc61223ad0c6fc714abb6": {
        "version":  "9.1.0.2",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "9f9dd53a2181fca756529cde935c4f7c8d7d165f0d6b6e642123170463d13b5f": {
        "version":  "9.1.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_1",
    },
    "0631751ca19d924059ad823e00ef2c9a66e2edbc8ceb6aaa780bf09288f4c002": {
        "version":  "9.1.2",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "81ca10c85ff39ed954820bec62d7d234ca001d2d8d3720cfd8bc04b04c2b1b7c": {
        "version":  "9.1.3",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "3b54f9634fac20d2777a183d9992ac335ef7f4d506da4ae69c1f77ca157d8487": {
        "version":  "9.1.4",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "9858d93c8409c219ff3b89ea6bcab992465c338a9d03f3ca883426490bdc548c": {
        "version":  "9.1.5",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "62f5acc719f98634fb4958efaab780a642644a4f1bcc22c229c00ce1f3c390b9": {
        "version":  "9.1.6",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "dc1ad9c84df4c2c3c45e15136f9a90b5766ea57768591a4f8f481b731517ae31": {
        "version":  "9.1.7",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "3c8247c53b236b7cdbd2a6fecb44c7249add8a11922f8ca99d562ab0f91cf695": {
        "version":  "9.1.8",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "29a7f5ea194cee4327337e414be14249ff0e275ca926204b5829bfa18154519d": {
        "version":  "9.1.9",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "ad9114ecda7b3a2cf48f292b77aff8a71971d08ec28484c03e9073959d8a9498": {
        "version":  "9.1.10",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "431a0fa83c4b2fec2ca494678e0025dbf33c49215fc45e5b72f4dd06021254e3": {
        "version":  "9.2.0",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "288b88978d7184bf1aab8d3b222855ede7b7f479df11abf603eedb14ab90bbd6": {
        "version":  "9.2.0.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "bdd8d584809ffc7f69624d56c98b13aab615c528dbb9bebf8e2460f8d5777bfe": {
        "version":  "9.2.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "cefa0fe22fb5e71d78620acf64b22862054136ed77ccd45a56094b4b7603135d": {
        "version":  "9.2.2",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "c997de69783b5bc08a87f47a74155fa1af1ac9eebcca11f63ccbf3415425c383": {
        "version":  "9.2.3",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "1e39e7df3146807f2dde9c380c7279074dd3c640fa6b0219d20556b36ec93b65": {
        "version":  "9.2.4",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "6260d654dd0e759f58664202467181d8463d8a8b5c6af38a1648499cbda7574a": {
        "version":  "9.2.5",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "5e35f1465dcba7bdf47d6792b1bb5aa38234742cbc15221f1110c6e5621a6a6c": {
        "version":  "9.2.6",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "37bcd00e6aaf75bbfe5b6c5a8f936d649026940607a95e15078cb8a1fbc3103d": {
        "version":  "9.2.7",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "b10e6d5ec888f8adda41837f8a3117fc315811c454d8d964e40235a1ffd2ded6": {
        "version":  "9.2.8",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "600f91a71bb78e57eca461b0b59fce423e1ac4eb30b1ae489df627a3b9f9f286": {
        "version":  "9.2.9",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "31d2bc92b6d962df1cfd91795137536ce6ad60a0918c8afa27668c104766801d": {
        "version":  "9.2.10",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "68a62a5fd7a2d355c9e000598daca8e3930e2099afbc4d280be063a234a3f805": {
        "version":  "9.2.11",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "5135a2185a4b098a085b4c8982fe1553db6269131a1dac1019d43273ee4c5277": {
        "version":  "9.2.12",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "adb82d54a6610c0762f20a7e5a02d4f616de1068dfd7749caa5fc1e582766c0a": {
        "version":  "9.3.0",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "20b84a61c8195e02c874c91ddf0f9d7a9b4a6cb05bca3e845dc50a74a7e11e9a": {
        "version":  "9.3.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "68cb94864b515d6540316b565b29853ca52039d607693ad90f8fa0c0566ebc77": {
        "version":  "9.3.2",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "b6dac23dd980ff9eeab3876b3d9de2c1c3ace4122c5a649df7ef5382fd41d757": {
        "version":  "9.3.3",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "ad5015173d2bc3a84843b4d1baa7f5ec7857246161cbeeeee11d853cdf7c25b1": {
        "version":  "9.3.4",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "0147af46e7f0eba3e27085ae41f3d5cd5142b3b4369c123a40bcc2f4a5b8888c": {
        "version":  "9.3.5",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "f3eabf314b0d11705bd67d6158537248f1a5c13e9671220643e655c7967ab82d": {
        "version":  "9.3.6",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "261f1ff4215025bd5286001a9c961a564741a17be429fab6dcd8ebb406701949": {
        "version":  "9.3.7",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "fcc87acf941010f1f388065d6fed28cccd70e2920fb76e6c1631f33bfd8dcc6e": {
        "version":  "9.3.8",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "320e6a6b3488aeb57414b7254adfe89d2a5a11a63bcfb6542c29ce0694ce3992": {
        "version":  "9.3.9",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "ff589a3f30ca464a59379ae4c56e5d4d4e2aca2a49ed11ab08dd04a2124e6286": {
        "version":  "9.3.10",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "4f51d025dc74401c0626660795c4c49081bbc5c53f04503a71427f834e0dfc3e": {
        "version":  "9.3.11",
        "platform": "linux64",
        "patch_id": "spl_lin64_3",
    },
    "bcdcbf8fa6c0cfc1ef13cc159d54c5f5adffea38f5d87096797badaf33bc7aa6": {
        "version":  "9.4.0",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "98a0f7b143f5191af5fef58f51ae46325ee50994bf4a2ed93b8f14cac1c314cc": {
        "version":  "9.4.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "bfeeb1ef7840e0d3454b3d15d8f06ba47ea4cd83537899d0657ee9e805ae29d2": {
        "version":  "9.4.2",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "978981b9191694b8530b7d6f9e7388ec2c894fc0f67f7f0343f0fbd638b24bd0": {
        "version":  "9.4.3",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "1dc97a70b33f965f8f516ba9b8e575b9ecc4ea6c46ac4fb649aabb02c458aef0": {
        "version":  "9.4.4",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "9aa077229c7e80524d5626b2b8d41fa6b8989277a1eff4aa83ec6b93d2e02d63": {
        "version":  "9.4.5",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "70c7f133f1547c9d7f9ae2fa4ad9a3f3b9b9ea04680d7bfa9e107671ef491dee": {
        "version":  "9.4.6",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "eb32b4ba09f68e82f25f5fbf5f58b6fbcd21998e7d02ef48b6a3319ef781c824": {
        "version":  "9.4.7",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "b2041117bb520ceb2097e1d7cfc57f47361099af8a8f25483e84501f64a3ce2a": {
        "version":  "9.4.8",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "5774c4bcddf2bfb90ab2987af999b4b54979c96357dcfc18ec6c3b30a47d8f40": {
        "version":  "9.4.9",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "e171dfcf638a3e8f78f8d435038c4196fc854e35c686522044bc8c26d72ab63e": {
        "version":  "9.4.10",
        "platform": "linux64",
        "patch_id": "spl_lin64_4",
    },
    "c40c37cf5dd171861ff91a2abc2bc4a134a392997940aa6fc9b9dedbd8ce8dfb": {
        "version":  "10.0.0",
        "platform": "linux64",
        "patch_id": "spl_lin64_5",
    },
    "4e45fc33ab13d0e06f2dce38abc30575afdfce5aefc7786e1e4d5f315e83dc60": {
        "version":  "10.0.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_5",
    },
    "e57b3234f340c9d59778aeffcf2708afbcb60198d671dad4ea58b294244bf31e": {
        "version":  "10.0.2",
        "platform": "linux64",
        "patch_id": "spl_lin64_5",
    },
    "9bb9a17d4f4f27b0e1e819dd6cdea3ab5915e514b5eb9e8796a74972097764ed": {
        "version":  "10.0.3",
        "platform": "linux64",
        "patch_id": "spl_lin64_5",
    },
    "f65eaff6fcba4f19702ff489eb560ce298073517133e308e0bb5de4fba93fba0": {
        "version":  "10.0.4",
        "platform": "linux64",
        "patch_id": "spl_lin64_5",
    },
    "6d8ddbf8044824518a2055d612f1343b207199ccf9ba8ac4c91da1e313f5b7aa": {
        "version":  "10.0.5",
        "platform": "linux64",
        "patch_id": "spl_lin64_5",
    },
    "228bbf46fe72d54145c44362d4a80910b2080fde332ed00341e15f3add400854": {
        "version":  "10.2.0",
        "platform": "linux64",
        "patch_id": "spl_lin64_6",
    },
    "8e1ed022ba609b4ea409e04b8f939d098b33d1d0f78c606a006b4d0e0861de99": {
        "version":  "10.2.1",
        "platform": "linux64",
        "patch_id": "spl_lin64_6",
    },
    "28cd1a779f114be9d2da2991f06cdcff2f652150eb09fed72e2e3fc067a57909": {
        "version":  "10.2.2",
        "platform": "linux64",
        "patch_id": "spl_lin64_6",
    },
}


# ---------------------------------------------------------------------------
# Patch database
# ---------------------------------------------------------------------------
# Maps a patch ID to the byte-level transformation to apply.
#
# Key   : patch_id string (must match values used in HASH_DB)
# Value : dict
#     "description" (str):  human-readable label shown at runtime
#     "pattern"     (list): byte sequence to locate  (list of int 0-255)
#     "replace"     (list): replacement bytes, same length as pattern
# ---------------------------------------------------------------------------

PATCH_DB = {
    "spl_lin64_1": {
        "description": "splunkd (linux64), 9.0.0 to 9.0.6 and 9.1.0 to 9.1.1",
        "pattern": [0xE8, 0x2B, 0xC3, 0xFF, 0xFF, 0x84, 0xC0, 0x0F, 0x84],
        "replace": [0xE8, 0x2B, 0xC3, 0xFF, 0xFF, 0x84, 0xC0, 0x0F, 0x85],
    },
    "spl_lin64_2": {
        "description": "splunkd (linux64), 9.0.7 to 9.0.10",
        "pattern": [0xE8, 0xA3, 0xC3, 0xFF, 0xFF, 0x84, 0xC0, 0x0F, 0x84],
        "replace": [0xE8, 0xA3, 0xC3, 0xFF, 0xFF, 0x84, 0xC0, 0x0F, 0x85],
    },
    "spl_lin64_3": {
        "description": "splunkd (linux64), 9.1.2 to 9.3.11",
        "pattern": [0xE8, 0x43, 0xC3, 0xFF, 0xFF, 0x84, 0xC0, 0x0F, 0x84],
        "replace": [0xE8, 0x43, 0xC3, 0xFF, 0xFF, 0x84, 0xC0, 0x0F, 0x85],
    },
    "spl_lin64_4": {
        "description": "splunkd (linux64), 9.4.0 to 9.4.10",
        "pattern": [0xE8, 0xDF, 0xD4, 0xFF, 0xFF, 0x84, 0xC0, 0x0F, 0x84],
        "replace": [0xE8, 0xDF, 0xD4, 0xFF, 0xFF, 0x84, 0xC0, 0x0F, 0x85],
    },
    "spl_lin64_5": {
        "description": "splunkd (linux64), 10.0.0 to 10.0.5",
        "pattern": [0xE8, 0x0F, 0xEA, 0xFF, 0xFF, 0x84, 0xC0, 0x75],
        "replace": [0xE8, 0x0F, 0xEA, 0xFF, 0xFF, 0x84, 0xC0, 0x74],
    },
    "spl_lin64_6": {
        "description": "splunkd (linux64), 10.2.0 to 10.2.2",
        "pattern": [0xE8, 0x6D, 0x49, 0x04, 0x00, 0x84, 0xC0, 0x75],
        "replace": [0xE8, 0x6D, 0x49, 0x04, 0x00, 0x84, 0xC0, 0x74],
    },
}


def setup_logging(verbose: bool) -> None:
    """Configure the root logger."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="[%(levelname)-7s] %(message)s",
        level=level,
    )


def compute_hash(filepath: str, algo: str = HASH_ALGO) -> str:
    """Return the lowercase hex digest of *filepath* using *algo*.
    Raises
    ------
    OSError
        If the file cannot be opened or read.
    ValueError
        If *algo* is not supported by :mod:`hashlib`.
    """
    h = hashlib.new(algo)
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def find_pattern(data: bytes, pattern: bytes) -> list:
    """Return all starting offsets of *pattern* inside *data*."""
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def bytes_to_hex(data: bytes) -> str:
    """Return a space-separated uppercase hex string."""
    return " ".join(f"{b:02X}" for b in bytearray(data))


def create_backup(filepath: str) -> str:
    """Copy *filepath* to *filepath*.*timestamp*.bak and return the backup path.
    Raises
    ------
    OSError
        If the copy operation fails.
    """
    timestamp = int(time.time())
    backup_path = f"{filepath}.{timestamp}.bak"

    if os.path.exists(backup_path):
        os.chmod(backup_path, stat.S_IWRITE | stat.S_IREAD)

    shutil.copy2(filepath, backup_path)
    return backup_path

def restore_backup(backup_path: str, filepath: str) -> int:
    """Restore backup, returns 6 on success, 7 on failure."""
    log = logging.getLogger(__name__)
    log.info("Restoring backup...")

    try:
        shutil.copy2(backup_path, filepath)
        log.info("Backup restored successfully.")
        return 6
    except OSError as restore_exc:
        log.critical(
            "Backup restoration also failed: %s\n"
            "  The file may be in a corrupted state!\n"
            "  Backup is available at: %s",
            restore_exc,
            backup_path,
        )
        log.debug(traceback.format_exc())
        return 7


def apply_patch(filepath: str, offset: int, pattern: bytes, replace: bytes) -> None:
    """Overwrite bytes at *offset* in *filepath* with *replace*.
    Raises
    ------
    RuntimeError
        If the bytes at *offset* no longer match *pattern*.
    OSError
        If the file cannot be opened or written.
    """
    original_mode = stat.S_IMODE(os.stat(filepath).st_mode)
    os.chmod(filepath, original_mode | stat.S_IWRITE | stat.S_IREAD)

    with open(filepath, "r+b") as fh:
        fh.seek(offset)
        current = fh.read(len(pattern))
        if current != pattern:
            os.chmod(filepath, original_mode)
            raise RuntimeError(
                f"Bytes at offset 0x{offset:08X} do not match expected pattern.\n"
                f"  Expected : {bytes_to_hex(pattern)}\n"
                f"  Found    : {bytes_to_hex(current)}"
            )
        fh.seek(offset)
        fh.write(replace)
        fh.flush()
        os.fsync(fh.fileno())

    os.chmod(filepath, original_mode)


def run(filepath: str, dry_run: bool = False, force_mode: bool = False) -> int:
    """Execute the workflow.
    Returns
    -------
    int
        Exit code (0 = success, see module docstring for details).
    """
    log = logging.getLogger(__name__)

    log.info("""

  █████████            ████                        █████      █████  █████            ████   ███                   ███   █████                 █████
 ███░░░░░███          ░░███                       ░░███      ░░███  ░░███            ░░███  ░░░                   ░░░   ░░███                 ░░███
░███    ░░░  ████████  ░███  █████ ████ ████████   ░███ █████ ░███   ░███  ████████   ░███  ████  █████████████   ████  ███████    ██████   ███████
░░█████████ ░░███░░███ ░███ ░░███ ░███ ░░███░░███  ░███░░███  ░███   ░███ ░░███░░███  ░███ ░░███ ░░███░░███░░███ ░░███ ░░░███░    ███░░███ ███░░███
 ░░░░░░░░███ ░███ ░███ ░███  ░███ ░███  ░███ ░███  ░██████░   ░███   ░███  ░███ ░███  ░███  ░███  ░███ ░███ ░███  ░███   ░███    ░███████ ░███ ░███
 ███    ░███ ░███ ░███ ░███  ░███ ░███  ░███ ░███  ░███░░███  ░███   ░███  ░███ ░███  ░███  ░███  ░███ ░███ ░███  ░███   ░███ ███░███░░░  ░███ ░███
░░█████████  ░███████  █████ ░░████████ ████ █████ ████ █████ ░░████████   ████ █████ █████ █████ █████░███ █████ █████  ░░█████ ░░██████ ░░████████
 ░░░░░░░░░   ░███░░░  ░░░░░   ░░░░░░░░ ░░░░ ░░░░░ ░░░░ ░░░░░   ░░░░░░░░   ░░░░ ░░░░░ ░░░░░ ░░░░░ ░░░░░ ░░░ ░░░░░ ░░░░░    ░░░░░   ░░░░░░   ░░░░░░░░
             ░███
             █████
            ░░░░░

Version: %s

""", VERSION)

    if force_mode:
        log.warning(
            "Force-mode enabled: only proceed if you know what you are doing.")

    if not os.path.isfile(filepath):
        log.error("File not found: %s", filepath)
        return 1

    log.info("Computing %s hash...", HASH_ALGO.upper())
    try:
        digest = compute_hash(filepath)
    except OSError as exc:
        log.error("Cannot read file: %s", exc)
        log.debug(traceback.format_exc())
        return 1

    log.debug("Hash      : %s", digest)
    log.debug("File      : %s", os.path.abspath(filepath))

    log.info("Detecting the Splunk version...")
    hash_entry = HASH_DB.get(digest)
    if hash_entry is None:
        if not force_mode:
            log.error(
                "Hash not found in the database, your version is not supported or the file has already been patched.\n"
                "  Hash : %s\n"
                "  Tip  : run with --list to see supported binaries.",
                digest,
            )
            return 2

        log.warning("Hash not found in database. Entering force-mode...")
        log.warning("")
        entries = list(HASH_DB.items())
        log.warning("Supported versions:")
        for idx, (h, e) in enumerate(entries, 1):
            log.warning("  [%3d] splunkd %-10s  (%s)", idx,
                        e.get("version", "N/A"), e.get("platform", "N/A"))
        log.warning("")
        while True:
            try:
                choice = input(
                    f"Select a version [1-{len(entries)}]: ").strip()
                if not choice.isdigit() or not 1 <= int(choice) <= len(entries):
                    print(
                        f"  Please enter a number between 1 and {len(entries)}.")
                    continue
                hash_entry = entries[int(choice) - 1][1]
                log.warning("Selected: splunkd %s (%s)", hash_entry.get(
                    "version", "N/A"), hash_entry.get("platform", "N/A"))
                log.warning("")
                break
            except (KeyboardInterrupt, EOFError):
                print("")
                log.error("Aborted by user.")
                return 2

    version = hash_entry.get("version",  "N/A")
    platform = hash_entry.get("platform", "N/A")
    patch_id = hash_entry["patch_id"]

    log.info("Supported Splunk version found!")
    log.info("Version   : %s", version)
    log.info("Platform  : %s", platform)
    log.debug("Patch ID  : %s", patch_id)

    patch_entry = PATCH_DB.get(patch_id)
    if patch_entry is None:
        log.error(
            "Patch ID '%s' not found, patch database may be inconsistent.",
            patch_id,
        )
        return 3

    description = patch_entry.get("description", "N/A")
    pattern_bytes = bytes(bytearray(patch_entry["pattern"]))
    replace_bytes = bytes(bytearray(patch_entry["replace"]))

    log.info("Patch     : %s", description)
    log.debug("Pattern   : %s (%d bytes)", bytes_to_hex(
        pattern_bytes), len(pattern_bytes))
    log.debug("Replace   : %s (%d bytes)", bytes_to_hex(
        replace_bytes), len(replace_bytes))
    log.info("")

    if len(pattern_bytes) != len(replace_bytes):
        log.error(
            "Patch database integrity error: pattern length (%d) differs from replace length (%d).",
            len(pattern_bytes),
            len(replace_bytes),
        )
        return 3

    log.info("Loading splunkd...")
    try:
        with open(filepath, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        log.error("Cannot read file: %s", exc)
        log.debug(traceback.format_exc())
        return 1

    offsets = find_pattern(data, pattern_bytes)

    if not offsets:
        log.error(
            "Pattern not found in file, binary may already be patched or does not match the expected layout.\n"
            "  Pattern : %s",
            bytes_to_hex(pattern_bytes),
        )
        return 4

    if len(offsets) > 1:
        log.error(
            "Pattern found %d time(s), ambiguous location, aborting to prevent corruption.\n"
            "  Offsets : %s",
            len(offsets),
            ", ".join(f"0x{o:08X}" for o in offsets),
        )
        return 5

    offset = offsets[0]
    log.info("Pattern found at offset 0x%08X", offset)

    if dry_run:
        log.info("")
        log.info("=== DRY-RUN (no changes written) ===")
        log.info("  Offset  : 0x%08X", offset)
        log.info("  Before  : %s", bytes_to_hex(pattern_bytes))
        log.info("  After   : %s", bytes_to_hex(replace_bytes))
        return 0

    log.info("Creating backup...")
    try:
        backup_path = create_backup(filepath)
    except OSError as exc:
        log.error("Cannot create backup: %s", exc)
        log.debug(traceback.format_exc())
        return 1

    log.info("Backup    : %s", backup_path)

    log.info("Applying patch...")
    try:
        apply_patch(filepath, offset, pattern_bytes, replace_bytes)
    except KeyboardInterrupt:
        log.error("\nAborted by user.")
        sys.exit(restore_backup(backup_path, filepath))
    except (RuntimeError, OSError) as exc:
        log.error("Patch failed: %s", exc)
        log.debug(traceback.format_exc())
        return restore_backup(backup_path, filepath)

    log.info("")
    log.info("Patch applied successfully!")
    log.debug("  Offset  : 0x%08X", offset)
    log.debug("  Before  : %s", bytes_to_hex(pattern_bytes))
    log.debug("  After   : %s", bytes_to_hex(replace_bytes))
    log.info("")
    log.info("You can now add the Unlimited license, enjoy.")

    return 0


def cmd_list_db() -> None:
    """Print the full patch database (hash DB + patch DB) to stdout."""
    count = len(PATCH_DB)
    print(f"Patch database: {count} entr{'y' if count == 1 else 'ies'}:")
    for pid, pentry in PATCH_DB.items():
        pat = bytes(bytearray(pentry.get("pattern", [])))
        rep = bytes(bytearray(pentry.get("replace", [])))
        print()
        print(f"  Patch ID    : {pid}")
        print(f"  Description : {pentry.get('description', 'N/A')}")
        print(f"  Pattern     : {bytes_to_hex(pat)}")
        print(f"  Replace     : {bytes_to_hex(rep)}")
        print(f"  Size        : {len(pat)} byte(s)")

    print()
    count = len(HASH_DB)
    print(f"Hash database: {count} entr{'y' if count == 1 else 'ies'}:")
    for digest, hentry in HASH_DB.items():
        print()
        print(f"  Hash        : {digest}")
        print(f"  Version     : {hentry.get('version',  'N/A')}")
        print(f"  Platform    : {hentry.get('platform', 'N/A')}")
        print(f"  Patch ID    : {hentry.get('patch_id', 'N/A')}")


def build_parser() -> argparse.ArgumentParser:
    """Return the configured :class:`argparse.ArgumentParser`."""
    parser = argparse.ArgumentParser(
        prog="python3 SplunkUnlimited.py",
        description=(
            "Patch a splunkd file identified by its SHA-256 hash.\n"
            "Remove signature and hash verification on license"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s splunkd             # identify and patch\n"
            "  %(prog)s splunkd --dry-run   # preview without writing\n"
            "  %(prog)s splunkd --hash      # print hash and exit\n"
            "  %(prog)s --list              # show databases\n"
        ),
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        nargs="?",
        help="Path to the splunkd file to patch.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Simulate the operation without writing any changes.",
    )
    parser.add_argument(
        "--hash",
        action="store_true",
        default=False,
        dest="show_hash",
        help=(
            f"Print the {HASH_ALGO.upper()} hash of FILE to stdout and exit (no patching performed)."
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        default=False,
        dest="list_db",
        help="List all entries in both databases and exit.",
    )
    parser.add_argument(
        "--force-mode",
        action="store_true",
        default=False,
        help=(
            "If the hash is not recognized, allow manual selection of a supported version."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose / debug output.",
    )
    return parser


def main() -> None:
    """Parse arguments and dispatch to the appropriate command."""
    parser = build_parser()
    args = parser.parse_args()

    if args.force_mode:
        args.verbose = True

    setup_logging(args.verbose)
    log = logging.getLogger(__name__)

    # --list does not require FILE
    if args.list_db:
        cmd_list_db()
        sys.exit(0)

    # All other modes require FILE
    if not args.file:
        parser.print_help()
        sys.exit(1)

    if args.show_hash:
        try:
            digest = compute_hash(args.file)
        except (OSError, ValueError) as exc:
            log.error("Cannot hash file: %s", exc)
            log.debug(traceback.format_exc())
            sys.exit(1)
        print(f"{digest}  {args.file}")
        sys.exit(0)

    sys.exit(run(args.file, dry_run=args.dry_run, force_mode=args.force_mode))


if __name__ == "__main__":
    main()
