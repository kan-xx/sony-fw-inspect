"""Offline read-only partition carving, APFS case-collision ext2 inode aliasing,
nested MBR/FAT12 extraction, and bounds-checked WBI1/CramFS boot component unpacking.
"""

from .boot_components import (
    BoundedFile,
    CramfsSuper,
    WbiHeader,
    WbiSectionHeader,
    inflate_bounded,
    unpack_cramfs_image,
    unpack_wbi_image,
)
from .nested_fat import extract_nested_mbr_fat
from .partition_carver import (
    ExtPreflight,
    carve_firmware_image,
    collision_key,
    elf_header,
    ext_export,
    fat_export,
    format_header,
    hashes,
    inventory_export,
)
from .root_export import complete_failed_ext_partition

__all__ = [
    "BoundedFile",
    "WbiHeader",
    "WbiSectionHeader",
    "CramfsSuper",
    "inflate_bounded",
    "unpack_wbi_image",
    "unpack_cramfs_image",
    "extract_nested_mbr_fat",
    "ExtPreflight",
    "carve_firmware_image",
    "collision_key",
    "elf_header",
    "ext_export",
    "fat_export",
    "format_header",
    "hashes",
    "inventory_export",
    "complete_failed_ext_partition",
]
