from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from shutil import rmtree
from struct import unpack_from
import sys

import ida_auto
import ida_entry
import ida_ida
import ida_idp
import ida_kernwin
import ida_loader
import ida_nalt
import ida_segment
import ida_segregs
import ida_typeinf
import ida_ua


FORMATS = {
    "ATS2853 firmware (Normal boot)": "normal",
    "ATS2853 firmware (USB production)": "usb",
    "ATS2853 firmware (ATT card, data only)": "att",
    "ATS2853 firmware (SP card)": "sp",
}

PROFILES = {
    "normal": (
        ("outer/mbrec.bin", 0xBFC38000, 0xBFC38444, 0xBFC38750),
        ("outer/zephyr.bin", 0xBF000000, 0xBF000030, 0xBF06D9F0),
    ),
    "usb": (
        ("attdfu/mp_usb.bin", 0xBFC38000, 0xBFC38000, 0xBFC38298),
    ),
    "att": (
        ("attdfu/att_card.bin", 0x00042000, 0x0004243C, None),
        ("att_card_sdfs/stub.bin", 0x00049000, 0x00049400, None),
    ),
    "sp": (
        ("attdfu/sp_card.bin", 0xBFC21000, 0xBFC21030, 0xBFC2112C),
        ("sp_card_sdfs/product.bin", 0xBFC22000, 0xBFC22000, 0xBFC2208C),
    ),
}

MMIO_PAGES = (
    0xC0000000, 0xC0001000, 0xC0010000, 0xC0020000,
    0xC0060000, 0xC0080000, 0xC0090000, 0xC00A0000,
    0xC00E0000, 0xC0100000, 0xC0110000, 0xC0120000,
    0xC0140000, 0xC0190000, 0xC01A0000,
)

scan_filename = None
scan_index = 0


def accept_file(li, filename):
    global scan_filename, scan_index
    if filename != scan_filename:
        scan_filename, scan_index = filename, 0
    li.seek(0)
    header = li.read(512)
    if len(header) != 512 or header[:8] != b"ACTTEST0":
        scan_index = 0
        return 0
    count = unpack_from("<I", header, 0x0C)[0]
    size = unpack_from("<I", header, 0x14)[0]
    if not 1 <= count <= 14 or size != li.size():
        scan_index = 0
        return 0
    entries = {header[i:i + 16].split(b"\0", 1)[0] for i in range(0x20, 0x20 + count * 32, 32)}
    if not {b"attdfu.fw", b"mbrec.bin", b"zephyr.bin"} <= entries:
        scan_index = 0
        return 0

    formats = tuple(FORMATS)
    index = scan_index
    scan_index = (index + 1) % len(formats)
    options = 1
    if index == 0:
        options |= ida_loader.ACCEPT_FIRST
    if scan_index:
        options |= ida_loader.ACCEPT_CONTINUE
    return {"format": formats[index], "processor": "mipsl", "options": options}


class FirmwareInput:
    def __init__(self, li):
        li.seek(0)
        self.data = li.read(li.size())

    def read_bytes(self):
        return self.data


def extract_beside_input(li, extractor):
    filename = ida_nalt.get_input_file_path()
    if not filename or not Path(filename).is_file():
        raise ValueError("Open the firmware from a local file")
    source = Path(filename)
    out = source.with_name(source.stem if source.suffix else f"{source.name}_extracted")
    marker = out / ".firmware.sha256"
    firmware = FirmwareInput(li)
    digest = sha256(firmware.read_bytes()).hexdigest()

    try:
        out.mkdir()
    except FileExistsError:
        if marker.is_file() and marker.read_text(encoding="ascii").strip() == digest:
            return out
        raise ValueError(f"Extraction folder already exists for different or incomplete firmware: {out}") from None

    try:
        extractor.extract(firmware, out)
        marker.write_text(digest + "\n", encoding="ascii")
    except Exception:
        rmtree(out)
        raise
    return out


def read_module(directory, name):
    spec = spec_from_file_location(f"_ats2853_{name}", directory / f"{name}.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_extractor(directory):
    dependencies = {name: read_module(directory, name) for name in ("decode", "unwrap")}
    previous = {name: sys.modules[name] for name in dependencies if name in sys.modules}
    sys.modules.update(dependencies)
    try:
        return read_module(directory, "extract")
    finally:
        for name in dependencies:
            sys.modules.pop(name)
        sys.modules.update(previous)


def add_segment(name, start, size, kind, permissions):
    segment = ida_segment.segment_t()
    segment.start_ea = start
    segment.end_ea = start + size
    segment.bitness = 1
    segment.perm = permissions
    if not ida_segment.add_segm_ex(segment, name, kind, ida_segment.ADDSEG_NOSREG):
        raise RuntimeError(f"Could not add {name}")


def map_profile(profile, out):
    if ida_segment.get_first_seg() is not None:
        raise ValueError("Start with an empty IDA database")

    images = []
    for relative, base, entry, first_mips16 in PROFILES[profile]:
        path = out / relative
        data = path.read_bytes()
        if not base <= entry < base + len(data):
            raise ValueError(f"Entry outside {path}")
        if first_mips16 is not None and not base <= first_mips16 < base + len(data):
            raise ValueError(f"MIPS16 entry outside {path}")
        images.append((path.stem, data, base, entry, first_mips16))

    mips = profile != "att"
    if mips and (ida_ida.inf_get_procname() != "mipsl" or ida_ida.inf_is_be()):
        raise ValueError("Expected a little-endian MIPS processor")
    mode_reg = ida_idp.str2reg("mips16") if mips else -1
    if mips and mode_reg < 0:
        raise RuntimeError("MIPS16 mode register unavailable")

    ida_ida.inf_set_app_bitness(32)
    if mips:
        compiler = ida_ida.compiler_info_t()
        compiler.id = ida_typeinf.COMP_GNU
        flags = ida_typeinf.SETCOMP_ONLY_ID | ida_typeinf.SETCOMP_OVERRIDE | ida_typeinf.SETCOMP_BY_USER
        if not ida_typeinf.set_compiler(compiler, flags, "o32"):
            raise RuntimeError("Could not set the GNU MIPS o32 compiler")
    read = ida_segment.SEGPERM_READ
    for name, data, base, entry, first_mips16 in images:
        kind = "CODE" if mips else "DATA"
        permissions = read | ida_segment.SEGPERM_EXEC if mips else read
        add_segment(name, base, len(data), kind, permissions)
        if not ida_loader.mem2base(data, base, -1):
            raise RuntimeError(f"Could not load {name}")
        if mips:
            ida_segregs.split_sreg_range(base, mode_reg, 0, ida_segregs.SR_user)
            ida_segregs.split_sreg_range(first_mips16, mode_reg, 1, ida_segregs.SR_user)

    for base in MMIO_PAGES:
        add_segment(f"MMIO_{base:08X}", base, 0x1000, "DATA", read | ida_segment.SEGPERM_WRITE)

    for name, _, _, entry, first_mips16 in images:
        ida_entry.add_entry(entry, entry, f"{name}_entry", mips)
        if mips:
            ida_ua.create_insn(first_mips16)
            ida_auto.auto_make_proc(first_mips16)

    first_entry = images[0][3]
    if mips:
        ida_ida.inf_set_start_ea(first_entry)
    ida_kernwin.jumpto(first_entry)


def load_file(li, neflags, format):
    try:
        profile = FORMATS[format]
        directory = Path(__file__).resolve().parent
        support = directory / "ats2853_support"
        if support.is_dir():
            directory = support
        elif not (directory / "extract.py").is_file():
            directory = directory.parent

        extractor = read_extractor(directory)
        if not ida_idp.set_processor_type("mipsl", ida_idp.SETPROC_LOADER):
            raise RuntimeError("Could not select little-endian MIPS")
        map_profile(profile, extract_beside_input(li, extractor))
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        ida_kernwin.msg(f"ATS2853 loader: {error}\n")
        return 0
    return 1
