package ats2853;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

final class Ats2853Firmware {
    private static final int HEADER_SIZE = 512;
    private static final int RECORD_SIZE = 32;
    private static final int ATT_ROOT = 0x203010;
    private static final int CLUSTER_SIZE = 4096;
    private static final Set<String> REQUIRED = Set.of("attdfu.fw", "mbrec.bin", "zephyr.bin");

    // The same 32-byte reset and state taps as decode.py.
    private static final int SEED = 0x030A93B4;
    private static final int[] TAPS = {
        0x82108421, 0x08411043, 0x10802084, 0x21004108,
        0x82008210, 0x04000420, 0x10001020, 0x200021CC
    };
    private static final int FEEDBACK = 0x82608EDB;

    private record Entry(long offset, long size, long crc) {}
    private record Directory(Map<String, Entry> entries, long crc) {}

    private final ByteProvider provider;
    private final Map<String, Entry> outer;
    private Map<String, Entry> nested;

    static boolean recognizes(ByteProvider provider) throws IOException {
        try {
            return readDirectory(provider).entries.keySet().containsAll(REQUIRED);
        }
        catch (InvalidFirmwareException e) {
            return false;
        }
    }

    Ats2853Firmware(ByteProvider provider, TaskMonitor monitor) throws IOException, CancelledException {
        this.provider = provider;
        Directory directory = readDirectory(provider);
        this.outer = directory.entries;
        if (!outer.keySet().containsAll(REQUIRED) ||
            crc32(HEADER_SIZE, provider.length() - HEADER_SIZE, monitor) != directory.crc) {
            throw new InvalidFirmwareException("Invalid ATS2853 firmware directory or CRC");
        }
        for (var member : outer.entrySet()) {
            Entry entry = member.getValue();
            if (crc32(entry.offset, entry.size, monitor) != entry.crc) {
                throw new InvalidFirmwareException("Invalid CRC for " + member.getKey());
            }
        }
    }

    byte[] readImage(String path, long base, long entry) throws IOException {
        String[] parts = path.split("/", 2);
        String name = parts[1];
        return switch (parts[0]) {
            case "outer" -> {
                byte[] bytes = decodeImage(readOuter(name));
                if (!startsWith(bytes, "ACTHHTCA")) {
                    throw new InvalidFirmwareException("Invalid decoded image: " + name);
                }
                yield bytes;
            }
            case "attdfu" -> readNested(name);
            case "att_card_sdfs", "sp_card_sdfs" ->
                readSdfs(readNested(parts[0] + ".bin"), name, base, entry);
            default -> throw new InvalidFirmwareException("Unknown firmware image: " + path);
        };
    }

    private static Directory readDirectory(ByteProvider provider) throws IOException {
        if (provider.length() < HEADER_SIZE) {
            throw new InvalidFirmwareException("Truncated ATS2853 header");
        }
        byte[] header = provider.readBytes(0, HEADER_SIZE);
        ByteBuffer fields = littleEndian(header);
        int count = fields.getInt(0x0c);
        long size = u32(fields, 0x14);
        if (!startsWith(header, "ACTTEST0") || count < 1 || count > 14 || size != provider.length()) {
            throw new InvalidFirmwareException("Invalid ATS2853 header");
        }

        Map<String, Entry> entries = new HashMap<>();
        for (int i = 0; i < count; i++) {
            int at = 0x20 + i * RECORD_SIZE;
            String name = ascii(header, at, 16);
            long offset = u32(fields, at + 16);
            long length = u32(fields, at + 20);
            if (offset < HEADER_SIZE || offset + length > size ||
                entries.putIfAbsent(name, new Entry(offset, length, u32(fields, at + 28))) != null) {
                throw new InvalidFirmwareException("Invalid ATS2853 file entry: " + name);
            }
        }
        return new Directory(entries, u32(fields, 0x18));
    }

    private byte[] readOuter(String name) throws IOException {
        Entry entry = required(outer, name);
        return provider.readBytes(entry.offset, entry.size);
    }

    private long crc32(long offset, long size, TaskMonitor monitor)
            throws IOException, CancelledException {
        var crc = new CRC32();
        long end = offset + size;
        while (offset < end) {
            monitor.checkCancelled();
            int length = (int) Math.min(65536, end - offset);
            crc.update(provider.readBytes(offset, length));
            offset += length;
        }
        return crc.getValue();
    }

    private byte[] readNested(String name) throws IOException {
        if (nested == null) {
            nested = readAttDirectory(required(outer, "attdfu.fw"));
        }
        Entry entry = required(nested, name);
        byte[] bytes = provider.readBytes(entry.offset, entry.size);
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] ^= 0x38;
        }
        return bytes;
    }

    private Map<String, Entry> readAttDirectory(Entry container) throws IOException {
        if (container.size <= ATT_ROOT ||
            !startsWith(provider.readBytes(container.offset, 12), "100TMFWFSTCA")) {
            throw new InvalidFirmwareException("Invalid attdfu.fw container");
        }
        byte[] directory = provider.readBytes(container.offset + ATT_ROOT,
            Math.min(container.size - ATT_ROOT, 0x2000));
        ByteBuffer fields = littleEndian(directory);
        Map<String, Entry> entries = new HashMap<>();
        List<byte[]> longName = new ArrayList<>();
        for (int at = 0; at + RECORD_SIZE <= directory.length; at += RECORD_SIZE) {
            int first = Byte.toUnsignedInt(directory[at]);
            int flags = Byte.toUnsignedInt(directory[at + 11]);
            if (first == 0) {
                break;
            }
            if (first == 0xe5) {
                longName.clear();
                continue;
            }
            if (flags == 0x0f) {
                longName.add(Arrays.copyOfRange(directory, at, at + RECORD_SIZE));
                continue;
            }
            String name = longName.isEmpty() ? shortName(directory, at) : longName(longName);
            longName.clear();
            if ((flags & 0x18) != 0) {
                continue;
            }
            if (name.endsWith("~0")) {
                name = name.substring(0, name.length() - 2);
            }
            long cluster = ((long) Short.toUnsignedInt(fields.getShort(at + 20)) << 16) |
                Short.toUnsignedInt(fields.getShort(at + 26));
            long size = u32(fields, at + 28);
            if (cluster < 2 || size == 0) {
                continue;
            }
            long offset = ATT_ROOT + (cluster - 2) * CLUSTER_SIZE;
            if (offset + size > container.size ||
                entries.putIfAbsent(name, new Entry(container.offset + offset, size, 0)) != null) {
                throw new InvalidFirmwareException("Invalid attdfu.fw entry: " + name);
            }
        }
        return entries;
    }

    private static byte[] readSdfs(byte[] bytes, String name, long base, long entry) throws IOException {
        if (bytes.length < RECORD_SIZE || !startsWith(bytes, "sdfs.bin\0\0\0\0")) {
            throw new InvalidFirmwareException("Invalid card SDFS header");
        }
        ByteBuffer fields = littleEndian(bytes);
        int count = fields.getInt(12);
        if (u32(fields, 16) != bytes.length || count < 1 || count > 256 ||
            (count + 1) * RECORD_SIZE > bytes.length) {
            throw new InvalidFirmwareException("Invalid card SDFS directory");
        }
        int end = (count + 1) * RECORD_SIZE;
        for (int at = RECORD_SIZE; at < end; at += RECORD_SIZE) {
            if (name.equals(ascii(bytes, at, 12))) {
                long offset = u32(fields, at + 12);
                long length = u32(fields, at + 16);
                if (offset < end || offset + length > bytes.length ||
                    u32(fields, at + 20) != base || u32(fields, at + 24) != entry) {
                    throw new InvalidFirmwareException("Invalid card SDFS entry: " + name);
                }
                return Arrays.copyOfRange(bytes, (int) offset, (int) (offset + length));
            }
        }
        throw new InvalidFirmwareException("Missing card SDFS entry: " + name);
    }

    private static Entry required(Map<String, Entry> entries, String name) throws IOException {
        Entry entry = entries.get(name);
        if (entry == null) {
            throw new InvalidFirmwareException("Missing firmware entry: " + name);
        }
        return entry;
    }

    private static byte[] decodeImage(byte[] bytes) {
        int state = SEED;
        for (int i = 0; i < bytes.length; i++) {
            if ((i & 31) == 0) {
                state = SEED;
            }
            int mask = 0;
            for (int bit = 0; bit < TAPS.length; bit++) {
                mask |= (Integer.bitCount(state & TAPS[bit]) & 1) << bit;
            }
            int plain = Byte.toUnsignedInt(bytes[i]) ^ mask;
            bytes[i] = (byte) plain;
            int low = Integer.bitCount(state & FEEDBACK) & 1;
            int second = (state ^ (plain >>> 2) ^ (plain >>> 3) ^ (plain >>> 4) ^ (plain >>> 5)) & 1;
            state = ((state & ~1) << 1) | (second << 1) | low;
        }
        return bytes;
    }

    private static String ascii(byte[] bytes, int start, int length) {
        int end = start;
        while (end < start + length && bytes[end] != 0) {
            end++;
        }
        return new String(bytes, start, end - start, StandardCharsets.US_ASCII);
    }

    private static String shortName(byte[] bytes, int at) {
        String name = ascii(bytes, at, 8).stripTrailing();
        String ext = ascii(bytes, at + 8, 3).stripTrailing();
        return ext.isEmpty() ? name : name + "." + ext;
    }

    private static String longName(List<byte[]> parts) {
        parts.sort(Comparator.comparingInt(part -> part[0] & 31));
        var bytes = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            bytes.write(part, 1, 10);
            bytes.write(part, 14, 12);
            bytes.write(part, 28, 4);
        }
        String name = bytes.toString(StandardCharsets.UTF_16LE);
        int terminator = name.indexOf('\0');
        return (terminator < 0 ? name : name.substring(0, terminator)).replaceFirst("\\uffff+$", "");
    }

    private static boolean startsWith(byte[] bytes, String signature) {
        byte[] prefix = signature.getBytes(StandardCharsets.US_ASCII);
        return bytes.length >= prefix.length &&
            Arrays.equals(bytes, 0, prefix.length, prefix, 0, prefix.length);
    }

    private static ByteBuffer littleEndian(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static long u32(ByteBuffer fields, int at) {
        return Integer.toUnsignedLong(fields.getInt(at));
    }

    private static class InvalidFirmwareException extends IOException {
        InvalidFirmwareException(String message) {
            super(message);
        }
    }
}
