package ats2853;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

public abstract class Ats2853Loader extends AbstractProgramWrapperLoader {
    private static final String MIPS = "MIPS:LE:32:default";
    private static final String CSKY = "CSKY_V2:LE:32:default";
    private static final long[] MMIO = {
        0xC0000000L, 0xC0001000L, 0xC0010000L, 0xC0020000L, 0xC0060000L,
        0xC0080000L, 0xC0090000L, 0xC00A0000L, 0xC00E0000L, 0xC0100000L,
        0xC0110000L, 0xC0120000L, 0xC0140000L, 0xC0190000L, 0xC01A0000L
    };

    private record Image(String path, long base, long entry, long mips16) {
        Image(String path, long base, long entry) {
            this(path, base, entry, 0);
        }

        String name() {
            return Path.of(path).getFileName().toString().replaceFirst("\\.bin$", "");
        }
    }

    protected enum Profile {
        NORMAL("Normal boot", MIPS,
            new Image("outer/mbrec.bin", 0xBFC38000L, 0xBFC38444L, 0xBFC38750L),
            new Image("outer/zephyr.bin", 0xBF000000L, 0xBF000030L, 0xBF06D9F0L)),
        USB("USB production", MIPS,
            new Image("attdfu/mp_usb.bin", 0xBFC38000L, 0xBFC38000L, 0xBFC38298L)),
        ATT("ATT card", CSKY,
            new Image("attdfu/att_card.bin", 0x42000, 0x4243C),
            new Image("att_card_sdfs/stub.bin", 0x49000, 0x49400)),
        SP("SP card", MIPS,
            new Image("attdfu/sp_card.bin", 0xBFC21000L, 0xBFC21030L, 0xBFC2112CL),
            new Image("sp_card_sdfs/product.bin", 0xBFC22000L, 0xBFC22000L, 0xBFC2208CL));

        private final String label;
        private final String language;
        private final Image[] images;

        Profile(String label, String language, Image... images) {
            this.label = label;
            this.language = language;
            this.images = images;
        }
    }

    private final Profile profile;

    protected Ats2853Loader(Profile profile) {
        this.profile = profile;
    }

    @Override
    public String getName() {
        return "ATS2853 firmware (" + profile.label + ")";
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }

    @Override
    public int getTierPriority() {
        return profile.ordinal();
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        if (!Ats2853Firmware.recognizes(provider)) {
            return List.of();
        }
        LanguageID id = new LanguageID(profile.language);
        try {
            var language = getLanguageService().getLanguage(id);
            var pair = new LanguageCompilerSpecPair(id,
                language.getDefaultCompilerSpec().getCompilerSpecID());
            return List.of(new LoadSpec(this, profile.images[0].base, pair, true));
        }
        catch (LanguageNotFoundException e) {
            return List.of();
        }
    }

    @Override
    protected void load(Program program, ImporterSettings settings) throws IOException, CancelledException {
        if (!program.getLanguageID().getIdAsString().equals(profile.language)) {
            throw new IOException("Select " + profile.language + " for " + getName());
        }
        var firmware = new Ats2853Firmware(settings.provider(), settings.monitor());
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Register mode = program.getProgramContext().getRegister("ISA_MODE");

        try {
            for (Image image : profile.images) {
                settings.monitor().checkCancelled();
                byte[] data = firmware.readImage(image.path, image.base, image.entry);
                long size = data.length;
                if (image.entry - image.base >= size ||
                    (image.mips16 != 0 && image.mips16 - image.base >= size)) {
                    throw new IOException("Image entry outside " + image.path);
                }
                try (var bytes = new ByteArrayInputStream(data)) {
                    MemoryBlock block = program.getMemory().createInitializedBlock(image.name(),
                        space.getAddress(image.base), bytes, size, settings.monitor(), false);
                    block.setPermissions(true, false, true);
                }
                if (image.mips16 != 0) {
                    Address target = space.getAddress(image.mips16);
                    program.getProgramContext().setValue(mode, target, target, BigInteger.ONE);
                }
            }
            for (long page : MMIO) {
                MemoryBlock block = program.getMemory().createUninitializedBlock(
                    "MMIO_%08X".formatted(page), space.getAddress(page), 0x1000, false);
                block.setPermissions(true, true, false);
                block.setVolatile(true);
            }
            for (Image image : profile.images) {
                addEntry(program, space.getAddress(image.entry), image.name() + "_entry", settings);
                if (image.mips16 != 0) {
                    addEntry(program, space.getAddress(image.mips16), image.name() + "_mips16", settings);
                }
            }
        }
        catch (AddressOverflowException | ContextChangeException | InvalidInputException |
               LockException | MemoryConflictException e) {
            throw new IOException("Could not map ATS2853 images", e);
        }
    }

    private static void addEntry(Program program, Address address, String name, ImporterSettings settings)
            throws InvalidInputException {
        program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
        program.getSymbolTable().addExternalEntryPoint(address);
        var command = new DisassembleCommand(address, null, false);
        command.enableCodeAnalysis(false);
        if (command.applyTo(program, settings.monitor())) {
            markAsFunction(program, name, address);
        }
        else {
            settings.log().appendMsg("Could not disassemble " + name + " at " + address);
        }
    }

}
