# Ghidra loader

Build with the JDK used by Ghidra and Python 3.10 or later:

```powershell
python ghidra/build.py E:\ghidra_12.1.2_PUBLIC
```

Install the resulting ZIP with **File → Install Extensions → +** and restart Ghidra. Import the
original `.fw` and choose an ATS2853 format for Normal boot, USB production, ATT card, or SP card.
ATT card requires the separate `CSKY_V2:LE:32:default` processor language.

The importer reads the selected executable images directly from the firmware. Python is only needed to build the ZIP.
