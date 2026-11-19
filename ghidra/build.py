import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


HERE = Path(__file__).resolve().parent


def build(ghidra, javac, output):
    ghidra = ghidra.resolve()
    properties = (ghidra / "Ghidra/application.properties").read_text(encoding="utf-8")
    version = re.search(r"^application\.version=(.+)$", properties, re.M).group(1).strip()
    output = output or Path(f"ghidra_{version}_ATS2853.zip")
    classpath = os.pathsep.join(p.as_posix() for p in sorted((ghidra / "Ghidra").rglob("*.jar")))
    sources = sorted((HERE / "src").rglob("*.java"))

    with TemporaryDirectory(prefix="ats2853-build-") as temporary:
        work = Path(temporary)
        classes = work / "classes"
        classes.mkdir()
        args = ["-proc:none", "-encoding", "UTF-8", "-classpath", classpath, "-d", classes.as_posix()]
        args.extend(path.as_posix() for path in sources)
        argfile = work / "javac.args"
        argfile.write_text("\n".join(f'"{arg}"' for arg in args), encoding="utf-8")
        subprocess.run([javac, f"@{argfile}"], check=True)

        jar = work / "ATS2853.jar"
        with ZipFile(jar, "w", ZIP_DEFLATED) as archive:
            for path in sorted(classes.rglob("*.class")):
                archive.write(path, path.relative_to(classes).as_posix())

        with ZipFile(output, "w", ZIP_DEFLATED) as archive:
            for directory in ("ATS2853/", "ATS2853/lib/"):
                entry = ZipInfo(directory)
                entry.create_system = 3
                entry.external_attr = (0o40755 << 16) | 0x10
                archive.writestr(entry, b"")
            archive.writestr("ATS2853/Module.manifest", "")
            archive.writestr("ATS2853/extension.properties",
                f"name=ATS2853\nversion={version}\nauthor=LemonHaze\n"
                "description=Actions ATS2853 firmware loader\n")
            archive.write(jar, "ATS2853/lib/ATS2853.jar")
            license_file = HERE.parent / "LICENSE"
            if license_file.is_file():
                archive.write(license_file, "ATS2853/LICENSE")

    print(output.resolve())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ghidra", type=Path, help="Ghidra installation directory")
    parser.add_argument("--javac", help="JDK 21 javac, if it is not on PATH")
    parser.add_argument("-o", "--output", type=Path)
    options = parser.parse_args()
    java_home = os.environ.get("JAVA_HOME")
    javac = options.javac or shutil.which("javac")
    if not javac and java_home:
        javac = str(Path(java_home) / "bin" / ("javac.exe" if os.name == "nt" else "javac"))
    if not javac:
        parser.error("set JAVA_HOME or pass --javac for the JDK used by Ghidra")
    build(options.ghidra, javac, options.output)
