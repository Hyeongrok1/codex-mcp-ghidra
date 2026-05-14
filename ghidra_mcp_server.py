import json
import hashlib
import os
import re
import shutil
import sys
import subprocess
import struct
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("ghidra")

SCRIPTS = {
    "summary": "summary.java",
    "functions": "functions.java",
    "decompile": "decompile.java",
    "strings": "strings.java",
    "read_memory": "memory.java",
    "sections": "memory.java",
    "read_section": "memory.java",
    "va_to_file_offset": "memory.java",
    "xrefs_to": "xrefs_to.java",
    "xrefs_from": "xrefs_from.java",
    "functions_calling": "finders.java",
    "functions_referencing_string": "finders.java",
}


def log(message):
    print(f"[ghidra-mcp] {message}", file=sys.stderr, flush=True)


def project_root():
    return Path(os.environ.get("GHIDRA_MCP_PROJECTS", "/tmp/ghidra-mcp-projects")).expanduser()


def project_name(binary_path):
    path = Path(binary_path).expanduser().resolve()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:10]
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name).strip("._")
    return f"{safe_name}_{digest}"


def analyze_headless_path():
    ghidra_home = os.environ.get("GHIDRA_HOME")
    candidates = []
    if ghidra_home:
        candidates.append(Path(ghidra_home).expanduser() / "support" / "analyzeHeadless")
    candidates.extend(Path("/opt/homebrew/Cellar/ghidra").glob("*/libexec/support/analyzeHeadless"))
    candidates.extend(Path("/usr/local/Cellar/ghidra").glob("*/libexec/support/analyzeHeadless"))

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    searched = ", ".join(str(c) for c in candidates) or "<none>"
    raise FileNotFoundError(f"analyzeHeadless not found; searched: {searched}")


def pe_sections(binary_path):
    path = Path(binary_path).expanduser().resolve()
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None

    coff = pe_offset + 4
    section_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    image_base = struct.unpack_from("<Q" if magic == 0x20B else "<I", data, optional + 24)[0]
    section_table = optional + optional_size

    sections = []
    for i in range(section_count):
        off = section_table + i * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, off + 8)
        sections.append({
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_offset": raw_offset,
            "raw_size": raw_size,
            "start_va": image_base + virtual_address,
            "end_va": image_base + virtual_address + max(virtual_size, raw_size) - 1,
        })

    return {"format": "PE", "image_base": image_base, "sections": sections}


def pe_va_to_file_offset(binary_path, address):
    parsed = pe_sections(binary_path)
    if not parsed:
        return None

    va = int(address, 16) if isinstance(address, str) else int(address)
    for section in parsed["sections"]:
        start = section["start_va"]
        end = start + max(section["virtual_size"], section["raw_size"])
        if start <= va < end:
            delta = va - start
            if delta >= section["raw_size"]:
                return {
                    "address": hex(va),
                    "section": section["name"],
                    "file_offset": None,
                    "reason": "address is past raw section data",
                }
            file_offset = section["raw_offset"] + delta
            return {
                "address": hex(va),
                "section": section["name"],
                "file_offset": file_offset,
                "file_offset_hex": hex(file_offset),
            }
    return None


def format_error(proc):
    return "\n".join(part for part in [proc.stderr.strip(), proc.stdout.strip()] if part)


def project_files(project):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", project):
        raise ValueError(f"unsafe project name: {project}")

    projects = project_root()
    return [
        projects / f"{project}.gpr",
        projects / f"{project}.rep",
        projects / f"{project}.lock",
        projects / f"{project}.lock~",
    ]


def remove_project_files(project):
    for path in project_files(project):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            path.unlink()


def run_headless(cmd, timeout, project):
    try:
        return subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        log(f"timeout after {timeout}s")
        remove_project_files(project)
        return {
            "error": f"analyzeHeadless timed out after {timeout}s",
            "stdout": e.stdout or "",
            "stderr": e.stderr or "",
            "_project": project,
        }


def ghidra(command, binary_path, *args):
    analyze_headless = analyze_headless_path()
    script_dir = Path(__file__).parent
    binary = Path(binary_path).expanduser().resolve()
    timeout = int(os.environ.get("GHIDRA_MCP_TIMEOUT", "600"))

    out_dir = Path(tempfile.mkdtemp(prefix="ghidra-mcp-out-"))
    out = out_dir / "out.json"
    projects = project_root()
    projects.mkdir(parents=True, exist_ok=True)
    project = project_name(binary)

    project_exists = (projects / f"{project}.gpr").exists()
    if project_exists:
        target_args = ["-process", binary.name]
    else:
        target_args = ["-import", str(binary)]

    try:
        log(f"tool={command} binary={binary}")
        log(f"project_dir={projects} project={project} mode={target_args[0]}")
        log(f"script={SCRIPTS[command]} out={out}")

        def build_cmd(next_target_args):
            return [
                str(analyze_headless),
                str(projects),
                project,
                *next_target_args,
                "-scriptPath",
                str(script_dir),
                "-postScript",
                SCRIPTS[command],
                str(out),
                *map(str, args),
            ]

        cmd = build_cmd(target_args)
        log("run: " + " ".join(cmd))

        proc = run_headless(cmd, timeout, project)
        if isinstance(proc, dict):
            return proc

        log(f"exit={proc.returncode}")
        if proc.returncode != 0:
            error = format_error(proc)
            log(error)

            log("process/import failed; cleaning project and retrying once with -import")
            remove_project_files(project)
            retry_cmd = build_cmd(["-import", str(binary)])
            log("retry: " + " ".join(retry_cmd))
            proc = run_headless(retry_cmd, timeout, project)
            if isinstance(proc, dict):
                return proc
            log(f"retry exit={proc.returncode}")
            if proc.returncode != 0:
                error = format_error(proc)
                log(error)
                return {"error": error, "_project": project}

        if not out.exists():
            log("script did not write output; cleaning project and retrying once with -import")
            remove_project_files(project)
            retry_cmd = build_cmd(["-import", str(binary)])
            log("retry: " + " ".join(retry_cmd))
            proc = run_headless(retry_cmd, timeout, project)
            if isinstance(proc, dict):
                return proc
            if proc.returncode != 0:
                error = format_error(proc)
                log(error)
                return {"error": error, "_project": project}

        result = json.loads(out.read_text())
        if isinstance(result, dict):
            result["_project"] = project
        log(f"ok keys={list(result.keys())}")
        return result
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def delete_ghidra_project(project: str):
    analyze_headless = analyze_headless_path()
    projects = project_root()
    timeout = int(os.environ.get("GHIDRA_MCP_TIMEOUT", "600"))

    cmd = [
            str(analyze_headless),
            str(projects),
            project,
            "-deleteProject",
        ]
    log("delete: " + " ".join(cmd))

    proc = run_headless(cmd, timeout, project)
    if isinstance(proc, dict):
        return proc
    log(f"delete exit={proc.returncode}")
    if proc.returncode != 0:
        error = format_error(proc)
        log(error)
        remove_project_files(project)
        return {"deleted": project, "project_dir": str(projects), "warning": error}
    return {"deleted": project, "project_dir": str(projects)}


@mcp.tool()
def summary(binary_path: str):
    return ghidra("summary", binary_path)


@mcp.tool()
def functions(binary_path: str, limit: int = 100):
    return ghidra("functions", binary_path, limit)


@mcp.tool()
def decompile(binary_path: str, address: str, include_line_addresses: bool = False):
    return ghidra("decompile", binary_path, address, include_line_addresses)


@mcp.tool()
def strings(binary_path: str, query: str, limit: int = 100):
    return ghidra("strings", binary_path, query, limit)


@mcp.tool()
def read_memory(binary_path: str, address: str, length: int, format: str = "hex"):
    return ghidra("read_memory", binary_path, "read_memory", address, length, format)


@mcp.tool()
def sections(binary_path: str):
    result = ghidra("sections", binary_path, "sections")
    parsed = pe_sections(binary_path)
    if parsed:
        result["file_format"] = parsed["format"]
        result["image_base"] = hex(parsed["image_base"])
        by_name = {section["name"]: section for section in parsed["sections"]}
        for section in result.get("sections", []):
            file_section = by_name.get(section.get("name"))
            if not file_section:
                continue
            section["raw_offset"] = file_section["raw_offset"]
            section["raw_offset_hex"] = hex(file_section["raw_offset"])
            section["raw_size"] = file_section["raw_size"]
            section["virtual_address"] = hex(file_section["virtual_address"])
    return result


@mcp.tool()
def read_section(binary_path: str, section: str, format: str = "hex"):
    return ghidra("read_section", binary_path, "read_section", section, format)


@mcp.tool()
def va_to_file_offset(binary_path: str, address: str):
    result = pe_va_to_file_offset(binary_path, address)
    if result:
        return result
    return ghidra("va_to_file_offset", binary_path, "va_to_file_offset", address)


@mcp.tool()
def xrefs_to(binary_path: str, address: str):
    return ghidra("xrefs_to", binary_path, address)


@mcp.tool()
def xrefs_from(binary_path: str, address: str):
    return ghidra("xrefs_from", binary_path, address)


@mcp.tool()
def functions_calling(binary_path: str, name: str, limit: int = 100):
    return ghidra("functions_calling", binary_path, "calling", name, limit)


@mcp.tool()
def functions_referencing_string(binary_path: str, query: str, limit: int = 100):
    return ghidra("functions_referencing_string", binary_path, "string_refs", query, limit)


@mcp.tool()
def delete_project(project: str):
    return delete_ghidra_project(project)


if __name__ == "__main__":
    log("starting server")
    log(f"GHIDRA_HOME={os.environ.get('GHIDRA_HOME', '<unset>')}")
    log(f"GHIDRA_MCP_PROJECTS={project_root()}")
    log(f"GHIDRA_MCP_TIMEOUT={os.environ.get('GHIDRA_MCP_TIMEOUT', '600')}")
    log(f"script_dir={Path(__file__).parent}")
    mcp.run()
