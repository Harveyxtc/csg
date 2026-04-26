import argparse
import ctypes
import datetime
import os
import signal
import shutil
import socket
import subprocess
import sys
import time
from shutil import copyfileobj
from pathlib import Path
from zipfile import ZipFile



def _enable_ansi() -> None:
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass


RST    = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
MAGENTA = "\033[35m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
WHITE  = "\033[97m"


def _info(msg: str) -> None:
    print(f"  {CYAN}›{RST} {msg}")


def _ok(msg: str) -> None:
    print(f"  {GREEN}✔{RST} {msg}")


def _warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{RST}  {msg}", file=sys.stderr)


def _err(msg: str) -> None:
    print(f"  {RED}✖{RST}  {msg}", file=sys.stderr)


def _step(n: int, total: int, title: str) -> None:
    label = f"[{n}/{total}]"
    print(f"\n  {BOLD}{WHITE}{label}{RST}  {BOLD}{title}{RST}")


def _banner() -> None:
    line = "═" * 55
    print(f"\n{MAGENTA}{line}{RST}")
    print(f"  {BOLD}{WHITE}Proactive Defense{RST}  {DIM}—{RST}  App Launcher")
    print(f"{MAGENTA}{line}{RST}")


def _divider(msg: str = "") -> None:
    if msg:
        pad = max(2, 51 - len(msg))
        print(f"\n  {GREEN}── {msg} {'─' * pad}{RST}")
    else:
        print(f"\n  {DIM}{'─' * 55}{RST}")


# ── Port helpers ──────────────────────────────────────────────────────────────

def wait_for_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def resolve_from_root(project_root: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = project_root / candidate
    return candidate.resolve()


def find_7z_split_zip(search_dirs: list[Path]) -> Path | None:

    for folder in search_dirs:
        if not folder.exists():
            continue

        # Style 1: first part is explicitly .001
        for first_part in sorted(folder.glob("*.zip.001")):
            second_part = Path(str(first_part)[:-3] + "002")
            if second_part.exists():
                return first_part

        # Style 2: first part is plain .zip and next starts at .002
        for base_zip in sorted(folder.glob("*.zip")):
            second_part = folder / f"{base_zip.name}.002"
            if second_part.exists():
                return base_zip

    return None


def _get_split_zip_parts(first_part: Path) -> list[Path]:
    folder = first_part.parent

    if first_part.name.endswith(".zip.001"):
        base_name = first_part.name[:-4]  # remove ".001" -> "name.zip"
        numbered = []
        for p in folder.glob(f"{base_name}.*"):
            suffix = p.name.rsplit(".", 1)[-1]
            if suffix.isdigit():
                numbered.append((int(suffix), p))
        numbered.sort(key=lambda t: t[0])
        return [p for _, p in numbered]

    # style: name.zip + name.zip.002 + name.zip.003
    numbered = []
    for p in folder.glob(f"{first_part.name}.*"):
        suffix = p.name.rsplit(".", 1)[-1]
        if suffix.isdigit():
            numbered.append((int(suffix), p))
    numbered.sort(key=lambda t: t[0])
    return [first_part] + [p for _, p in numbered]


def merge_split_zip_parts(first_part: Path, output_zip: Path) -> None:
    parts = _get_split_zip_parts(first_part)
    if len(parts) < 2:
        raise RuntimeError(f"Split archive set is incomplete: {first_part}")

    _info(f"Merging {len(parts)} split parts into {output_zip.name}...")
    with open(output_zip, "wb") as out:
        for i, part in enumerate(parts, 1):
            _info(f"  Part {i}/{len(parts)}: {part.name}")
            with open(part, "rb") as inp:
                copyfileobj(inp, out)
    _ok("Merge complete.")


def extract_zip(zip_path: Path, extract_to: Path, force: bool) -> None:
    if extract_to.exists() and force:
        _info(f"Force flag set — removing existing folder: {extract_to.name}\\")
        shutil.rmtree(extract_to)

    _info(f"Extracting  {zip_path.name}  →  {extract_to.name}\\")
    extract_to.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        total = len(names)
        for i, name in enumerate(names, 1):
            zf.extract(name, extract_to.parent)
            if total > 0 and (i == 1 or i == total or i % max(1, total // 10) == 0):
                pct = int(i / total * 100)
                print(f"\r    {DIM}Progress: {pct:>3}%  ({i}/{total} files){RST}", end="", flush=True)
    print()  # newline after progress ticker
    _ok(f"Extracted {total} files.")


def find_clamd(extract_to: Path) -> Path:
    direct = extract_to / "clamd.exe"
    if direct.exists():
        return direct

    candidates = sorted(extract_to.rglob("clamd.exe"))
    if not candidates:
        raise FileNotFoundError("Could not find clamd.exe in extracted files.")

    return candidates[0]


def build_clamd_command(clamd_path: Path) -> list[str]:
    command = [str(clamd_path)]
    config_path = clamd_path.parent / "clamd.conf"
    if config_path.exists():
        command.append(f"--config-file={config_path}")
    return command


def delete_zip(zip_path: Path) -> None:
    try:
        zip_path.unlink()
        _ok(f"Removed zip archive: {zip_path.name}")
    except FileNotFoundError:
        pass


FRESHCLAM_STAMP_FILE = ".freshclam_stamp"
REQUIREMENTS_STAMP_FILE = ".requirements_stamp"


def read_stamp(stamp_path: Path) -> float:
    try:
        return float(stamp_path.read_text().strip())
    except Exception:
        return 0.0


def write_stamp(stamp_path: Path) -> None:
    stamp_path.write_text(str(time.time()))


def needs_update(stamp_path: Path, interval_hours: float) -> bool:
    elapsed_hours = (time.time() - read_stamp(stamp_path)) / 3600
    return elapsed_hours >= interval_hours


def run_freshclam(clamd_path: Path) -> None:
    freshclam = clamd_path.parent / "freshclam.exe"
    if not freshclam.exists():
        _warn("freshclam.exe not found — skipping signature update.")
        return

    _info("Running freshclam to update virus signatures...")
    _divider("Freshclam Output")
    result = subprocess.run([str(freshclam)], cwd=str(clamd_path.parent))
    _divider()
    if result.returncode == 0:
        _ok("Signature update complete.")
    else:
        _warn(f"freshclam exited with code {result.returncode} — continuing anyway.")


def install_requirements(project_root: Path) -> int:
    requirements_path = project_root / "requirements.txt"
    if not requirements_path.exists():
        _warn("requirements.txt not found — skipping dependency install.")
        return 0

    requirements_stamp_path = project_root / REQUIREMENTS_STAMP_FILE
    if requirements_stamp_path.exists():
        _ok("Python dependencies already installed.")
        return 0

    _info("Installing Python dependencies from requirements.txt...")
    _divider("pip install -r requirements.txt")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements_path), "--user"],
        cwd=str(project_root),
    )
    _divider()

    if result.returncode != 0:
        _err(f"Dependency install failed with code {result.returncode}.")
        return result.returncode

    requirements_stamp_path.write_text(str(time.time()))
    _ok("Python dependencies are installed.")
    _divider
    _info("Re-run the script!")
    exit(0)



def terminate_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return

    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                text=True,
            )
            return

        proc.send_signal(signal.SIGTERM)
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        pass

    if proc.poll() is None:
        try:
            proc.kill()
        except Exception:
            pass


def main() -> int:
    _enable_ansi()

    parser = argparse.ArgumentParser(
        description="Start clamd and app_v5 together: one command for local development."
    )
    parser.add_argument("--zip", default="ClamAV.zip", help="Path to ClamAV zip")
    parser.add_argument("--extract-to", default="ClamAV", help="Extracted ClamAV folder")
    parser.add_argument("--clamd-timeout", type=float, default=45.0, help="Seconds to wait for clamd on 127.0.0.1:3310")
    parser.add_argument("--force", action="store_true", help="Force re-extract ClamAV before launch")
    parser.add_argument("--update-interval", type=float, default=24.0, metavar="HOURS", help="Run freshclam only if last update was more than this many hours ago (default: 24)")
    parser.add_argument("--skip-update", action="store_true", help="Never run freshclam")
    parser.add_argument("--force-update", action="store_true", help="Always run freshclam, ignoring the last update stamp")

    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    app_script = project_root / "src" / "app_v5.py"
    zip_path = resolve_from_root(project_root, args.zip)
    extract_to = resolve_from_root(project_root, args.extract_to)

    _banner()

    _step(1, 5, "Python Dependencies")
    install_code = install_requirements(project_root)
    if install_code != 0:
        return install_code

    if not app_script.exists():
        _err(f"Missing Flask app script: {app_script}")
        return 1

    # ── Step 2: ClamAV Setup ──────────────────────────────────────────────────
    _step(2, 5, "ClamAV Setup")

    # Detect archives in likely places (explicit --zip, extract folder, and ClamAV folder).
    zip_name = Path(args.zip).name
    archive_search_dirs = [extract_to, zip_path.parent, project_root / "ClamAV"]
    split_zip = find_7z_split_zip(archive_search_dirs)
    merged_zip = project_root / "ClamAV_merged.zip"

    zip_candidates = [
        zip_path,
        Path(str(zip_path) + ".001"),
        extract_to / zip_name,
        extract_to / f"{zip_name}.001",
        (project_root / "ClamAV" / zip_name),
        (project_root / "ClamAV" / f"{zip_name}.001"),
    ]
    zip_path_to_use = next((p for p in zip_candidates if p.exists()), zip_path)

    use_7z = split_zip is not None
    force_extract = args.force or use_7z  # Auto-extract when split set is detected

    # Check if already extracted by looking for clamd.exe specifically.
    extracted_clamd = extract_to / "clamd.exe"
    if extracted_clamd.exists() and not force_extract:
        _ok(f"Using existing ClamAV folder:  {DIM}{extract_to.name}\\{RST}")
    else:
        if use_7z:
            _info(f"Found split archive set starting at: {split_zip.name}")
            merge_split_zip_parts(split_zip, merged_zip)
            extract_zip(merged_zip, extract_to, force_extract)
        else:
            if not zip_path_to_use.exists():
                _err(
                    "Zip file not found. Checked: "
                    f"{zip_candidates[0]}, {zip_candidates[1]}, {zip_candidates[2]}"
                )
                return 1
            extract_zip(zip_path_to_use, extract_to, force_extract)

    if merged_zip.exists():
        try:
            merged_zip.unlink()
            _ok(f"Cleaned up temporary merge file: {merged_zip.name}")
        except Exception:
            pass

    if not extract_to.exists():
        _err(f"Expected extracted folder was not created: {extract_to}")
        return 1

    try:
        clamd_path = find_clamd(extract_to)
    except FileNotFoundError as exc:
        _err(str(exc))
        return 1

    _ok(f"Found clamd.exe:  {DIM}{clamd_path.relative_to(project_root)}{RST}")

    # ── Step 3: Signature Update ──────────────────────────────────────────────
    _step(3, 5, "Signature Update")

    stamp_path = project_root / FRESHCLAM_STAMP_FILE
    if args.skip_update:
        _info("Skipping signature update  (--skip-update).")
    elif args.force_update or needs_update(stamp_path, args.update_interval):
        run_freshclam(clamd_path)
        write_stamp(stamp_path)
    else:
        last_ts = read_stamp(stamp_path)
        last_dt = datetime.datetime.fromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M")
        _ok(f"Signatures up to date  {DIM}(last updated {last_dt}){RST}")

    # ── Step 4: ClamAV Daemon ─────────────────────────────────────────────────
    _step(4, 5, "ClamAV Daemon")

    clamd_cmd = build_clamd_command(clamd_path)
    common_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    new_console_flag = subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0
    creation_flags = common_flags | new_console_flag

    _info("Launching clamd in a separate window...")
    clamd_proc = subprocess.Popen(
        clamd_cmd,
        cwd=str(clamd_path.parent),
        creationflags=creation_flags,
    )
    _ok(f"clamd started  {DIM}(PID {clamd_proc.pid}){RST}")

    # ── Step 5: Flask App ─────────────────────────────────────────────────────
    try:
        _step(5, 5, "Starting Application")
        _info("Launching app_v5 in this terminal...")
        _divider()

        app_cmd = [sys.executable, str(app_script)]
        app_proc = subprocess.Popen(app_cmd, cwd=str(project_root))

        ready_announced = False
        timeout_announced = False
        readiness_start = time.time()

        try:
            while app_proc.poll() is None:
                if not ready_announced and is_port_open("127.0.0.1", 3310):
                    _divider("clamd ready on 127.0.0.1:3310")
                    print("")
                    ready_announced = True
                elif (
                    not ready_announced
                    and not timeout_announced
                    and (time.time() - readiness_start) >= args.clamd_timeout
                ):
                    _warn("clamd is still starting — app is running without it for now.")
                    timeout_announced = True

                if not ready_announced and clamd_proc.poll() is not None:
                    _warn("clamd process exited before becoming ready.")
                    ready_announced = True

                time.sleep(0.5)

            exit_code = app_proc.returncode if app_proc.returncode is not None else 0
            _divider()
            if exit_code == 0:
                _ok("app_v5 exited cleanly. Stopping clamd...")
            else:
                _warn(f"app_v5 exited with code {exit_code}. Stopping clamd...")
            return exit_code

        except KeyboardInterrupt:
            _divider()
            _info("Ctrl+C received — stopping app and clamd...")
            terminate_process(app_proc)
            return 0
        finally:
            terminate_process(clamd_proc)

    finally:
        if clamd_proc.poll() is None:
            terminate_process(clamd_proc)


if __name__ == "__main__":
    raise SystemExit(main())
