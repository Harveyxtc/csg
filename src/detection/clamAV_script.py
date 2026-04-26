#   Same test files as before, entire scan time went from 8.*s to now 0.04s 
#
#   Requires ClamAV installed + the ClamAV 'clamd.exe' deamon running 
#   + 'pyclamd' python wrapper for ClamAV (pip)
#
#   ClamAV requires some setup with the 2 config files but very easy
#
#   Same issue with the test files being automatically detected by windows but can easily add 
#   exception to folder but kinda have to be manually created 
#
#   Scan result output files DO contain too much info atm but we is testing

import os
import json
import datetime

import argparse
import pyclamd

test_folder = "test_files"
result_folder = "scan_results"
os.makedirs(result_folder, exist_ok=True)

# arg/flag setup for future use eg. 'python scan.py --folder {folderlocation}' for use in main program or others 
parser = argparse.ArgumentParser(description="ClamAV scanner")
parser.add_argument("--pretty", action="store_true")
parser.add_argument("--no-summary", action="store_true")
parser.add_argument("--folder", default=test_folder)
parser.add_argument("--file", help="Scan a single file instead of a folder")
parser.add_argument("--output", help="Write JSON results to this exact file path")
args = parser.parse_args()

# Determine scan target: single file takes precedence over folder
if args.file:
    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' does not exist or is not a file.")
        exit(1)
    files = [os.path.abspath(args.file)]
    scan_target = f"file: {args.file}"
else:
    # Folder scanning (existing logic)
    if not os.path.isdir(args.folder):
        print(f"Error: Folder '{args.folder}' does not exist.")
        exit(1)
    files = [os.path.abspath(os.path.join(args.folder, f)) for f in os.listdir(args.folder) if os.path.isfile(os.path.join(args.folder, f))]
    scan_target = f"folder: {args.folder}"

if not files:
    print(f"No files found in {scan_target}. Exiting...")
    exit(0) 

def format_size(bytes_size):
    if bytes_size < 1024:
        return f"{bytes_size} B"
    kb = bytes_size / 1024
    if kb < 1024:
        return f"{kb:.2f} KiB"
    mb = kb / 1024
    return f"{mb:.2f} MiB"


def print_summary(summary):
    print(f"\n----------- SCAN SUMMARY -----------")
    ordered_keys = [
        "Scan target",  # Add scan target first
        "Known viruses",
        "Engine version",
        "Scanned directories",
        "Scanned files",
        "Infected files",
        "Data scanned",
        "Data read",
        "Time",
        "Start Date",
        "End Date",
    ]
    for key in ordered_keys:
        if key in summary:
            print(f"{key}: {summary[key]}")


scan_results = []
scan_summary = {
    "Known viruses": "0",
    "Engine version": "unknown",
    "Scanned directories": "0" if args.file else "1",  # 0 for single file, 1 for folder
    "Scanned files": str(len(files)),
    "Infected files": "0",
    "Data scanned": "0.00 KiB",
    "Data read": "0.00 KiB (ratio 0.00:1)",
    "Time": "0.000 sec",
    "Start Date": "",
    "End Date": "",
    "Scan target": scan_target,  # Add scan target to summary
}

scan_start = datetime.datetime.now()
scan_summary["Start Date"] = scan_start.strftime("%Y:%m:%d %H:%M:%S")

# vscode buggy
if pyclamd is None:
    print("Error: pyclamd is not installed... or you're using the wrong interpreter ")
    exit(1)

cd = None

for connector in [
    lambda: pyclamd.ClamdNetworkSocket(),
    lambda: pyclamd.ClamdUnixSocket(),
    lambda: pyclamd.ClamdAgnostic(),
]:
    try:
        candidate = connector()
        candidate.ping()
        cd = candidate
        break
    except Exception:
        continue

if cd is None:
    print("Error: clamd daemon is unreachable. Make sure the daemon clamd.exe is running...")
    exit(1)

try:
    version_info = cd.version()
    if isinstance(version_info, str):
        engine_version = version_info
        if "/" in version_info:
            parts = version_info.split("/")
            engine_version = parts[0]
            known_viruses = parts[1] if len(parts) > 1 else "0"
    elif isinstance(version_info, dict):
        engine_version = version_info.get("version", "unknown")
        known_viruses = str(version_info.get("signatures", "0"))
except Exception:
    pass

scan_summary["Engine version"] = engine_version
scan_summary["Known viruses"] = known_viruses

infected_count = 0
data_scanned = 0

print("All good so far....\n")

for path in files:
    try:
        res = cd.scan_file(path)
        file_size = os.path.getsize(path)
        data_scanned += file_size

        if res is None:
            print(f"{path}: OK")
            scan_results.append({"file": path, "status": "clean", "signature": None})
        else:
            item = next(iter(res.values()))
            signature = None
            status = "unknown"

            if isinstance(item, (list, tuple)) and len(item) > 0:
                if len(item) >= 2:
                    first, second = str(item[0]).strip(), str(item[1]).strip()
                    if second.upper() == "FOUND":
                        signature = first if first.upper() != "FOUND" else None
                        status = "infected"
                    elif first.upper() == "FOUND":
                        signature = second if second.upper() != "FOUND" else None
                        status = "infected"
                    elif second.upper() == "OK" or first.upper() == "OK":
                        signature = None
                        status = "clean"
                    else:
                        signature = first
                        status = "infected"
                else:
                    val = str(item[0]).strip()
                    if val.upper() == "FOUND":
                        status = "infected"
                        signature = None
                    elif val.upper() == "OK":
                        status = "clean"
                        signature = None
                    else:
                        status = "infected"
                        signature = val
            elif isinstance(item, dict):
                signature = item.get("virus", None)
                status = "infected" if signature else "clean"
            else:
                payload = str(item).strip()
                if payload.upper() == "FOUND":
                    status = "infected"
                elif payload.upper() == "OK":
                    status = "clean"
                else:
                    status = "infected"
                    signature = payload

            if status == "clean":
                print(f"{path}: OK")
            else:
                print(f"{path}: {signature or 'Unknown'} FOUND")

            scan_results.append({"file": path, "status": status, "signature": signature})
            if status == "infected":
                infected_count += 1

    except Exception as exc:
        print(f"{path}: ERROR {exc}")
        scan_results.append({"file": path, "status": "error", "signature": str(exc)})

scan_summary["Infected files"] = str(infected_count)
scan_summary["Data scanned"] = format_size(data_scanned)
ratio = (data_scanned / data_scanned) if data_scanned > 0 else 0
scan_summary["Data read"] = f"{format_size(data_scanned)} (ratio {ratio:.2f}:1)"

scan_end = datetime.datetime.now()
scan_duration = (scan_end - scan_start).total_seconds()
scan_summary["Time"] = f"{scan_duration:.3f} sec"
scan_summary["End Date"] = scan_end.strftime("%Y:%m:%d %H:%M:%S")

for r in scan_results:
    r["scan_summary"] = scan_summary

for r in scan_results:
    if r["signature"]:
        r["signature"] = r["signature"].replace(".UNOFFICIAL", "")

if not args.no_summary:
    print_summary(scan_summary)

if args.pretty:
    print("\nScan results:")
    for r in scan_results:
        sig = r['signature'] if r['signature'] else 'None'
        print(f"{r['file']}: {r['status']} ({sig})")

if args.output:
    json_filename = os.path.abspath(args.output)
    output_dir = os.path.dirname(json_filename)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
else:
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = os.path.join(result_folder, f"ScanResults_{timestamp}.json")

temp_json_filename = f"{json_filename}.tmp"
with open(temp_json_filename, "w", encoding="utf-8") as f:
    json.dump(scan_results, f, indent=4)

os.replace(temp_json_filename, json_filename)

print(f"\nWrote results to {json_filename}")
