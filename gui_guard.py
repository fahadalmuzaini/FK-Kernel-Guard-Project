#!/usr/bin/env python3
import sys

print("\033[1;36m╔════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\033[0m")
print("\033[1;33m║  🛡️   FK-KERNEL GUARD — eBPF Real-Time Behavioral Threat & Process Monitor                         ║\033[0m")
print("\033[1;37m║  Developed by: Fahad Khuwaylid Almuzaini | Institution: Gulf Colleges                              ║\033[0m")
print("\033[1;36m╚════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\033[0m\n")

print("\033[1;37m┌──────────┬──────────┬──────────┬─────────────────┬─────────────────────────────────────────────────┐\033[0m")
print("\033[1;37m│ \033[1;33mSYSTEM   \033[1;37m│ \033[1;33mSTATUS   \033[1;37m│ \033[1;33mPID      \033[1;37m│ \033[1;33mPROCESS (COMM)  \033[1;37m│ \033[1;33mEXECUTABLE PATH                                 \033[1;37m│\033[0m")
print("\033[1;37m├──────────┼──────────┼──────────┼─────────────────┼─────────────────────────────────────────────────┤\033[0m")

try:
    for line in sys.stdin:
        line_clean = line.strip()
        if "FK-Kernel-Guard" in line_clean or "PID:" in line_clean:
            try:
                status_str = "\033[1;31mBLOCKED \033[0m" if "BLOCKED" in line_clean else "\033[1;32mALLOWED \033[0m"
                
                pid = line_clean.split("PID:")[1].split("|")[0].strip() if "PID:" in line_clean else "N/A"
                comm = line_clean.split("COMM:")[1].split("|")[0].strip() if "COMM:" in line_clean else "N/A"
                path = line_clean.split("PATH:")[1].strip() if "PATH:" in line_clean else "N/A"
                
                pid_fmt = pid[:8].ljust(8)
                comm_fmt = comm[:15].ljust(15)
                path_fmt = path[:47].ljust(47)
                
                print(f"\033[1;37m│\033[0m FK-Guard \033[1;37m│\033[0m {status_str}\033[1;37m│\033[0m {pid_fmt} \033[1;37m│\033[0m {comm_fmt} \033[1;37m│\033[0m {path_fmt} \033[1;37m│\033[0m")
                sys.stdout.flush()
            except Exception:
                continue
except KeyboardInterrupt:
    pass
finally:
    print("\033[1;37m└──────────┴──────────┴──────────┴─────────────────┴─────────────────────────────────────────────────┘\033[0m")
    print("\n\033[1;33m[*] FK-Kernel Guard Monitoring Stopped. Rights Reserved to Fahad Khuwaylid Almuzaini.\033[0m")
