import os
import subprocess
import time
import logging
import random
from typing import Dict, List, Any, Optional

logger = logging.getLogger("KavachDetonator")

class ApexIntentFuzzer:
    """
    Apex Intent & IPC Fuzzer:
    Active evasion bypassing component that analyzes exported and non-exported
    activities, broadcast receivers, and background services, firing targeted
    and fuzzed intent triggers with FLAG_INCLUDE_STOPPED_PACKAGES (0x00000020)
    to force dormant malware logic to awaken inside the sandbox window.
    """

    DEFAULT_CRITICAL_ACTIONS = [
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.QUICKBOOT_POWERON",
        "android.intent.action.REBOOT",
        "android.intent.action.SCREEN_ON",
        "android.intent.action.USER_PRESENT",
        "android.intent.action.BATTERY_LOW",
        "android.intent.action.POWER_CONNECTED",
        "android.provider.Telephony.SMS_RECEIVED",
        "android.net.conn.CONNECTIVITY_CHANGE",
        "android.intent.action.PACKAGE_ADDED"
    ]

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path

    def run_adb_command(self, cmd: List[str], timeout: int = 5) -> tuple[bool, str, str]:
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return res.returncode == 0, res.stdout.strip(), res.stderr.strip()
        except Exception as e:
            return False, "", str(e)

    def extract_manifest_targets(self, package_name: str) -> Dict[str, List[str]]:
        """
        Queries target package components directly via ADB dumpsys package.
        """
        targets = {
            "receivers": [],
            "activities": [],
            "services": []
        }
        
        success, stdout, _ = self.run_adb_command([
            self.adb_path, "shell", "dumpsys", "package", package_name
        ], timeout=8)
        
        if not success or not stdout:
            return targets

        current_section = None
        for line in stdout.splitlines():
            line_str = line.strip()
            if "Receiver Resolver Table:" in line:
                current_section = "receivers"
            elif "Activity Resolver Table:" in line:
                current_section = "activities"
            elif "Service Resolver Table:" in line:
                current_section = "services"
            elif "Key Set Manager:" in line or "Permissions:" in line:
                current_section = None

            if current_section and package_name in line_str:
                parts = line_str.split()
                for p in parts:
                    if package_name in p and "/" in p:
                        component = p.split()[0]
                        if component not in targets[current_section]:
                            targets[current_section].append(component)

        return targets

    def fuzz_package(
        self,
        package_name: str,
        manifest_targets: Optional[Dict[str, List[str]]] = None,
        max_triggers: int = 6
    ) -> List[Dict[str, Any]]:
        """
        Fires high-impact intent stimulus and fuzzed broadcast events to wake sleeping components.
        """
        executed_stimuli = []
        logger.info(f"[Apex-Fuzzer] Initiating active IPC stimulus fuzzing for {package_name}...")

        # 1. Fire Critical Banking Trojan Broadcast Triggers (with stopped package flag 0x00000020)
        for action in self.DEFAULT_CRITICAL_ACTIONS[:max_triggers]:
            cmd = [
                self.adb_path, "shell", "am", "broadcast",
                "-a", action,
                "-p", package_name,
                "-f", "0x00000020"
            ]
            logger.info(f"[Apex-Fuzzer] Firing broadcast intent: {action} (flag=0x00000020)")
            success, stdout, _ = self.run_adb_command(cmd)
            executed_stimuli.append({
                "type": "broadcast",
                "action": action,
                "flags": "0x00000020",
                "target": package_name,
                "status": "DELIVERED" if success else "FAILED"
            })
            time.sleep(0.3)

        # 2. Stimulate Discovered Explicit Receivers
        if manifest_targets and manifest_targets.get("receivers"):
            for receiver in manifest_targets["receivers"][:4]:
                fuzz_extra_key = f"extra_fuzz_{random.randint(100, 999)}"
                fuzz_extra_val = f"payload_{random.randint(1000, 9999)}"
                cmd = [
                    self.adb_path, "shell", "am", "broadcast",
                    "-n", receiver,
                    "-f", "0x00000020",
                    "--es", fuzz_extra_key, fuzz_extra_val
                ]
                logger.info(f"[Apex-Fuzzer] Stimulating targeted receiver: {receiver}")
                success, _, _ = self.run_adb_command(cmd)
                executed_stimuli.append({
                    "type": "targeted_receiver",
                    "receiver": receiver,
                    "extras": {fuzz_extra_key: fuzz_extra_val},
                    "status": "DELIVERED" if success else "FAILED"
                })
                time.sleep(0.3)

        # 3. Stimulate Exported Services
        if manifest_targets and manifest_targets.get("services"):
            for service in manifest_targets["services"][:3]:
                cmd = [
                    self.adb_path, "shell", "am", "startservice",
                    "-n", service
                ]
                logger.info(f"[Apex-Fuzzer] Stimulating background service: {service}")
                success, _, _ = self.run_adb_command(cmd)
                executed_stimuli.append({
                    "type": "service_start",
                    "service": service,
                    "status": "DELIVERED" if success else "FAILED"
                })
                time.sleep(0.3)

        logger.info(f"[Apex-Fuzzer] Completed {len(executed_stimuli)} IPC stimulus fuzzing events.")
        return executed_stimuli

if __name__ == "__main__":
    fuzzer = ApexIntentFuzzer()
    res = fuzzer.fuzz_package("com.mock.malware")
    print(res)
