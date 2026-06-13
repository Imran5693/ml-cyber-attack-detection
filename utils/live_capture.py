from pathlib import Path
from datetime import datetime
import subprocess


class LiveCapture:
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir).resolve()
        self.captures_dir = self.base_dir / "captures" / "live"
        self.captures_dir.mkdir(parents=True, exist_ok=True)

    def capture_to_csv(
        self,
        interface: str,
        duration: int = 5,
        output_prefix: str = "live_capture"
    ) -> Path:
        """
        Capture live packets using tshark and save directly to CSV.
        """

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.captures_dir / f"{output_prefix}_{timestamp}.csv"

        tshark_cmd = [
            "tshark",
            "-i", interface,
            "-f", "ip",
            "-a", f"duration:{duration}",
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=,",
            "-E", "quote=d",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.time_relative",
            "-e", "_ws.col.Info",
            "-e", "tcp.srcport",
            "-e", "frame.len",
            "-e", "tcp.flags",
            "-e", "tcp.dstport",
            "-e", "frame.time_delta",
        ]

        with open(output_file, "w", encoding="utf-8", newline="") as f:
            result = subprocess.run(
                tshark_cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True
            )

        if result.returncode != 0:
            raise RuntimeError(f"tshark capture failed: {result.stderr}")

        return output_file