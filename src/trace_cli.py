import argparse
from pathlib import Path
from datetime import datetime, timezone

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=["hello"])
    args = parser.parse_args()

    if args.cmd == "hello":
        now = datetime.now(timezone.utc).isoformat()
        out_dir = Path("out")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "hello.txt").write_text(f"TRACE CLI is working. UTC={now}\n", encoding="utf-8")
        print("✅ TRACE CLI is working. Wrote out/hello.txt")

if __name__ == "__main__":
    main()
