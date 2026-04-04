"""ai-dlp-proxy 엔트리포인트."""

import sys
from pathlib import Path

# mitmproxy_lib/ 임베드 경로를 sys.path에 추가
_LIB_DIR = Path(__file__).resolve().parent.parent.parent / "mitmproxy_lib"
if _LIB_DIR.is_dir() and str(_LIB_DIR) not in sys.path:
    sys.path.insert(0, str(_LIB_DIR))


def main():
    print("ai-dlp-proxy: not implemented yet")


if __name__ == "__main__":
    main()
