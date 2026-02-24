from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="wsa-web", description="Start the Wi-Fi Attack Surface Analyzer Web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true", help="Auto-reload on code changes (dev)")
    args = p.parse_args(argv)

    import uvicorn

    uvicorn.run("wifi_surface_analyzer.web.app:app", host=args.host, port=args.port, reload=bool(args.reload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

