#!/usr/bin/env python3
"""
ZapGuard Web Server Launcher

Run this script to start the ZapGuard web interface.
Access at http://localhost:5005 or http://<your-ip>:5005

Usage:
    python run_web.py                      # Default: 0.0.0.0:5005
    python run_web.py --port 8080          # Custom port
    python run_web.py --host 127.0.0.1     # Localhost only
    python run_web.py --debug              # Enable debug mode
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from zapguard.web_app import run_server


def main():
    parser = argparse.ArgumentParser(
        description='ZapGuard Web Server - Vulnerability Fix Verification Tool'
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0 for all interfaces)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5005,
        help='Port to listen on (default: 5005)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with auto-reload'
    )

    args = parser.parse_args()

    print(f"""
    ╔═══════════════════════════════════════════════════════╗
    ║                  ZapGuard Web Server                   ║
    ║           Vulnerability Fix Verification Tool          ║
    ╠═══════════════════════════════════════════════════════╣
    ║  Server: http://{args.host}:{args.port:<5}                         ║
    ║  Debug:  {'Enabled' if args.debug else 'Disabled':<8}                                ║
    ╚═══════════════════════════════════════════════════════╝
    """)

    run_server(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
