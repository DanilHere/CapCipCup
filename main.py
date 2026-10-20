# Name        : CapCipCup
# Version     : 1.0
# Description : Network monitoring and intrusion detection toolkit
# Date Created: 21-September-2026

import argparse

from modules.sniff_mode import run as run_sniff
from modules.ids_mode import run as run_ids


def main():
    parser = argparse.ArgumentParser(
        description="CapCipCup - Detect and Protect Your System or Network"
    )

    parser.add_argument(
        "--sniff",
        action="store_true",
        help="Start packet sniffing mode",
    )

    parser.add_argument(
        "--ids",
        action="store_true",
        help="Start IDS mode with terminal dashboard",
    )

    args = parser.parse_args()

    if args.sniff:
        run_sniff()
    elif args.ids:
        run_ids()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
