"""Clean platform-only entry point for the packaged Windows application."""

import sys
import tkinter as tk

from platform_desktop import PlatformDesktopApp
from update_client import apply_update_cli, cleanup_update_cache


def main() -> None:
    if "--apply-update" in sys.argv[1:]:
        raise SystemExit(apply_update_cli(sys.argv[1:]))
    cleanup_update_cache()
    root = tk.Tk()
    PlatformDesktopApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
