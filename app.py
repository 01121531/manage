"""Clean platform-only entry point for the packaged Windows application."""

import sys
import tkinter as tk

from platform_desktop import PlatformDesktopApp
from update_client import (
    apply_update_cli,
    cleanup_update_cache,
    confirm_update_startup,
    consume_update_notice,
)


def main() -> None:
    if "--apply-update" in sys.argv[1:]:
        raise SystemExit(apply_update_cli(sys.argv[1:]))
    arguments = sys.argv[1:]
    ready_token = None
    if arguments.count("--update-ready-token") == 1:
        index = arguments.index("--update-ready-token")
        if index + 1 < len(arguments):
            ready_token = arguments[index + 1]
    notice = consume_update_notice()
    cleanup_update_cache()
    root = tk.Tk()
    desktop = PlatformDesktopApp(root)

    def finish_startup() -> None:
        if ready_token is not None:
            confirm_update_startup(ready_token)
        if notice is not None:
            desktop.show_startup_notice(notice)

    root.after_idle(finish_startup)
    root.mainloop()


if __name__ == "__main__":
    main()
