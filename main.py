# main.py

import sys
import traceback
import tkinter as tk
from tkinter import messagebox

from gui.app import NetScopeApp
from utils.logger import Logger


# Global logger instance
logger = Logger()


# ---------------------------
# GLOBAL EXCEPTION HANDLER
# ---------------------------
def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Catch ALL unhandled errors (even thread crashes)
    """
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))

    print("[FATAL ERROR]")
    print(error_msg)

    # Log error
    try:
        logger.log_error(error_msg)
    except:
        pass

    # Show popup (safe)
    try:
        messagebox.showerror("Application Error", str(exc_value))
    except:
        pass


# ---------------------------
# SAFE SHUTDOWN
# ---------------------------
def on_close(app, root):
    """
    Clean shutdown of all components
    """
    try:
        print("[+] Shutting down...")

        # Stop sniffer
        if app.sniffer and app.sniffer.is_running():
            app.sniffer.stop()

        # Shutdown logger
        logger.shutdown()

    except Exception as e:
        print(f"[Shutdown Error] {e}")

    finally:
        root.destroy()
        sys.exit(0)


# ---------------------------
# MAIN APP START
# ---------------------------
def main():
    # Attach global exception handler
    sys.excepthook = handle_exception

    try:
        print("[+] Initializing NetScope...")

        root = tk.Tk()

        # High DPI scaling (important for Windows)
        try:
            root.tk.call("tk", "scaling", 1.2)
        except:
            pass

        # Improve window appearance
        root.configure(bg="#1e1e2f")

        app = NetScopeApp(root)

        # Handle close properly
        root.protocol("WM_DELETE_WINDOW", lambda: on_close(app, root))

        print("[+] NetScope started successfully")
        print("[INFO] Monitoring network traffic...")

        root.mainloop()

    except Exception as e:
        error_msg = f"[Startup Error] {e}"
        print(error_msg)

        try:
            logger.log_error(error_msg)
        except:
            pass

        try:
            messagebox.showerror("Startup Error", str(e))
        except:
            pass


# ---------------------------
# ENTRY POINT
# ---------------------------
if __name__ == "__main__":
    main()