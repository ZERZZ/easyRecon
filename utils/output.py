import shutil
import re
import builtins
import sys

class Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    BLUE   = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN   = "\033[36m"

## Utility functions for consistent output formatting for whole tool 
def _width():
    return shutil.get_terminal_size((80, 20)).columns


def _colorize_markers(text):
    text = re.sub(r"\[\+\]", f"{Color.BOLD}{Color.GREEN}[+]{Color.RESET}", text)
    text = re.sub(r"\[\-\]", f"{Color.BOLD}{Color.RED}[-]{Color.RESET}", text)
    text = re.sub(r"\[\*\]", f"{Color.BOLD}{Color.BLUE}[*]{Color.RESET}", text)
    text = re.sub(r"\[\!\]", f"{Color.BOLD}{Color.RED}[!]{Color.RESET}", text)
    text = re.sub(r"\[AI\]", f"{Color.BOLD}{Color.MAGENTA}[AI]{Color.RESET}", text)
    text = re.sub(r"\[WARNING\]", f"{Color.BOLD}{Color.RED}[WARNING]{Color.RESET}", text)
    return text


_original_print = builtins.print


def print(*args, **kwargs):
    formatted = []

    add_blank_line = False
    for arg in args:
        if isinstance(arg, str):
            arg = _colorize_markers(arg)
            # check if line contains [etc] that requires spacing
            if re.search(r"\[\+\]|\[\-\]|\[\*\]", arg):
                add_blank_line = True
        formatted.append(arg)

    try:
        _original_print(*formatted, **kwargs)
    except BlockingIOError:
        # fallback for large output to prevent crashes
        msg = " ".join(str(x) for x in formatted)
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()

    if add_blank_line:
        try:
            _original_print()
        except BlockingIOError:
            sys.stdout.write("\n")
            sys.stdout.flush()

## section header for each module 
def section(title):
    width = _width()
    line = "═" * width

    _original_print()
    _original_print(f"{Color.BLUE}{Color.BOLD}{line}{Color.RESET}")
    _original_print(f"{Color.BLUE}{Color.BOLD}[ {title.upper()} ]{Color.RESET}")
    _original_print(f"{Color.BLUE}{Color.BOLD}{line}{Color.RESET}")
    _original_print()

# for top target name
def banner(target):
    width = _width()
    line = "═" * width

    _original_print(f"{Color.BOLD}{line}{Color.RESET}")
    _original_print(f"{Color.BOLD} Target: {target}{Color.RESET}")
    _original_print(f"{Color.BOLD}{line}{Color.RESET}")