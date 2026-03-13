import shutil
import re
import builtins

class Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    BLUE   = "\033[34m"
    CYAN   = "\033[36m"

## Utility functions for consistent output formatting for whole tool 
def _width():
    return shutil.get_terminal_size((80, 20)).columns


def _colorize_markers(text):
    text = re.sub(r"\[\+\]", f"{Color.GREEN}[+]{Color.RESET}", text)
    text = re.sub(r"\[\-\]", f"{Color.RED}[-]{Color.RESET}", text)
    text = re.sub(r"\[\*\]", f"{Color.BLUE}[*]{Color.RESET}", text)
    text = re.sub(r"\[\!\]", f"{Color.RED}[!]{Color.RESET}", text)
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

    _original_print(*formatted, **kwargs)
    if add_blank_line:
        _original_print()  # add a blank line only after [etc] lines

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