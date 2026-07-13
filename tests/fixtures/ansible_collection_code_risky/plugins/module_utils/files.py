from pathlib import Path


def write_result(path, value):
    Path(path).write_text(value)
