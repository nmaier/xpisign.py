import os


def relfile(fn):
    return os.path.join(os.path.dirname(__file__), fn)
