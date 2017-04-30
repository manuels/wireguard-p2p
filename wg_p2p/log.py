import sys

def info(msg, *args):
    print(msg.format(*args), file=sys.stderr)

debug = info

