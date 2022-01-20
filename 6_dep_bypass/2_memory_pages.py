from pykd import *
import sys

PAGE_SIZE = 0x1000

if __name__ == '__main__':
    count = 0
    try:
        modname = sys.argv[1].strip()
    except IndexError:
        print("Syntax: %s modulename" % sys.argv[0])
        sys.exit()

    mod = module(modname)

    if mod:
        pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
        print("Total Memory Pages: %d" % pn)
