from pykd import *
import sys

PAGE_SIZE = 0x1000

MEM_ACCESS_EXE = {
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}


def isPageExec(address):
    try:
        protect = getVaProtect(address)
    except:
        protect = 0x1
    if protect in MEM_ACCESS_EXE.keys():
        return True
    else:
        return False


def findRetn(pages):
    retn = []
    for page in pages:
        ptr = page
        while ptr < (page + PAGE_SIZE):
            b = loadSignBytes(ptr, 1)[0] & 0xff
            if b not in [0xc3, 0xc2]:
                ptr += 1
                continue
            else:
                retn.append(ptr)
                ptr += 1

    print("Found %d ret instructions" % len(retn))
    return retn


def getGadgets(addr):
    ptr = addr - 1
    dasm = disasm(ptr)
    gadget_size = dasm.length()
    print("Gadget size is: %x" % gadget_size)
    instr = dasm.instruction()
    print("Found instruction: %s" % instr)


if __name__ == '__main__':
    count = 0
    try:
        modname = sys.argv[1].strip()
    except IndexError:
        print("Syntax: %s modulename" % sys.argv[0])
        sys.exit()

    mod = module(modname)
    pages = []

    if mod:
        pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
        print("Total Memory Pages: %d" % pn)

        for i in range(0, pn):
            page = mod.begin() + i * PAGE_SIZE
            if isPageExec(page):
                pages.append(page)
        print("Executable Memory Pages: %d" % len(pages))

        ret_addresses = findRetn(pages)
        for ret_address in ret_addresses:
            getGadgets(ret_address)
            break
