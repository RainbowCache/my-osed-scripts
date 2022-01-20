from pykd import *
import sys

# To run:
# .load pykd
# !py <full_path_to_this_file>

PAGE_SIZE = 0x1000
MAX_GADGET_SIZE = 8
OUT_FILENAME = r"C:\Users\Offsec\Desktop\rop_gadgets.txt"
if len(OUT_FILENAME) > 0:
    OUT_FILE = open(OUT_FILENAME, "w")
else:
    OUT_FILE = sys.stdout



# MEM_ACCESS = {
# 0x1   : "PAGE_NOACCESS"                                                    ,
# 0x2   : "PAGE_READONLY"                                                    ,
# 0x4   : "PAGE_READWRITE"                                                   ,
# 0x8   : "PAGE_WRITECOPY"                                                   ,
# 0x10  : "PAGE_EXECUTE"                                                     ,
# 0x20  : "PAGE_EXECUTE_READ"                                                ,
# 0x40  : "PAGE_EXECUTE_READWRITE"                                           ,
# 0x80  : "PAGE_EXECUTE_WRITECOPY"                                           ,
# 0x101 : "PAGE_NOACCESS PAGE_GUARD"                                         ,
# 0x102 : "PAGE_READONLY PAGE_GUARD "                                        ,
# 0x104 : "PAGE_READWRITE PAGE_GUARD"                                        ,
# 0x108 : "PAGE_WRITECOPY PAGE_GUARD"                                        ,
# 0x110 : "PAGE_EXECUTE PAGE_GUARD"                                          ,
# 0x120 : "PAGE_EXECUTE_READ PAGE_GUARD"                                     ,
# 0x140 : "PAGE_EXECUTE_READWRITE PAGE_GUARD"                                ,
# 0x180 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD"                                ,
# 0x301 : "PAGE_NOACCESS PAGE_GUARD PAGE_NOCACHE"                            ,
# 0x302 : "PAGE_READONLY PAGE_GUARD PAGE_NOCACHE"                            ,
# 0x304 : "PAGE_READWRITE PAGE_GUARD PAGE_NOCACHE"                           ,
# 0x308 : "PAGE_WRITECOPY PAGE_GUARD PAGE_NOCACHE"                           ,
# 0x310 : "PAGE_EXECUTE PAGE_GUARD PAGE_NOCACHE"                             ,
# 0x320 : "PAGE_EXECUTE_READ PAGE_GUARD PAGE_NOCACHE"                        ,
# 0x340 : "PAGE_EXECUTE_READWRITE PAGE_GUARD PAGE_NOCACHE"                   ,
# 0x380 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD PAGE_NOCACHE"                   ,
# 0x701 : "PAGE_NOACCESS PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"          ,
# 0x702 : "PAGE_READONLY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"          ,
# 0x704 : "PAGE_READWRITE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"         ,
# 0x708 : "PAGE_WRITECOPY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"         ,
# 0x710 : "PAGE_EXECUTE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"           ,
# 0x720 : "PAGE_EXECUTE_READ PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"      ,
# 0x740 : "PAGE_EXECUTE_READWRITE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE" ,
# 0x780 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE" ,
# }

MEM_ACCESS_EXE = {
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

BAD = ["clts", "hlt", "lmsw", "ltr", "lgdt", "lidt", "lldt", "mov cr", "mov dr",
       "mov tr", "in ", "ins", "invlpg", "invd", "out", "outs", "cli", "sti"
                                                                       "popf", "pushf", "int", "iret", "iretd",
       "swapgs", "wbinvd", "call",
       "jmp", "leave", "ja", "jb", "jc", "je", "jr", "jg", "jl", "jn", "jo",
       "jp", "js", "jz", "lock", "enter", "wait", "???"]


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


def disasmGadget(addr, mod, fp):
    """
 Find gadgets. Start from a ret instruction and crawl back from 1 to
 MAX_GADGET_SIZE bytes. At each iteration disassemble instructions and
 make sure the result gadget has no invalid instruction and is still
 ending with a ret.
 @param addr: address of a ret instruction
 @param mod: module object from getModule
 @param fp: file object to log found gadgets
 @return: number of gadgets found starting from a specific address
 """
    count = 0
    for i in range(1, MAX_GADGET_SIZE):
        gadget = []
        ptr = addr - i
        dasm = disasm(ptr)
        gadget_size = dasm.length()
        while gadget_size <= MAX_GADGET_SIZE:
            instr = dasm.instruction()
            if any(bad in instr for bad in BAD):
                break
            gadget.append(instr)
            if instr.find("ret") != -1:
                break
            dasm.disasm()
            gadget_size += dasm.length()
        matching = [i for i in gadget if "ret" in i]
        if matching:
            count += 1
            fp.write("-" * 86 + "\r\n")
            for instr in gadget:
                try:
                    fp.write(str(instr) + "\r\n")
                except UnicodeEncodeError:
                    print(str(repr(instr)))
    return count


if __name__ == '__main__':
    count = 0
    try:
        modname = sys.argv[1].strip()
    except IndexError:
        print("Syntax: %s modulename" % sys.argv[0])
        sys.exit()

    try:
        MAX_GADGET_SIZE = int(sys.argv[2])
    except IndexError:
        pass
    except ValueError:
        print("Syntax: %s modulename [MAX_GADGET_SIZE]" % sys.argv[0])
        print("Example: %s ntdll 8" % sys.argv[0])
        print("MAX_GADGET_SIZE needs to be an integer")
        sys.exit()

    mod = module(modname)
    executable_pages = []

    if mod:
        pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
        print("Total Memory Pages: %d" % pn)

        print("Finding executable memory pages...")
        for i in range(0, pn):
            page = mod.begin() + i * PAGE_SIZE
            if isPageExec(page):
                executable_pages.append(page)
        print("Executable Memory Pages: %d" % len(executable_pages))

        print("Finding return addresses...")
        ret_addresses = findRetn(executable_pages)
        print("Return addresses found: %d" % len(ret_addresses))

        print("Finding ROP gadgets...")
        gadget_count = 0
        for ret_address in ret_addresses:
            gadget_count += disasmGadget(ret_address, mod, OUT_FILE)
            # getGadgets(ret_address)
        print("Gadgets found: %d" % gadget_count)

    print("Done!")
    OUT_FILE.close()
