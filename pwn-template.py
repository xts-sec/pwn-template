from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Find offset to EIP/RIP for buffer overflows
def find_ip(payload, architecture):
    # Launch process 
    p = process(exe)
    # Send payload after this line is received [CHANGE THIS]
    p.sendlineafter("Whatever the program says", payload) 
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    if architecture == "x86":
        ip_offset = cyclic_find(p.corefile.pc)  # x86
    elif architecture == "x64":
        ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    else:
        print("Invalid architecture value supplied. Breaking.")
        exit(1)
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# ===========================================================
#                    CONFIG GOES HERE
# ===========================================================

# Specify GDB script here (breakpoints etc)
gdbscript = '''
break main
continue
'''.format(**locals())

# Binary filename [CHANGE THIS]
exe = './FileName'

# File architecture (x86 or x64)
architecture = "x86"

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=True)

# Change logging level to help with debugging (warning < info < debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT STARTS HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(1000), architecture)

# Start program
io = start()

#building the payload

pprint(elf.got)


payload = flat({
    offset: [

    ]
})

io.interactive()
