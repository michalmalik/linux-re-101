linux-re-101
============

Work in progress as I am actively collecting these.

#### Keep these two handy:
- "Executable and Linkable Format (ELF)" http://www.skyfree.org/linux/references/ELF_Format.pdf or http://www.muppetlabs.com/~breadbox/software/ELF.txt (I like .txt more)
- "System V ABI x86-64 Linux" http://www.x86-64.org/documentation/abi.pdf
    
#### Basics

1. Optional: "Gentle Introduction to x86-64 Assembly" http://www.x86-64.org/documentation/assembly.html 
- Optional: "Code as Art: Assembly x86_64 programming for Linux" http://0xax.blogspot.sk/p/assembly-x8664-programming-for-linux.html
- "The dissection of a simple hello world ELF file" https://github.com/mewrev/dissection and "ELF101" http://imgur.com/a/JEObT
- "A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux" http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
- "Startup state of a Linux/i386 ELF binary" http://asm.sourceforge.net/articles/startup.html and http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html
- "Stack frame layout on x86-64" http://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64
- "Anatomy of a system call, part 1" http://lwn.net/Articles/604287/
- "Anatomy of a system call, part 2" http://lwn.net/SubscriberLink/604515
- "About ELF auxiliary vectors" http://articles.manugarg.com/aboutelfauxiliaryvectors.html
- "What is linux-gate.so.1?" http://www.trilithium.com/johan/2005/08/linux-gate/
- "How statically linked programs run on Linux" http://eli.thegreenplace.net/2012/08/13/how-statically-linked-programs-run-on-linux
- "Static linking (x86) internals" http://sploitfun.blogspot.sk/2013/02/linking-with-static-library-internals.html
- "Dynamic linking (x86) internals" http://sploitfun.blogspot.sk/2013/06/dynamic-linking-internals.html
- "Static linking (x86_64) internals" http://sploitfun.blogspot.sk/2013/07/static-linking-x8664-internals.html
- "Dynamic linking and x86_64 internals" http://sploitfun.blogspot.sk/2013/07/dynamic-linking-x8664-internals.html
- "PLT and GOT - they key to code sharing and dynamic libraries" https://www.technovelty.org//linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html
- "Understanding x64 code models" http://eli.thegreenplace.net/2012/01/03/understanding-the-x64-code-models/
- "Load-time relocation of shared libraries " http://eli.thegreenplace.net/2011/08/25/load-time-relocation-of-shared-libraries
- "Position Independent Code (PIC) in shared libraries " http://eli.thegreenplace.net/2011/11/03/position-independent-code-pic-in-shared-libraries/
- "Position Independent Code (PIC) in shared libraries x64" http://eli.thegreenplace.net/2011/11/11/position-independent-code-pic-in-shared-libraries-on-x64/
- "LINUX ANTI-DEBUGGING TECHNIQUES (FOOLING THE DEBUGGER)" http://www.ouah.org/linux-anti-debugging.txt
- "ptrace() tutorial" http://mikecvet.wordpress.com/2010/08/14/ptrace-tutorial/
- "ptrace() on 64-bit system" http://theantway.com/2013/01/notes-for-playing-with-ptrace-on-64-bits-ubuntu-12-10/
- "Linux x86 run-time process manipulation" http://hick.org/code/skape/papers/needle.txt
- "Linux on the Half-ELF" http://mammon.github.io/tales/linux_re.txt

#### Infection techniques, viruses, obfuscation and encryption

1. "UNIX VIRUSES" http://ouah.org/unix-viruses.txt
- "Linux viruses - ELF file format" by Marius Van Oers http://www.mcafee.com/us/resources/white-papers/wp-linux-viruses-elf-file-format.pdf
- "UNIX ELF PARASITES AND VIRUS" http://ouah.org/elf-pv.txt
- "Abusing .CTORS and .DTORS for fun 'n profit" http://vxheaven.org/lib/viz00.html
- "Cheating the ELF Subversive Dynamic Linking to Libraries" http://www.ouah.org/subversiveld.pdf
- "Reverse of a coin: A short note on segment alignment" http://vxheavens.com/lib/vhe04.html
- "The WIT virus" http://vanilla47.com/PDFs/Viruses In Linux PDFs/The WIT Virus.pdf
- "Caveat virus" http://vxheaven.org/herm1t/caveat_en.html
- "Infecting ELF-files using function padding for Linux" http://vxheaven.org/lib/vhe00.html
- "INT 0x80? No, thank you! aka Pilot" http://vxheaven.org/herm1t/pilot_en.html
- "From position-independent to self-relocatable viral code" http://vxheaven.org/lib/vhe08.html
- Source code of infection techniques http://vxheaven.org/herm1t/examples.tar.gz by herm1t
- "Runtime binary encryption" http://phrack.org/issues/58/5.html
- "Next-Gen Runtime Binary Encryption" http://phrack.org/issues/63/13.html
- "Binary Protection Schemes" http://indra.linuxstudy.pe.kr/study/Binary%20Protection%20Schemes.pdf
- "The Cerberus ELF interface" http://phrack.org/issues/61/8.html#article
- "Malicious Code Injection via /dev/mem" http://www.blackhat.com/presentations/bh-europe-09/Lineberry/BlackHat-Europe-2009-Lineberry-code-injection-via-dev-mem.pdf
- VX Heaven collection of viruses http://vxheaven.org/vl.php?dir=Virus.Linux
- http://vxheaven.org/herm1t/ (Lacrimae is mind-bending)
- "Shiva - Advances in ELF Binary Encryption" https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-mehta/bh-us-03-mehta.pdf
- "Burneye protector" http://packetstormsecurity.com/files/30648/burneye-1.0.1-src.tar.bz2.html
- "ELF Encrypter" http://elf-encrypter.sourceforge.net/
- "An unofficial analysis of the Retaliation Virus (Authored by JPanic)" http://vxheaven.org/lib/vrn01.html or http://www.bitlackeys.org/papers/retaliation.txt
- "LD_NOT_PRELOADED_FOR_REAL" http://haxelion.eu/article/LD_NOT_PRELOADED_FOR_REAL/

#### Kernel rootkits, LKMs & stuff

1. "Kernel booting process part 1 "https://github.com/0xAX/linux-insides/blob/master/linux-bootstrap-1.md 
- "Kernel booting process part 2" https://github.com/0xAX/linux-insides/blob/master/linux-bootstrap-2.md
- "Anatomy of the Linux kernel" http://www.ibm.com/developerworks/linux/library/l-linux-kernel/index.html
- "Linux process management" http://www.ibm.com/developerworks/linux/library/l-linux-process-management/index.html
- "Linux processes" http://www.cs.columbia.edu/~junfeng/10sp-w4118/lectures/l07-proc-linux.pdf
- "Kernel hacking HOWTO" http://kernelnewbies.org/New_Kernel_Hacking_HOWTO
- "Kernel hacking" http://info.fs.tum.de/images/2/21/2011-01-19-kernel-hacking.pdf
- "Be a kernel hacker" http://www.linuxvoice.com/be-a-kernel-hacker/?pk_campaign=hn&pk_kwd=3
- "Day 5: I wrote a kernel module" http://jvns.ca/blog/2013/10/07/day-5-i-wrote-a-kernel-module/
- "Linux Rootkits 101" http://turbochaos.blogspot.sk/2013/09/linux-rootkits-101-1-of-3.html
- "Linux Rootkits 201" http://turbochaos.blogspot.sk/2013/10/writing-linux-rootkits-201-23.html
- "Linux Rootkits 301" http://turbochaos.blogspot.sk/2013/10/writing-linux-rootkits-301_31.html 
- "Handling Interrupt Descriptor Table for fun and profit" http://www.phrack.org/issues.html?issue=59&id=4
- "Intercepting System Calls and Dispatchers – Linux" https://ruinedsec.wordpress.com/2013/04/04/modifying-system-calls-dispatching-linux/
- "Linux Kernel Rootkits" http://www.la-samhna.de/library/rootkits/index.html
- "Linux Kernel Debugging using KGDB/GDB" http://sploitfun.blogspot.sk/2013/06/linux-kernel-debugging-using-kgdbgdb.html
- "Kernel instrumentation using kprobes" http://phrack.org/issues.html?issue=67&id=6#article
- "Infecting loadable kernel modules versions 2.6.x/3.0.x" http://phrack.org/issues/68/11.html#article

#### Other
1. "Introduction to Reverse Engineering Software in Linux" http://ouah.org/RevEng/ 
- "Intro to Radare2" http://rada.re/get/condret-r2talk.pdf
- "100 GDB tips" https://github.com/hellogcc/100-gdb-tips/tree/master/src
- https://github.com/citypw/citypw-SCFE/tree/master/security
- http://mammon.github.io/
- https://code.google.com/p/corkami/downloads/list & https://code.google.com/p/corkami/source/browse/#svn/trunk/wip/elf
- "Kickers of ELF" http://www.muppetlabs.com/~breadbox/software/elfkickers.html
- http://www.bitlackeys.orgp
- "How to detect virtualization on Linux" http://www.dmo.ca/blog/detecting-virtualization-on-linux/
- "Mechanisms to determine VMWare VM" http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458
- "Analysis of an unknown binary, for the HoneyNet Reverse Challenge" http://old.honeynet.org/reverse/results/sol/sol-06/analysis.html
- "Hacking the wholism of GNU/Linux net*" http://kernelnewbies.org/Networking?action=AttachFile&do=get&target=hacking_the_wholism_of_linux_net.txt
- "Linux Device Drivers" https://lwn.net/Kernel/LDD3/
- "Toolkit to detect/crash/attack GNU debugging tools" https://github.com/jvoisin/pangu
- "ld-linux code injector" https://github.com/sduverger/ld-shatner
- "Linux 64-bit Return Oriented Programming" https://crypto.stanford.edu/~blynn/rop/

#### Books
1.  "Malware Forensics Field Guide for Linux Systems" by Cameron H. Malin, Eoghan Casey, James M. Aquilina
- "Linux (Bezpečnosť a exploity)" by Miroslav Dobšíček and Radim Ballner
- "Hacking: The Art of Exploitation" by Jon Erickson
- "The Linux Programming Interface" by Michael Kerrisk
