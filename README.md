linux-re-101
============

Work in progress as I am actively collecting these.

#### Keep these handy
- "Executable and Linkable Format (ELF)" http://www.skyfree.org/linux/references/ELF_Format.pdf or http://www.muppetlabs.com/~breadbox/software/ELF.txt (I like .txt more)
- "System V ABI x86-64 Linux" http://www.x86-64.org/documentation/abi.pdf

#### Keep these somewhere in the closet
- "MIPS documentation" http://www.linux-mips.org/pub/linux/mips/doc/ABI/
- "ELF for the ARM" http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044e/IHI0044E_aaelf.pdf
- "ELF for the ARM64" http://infocenter.arm.com/help/topic/com.arm.doc.ihi0056b/IHI0056B_aaelf64.pdf
- "How to write shared libraries" by Ulrich Drepper http://www.akkadia.org/drepper/dsohowto.pdf    

#### Basics

1. *Optional*: "Gentle Introduction to x86-64 Assembly" http://www.x86-64.org/documentation/assembly.html 
- *Optional*: "Guide to x86 assembly" http://www.cs.virginia.edu/~evans/cs216/guides/x86.html
- *Optional*: "Assembly x86_64 programming for Linux" http://0xax.blogspot.sk/p/assembly-x8664-programming-for-linux.html
- "The dissection of a simple hello world ELF file" https://github.com/mewrev/dissection and "ELF101" http://imgur.com/a/JEObT
- https://www.cs.stevens.edu/~jschauma/631/elf.html
- "A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux" http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
- "Startup state of a Linux/i386 ELF binary" http://asm.sourceforge.net/articles/startup.html and http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html
- "Stack frame layout on x86-64" http://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64
- "Anatomy of a system call, part 1" http://lwn.net/Articles/604287/
- "Anatomy of a system call, part 2" http://lwn.net/SubscriberLink/604515
- "About ELF auxiliary vectors" http://articles.manugarg.com/aboutelfauxiliaryvectors.html
- "What is linux-gate.so.1?" http://www.trilithium.com/johan/2005/08/linux-gate/
- "Understanding ld-linux.so.2 " http://www.cs.virginia.edu/~dww4s/articles/ld_linux.html
- "Understanding Linux ELF RTLD internals" http://s.eresi-project.org/inc/articles/elf-rtld.txt
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
- "Linux on the Half-ELF" http://mammon.github.io/tales/linux_re.txt
- "Linkers - 20 parts" http://www.airs.com/blog/page/4?s=linkers
- "Quickly determine the capabilities of an ELF binary through static analysis" http://elfparser.com/

#### Anti-debugging, infection techniques, viruses, obfuscation, encryption, shellcode and exploits

1. "LINUX ANTI-DEBUGGING TECHNIQUES (FOOLING THE DEBUGGER)" http://www.ouah.org/linux-anti-debugging.txt
- "ptrace() tutorial" http://mikecvet.wordpress.com/2010/08/14/ptrace-tutorial/
- "ptrace() on 64-bit system" http://theantway.com/2013/01/notes-for-playing-with-ptrace-on-64-bits-ubuntu-12-10/
- "Linux x86 run-time process manipulation" http://hick.org/code/skape/papers/needle.txt
- "UNIX VIRUSES" http://ouah.org/unix-viruses.txt
- "Linux viruses - ELF file format" by Marius Van Oers http://www.mcafee.com/us/resources/white-papers/wp-linux-viruses-elf-file-format.pdf
- "UNIX ELF PARASITES AND VIRUS" http://ouah.org/elf-pv.txt
- "Abusing .CTORS and .DTORS for fun 'n profit" http://vxer.org/lib/viz00.html
- "Cheating the ELF Subversive Dynamic Linking to Libraries" http://www.ouah.org/subversiveld.pdf
- "Reverse of a coin: A short note on segment alignment" http://vxheavens.com/lib/vhe04.html
- "The WIT virus" http://vanilla47.com/PDFs/Viruses In Linux PDFs/The WIT Virus.pdf
- "Caveat virus" http://vxer.org/herm1t/caveat_en.html
- "Infecting ELF-files using function padding for Linux" http://vxer.org/lib/vhe00.html
- "Injected Evil (executable files infection)" http://vxheaven.org/lib/vzo08.html
- "INT 0x80? No, thank you! aka Pilot" http://vxer.org/herm1t/pilot_en.html
- "From position-independent to self-relocatable viral code" http://vxer.org/lib/vhe08.html
- Source code of infection techniques http://vxer.org/herm1t/examples.tar.gz by herm1t
- "Runtime binary encryption" http://phrack.org/issues/58/5.html
- "Next-Gen Runtime Binary Encryption" http://phrack.org/issues/63/13.html
- "Binary Protection Schemes" http://indra.linuxstudy.pe.kr/study/Binary%20Protection%20Schemes.pdf
- "The Cerberus ELF interface" http://phrack.org/issues/61/8.html#article
- "Malicious Code Injection via /dev/mem" http://www.blackhat.com/presentations/bh-europe-09/Lineberry/BlackHat-Europe-2009-Lineberry-code-injection-via-dev-mem.pdf
- VX Heaven collection of viruses http://vxer.org/vl.php?dir=Virus.Linux
- http://vxer.org/herm1t/ (Lacrimae is mind-bending)
- "Shiva - Advances in ELF Binary Encryption" https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-mehta/bh-us-03-mehta.pdf
- "Burneye protector" http://packetstormsecurity.com/files/30648/burneye-1.0.1-src.tar.bz2.html
- "ELF Encrypter" http://elf-encrypter.sourceforge.net/
- "An unofficial analysis of the Retaliation Virus (Authored by JPanic)" http://vxer.org/lib/vrn01.html or http://www.bitlackeys.org/papers/retaliation.txt
- "LD_NOT_PRELOADED_FOR_REAL" http://haxelion.eu/article/LD_NOT_PRELOADED_FOR_REAL/
- "midgetpack is a multiplatform secure ELF packer" https://github.com/arisada/midgetpack
- "Linux x86 Reverse Engineering - Shellcode Disassembling and XOR decryption" https://www.exploit-db.com/docs/33429.pdf
- "Shellcoding in Linux" https://www.exploit-db.com/docs/21013.pdf
- "Linux (x86) Exploit Development Series" https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/
- "Linux 64-bit Return Oriented Programming" https://crypto.stanford.edu/~blynn/rop/
- http://www.bitlackeys.org
- "Kickers of ELF" http://www.muppetlabs.com/~breadbox/software/elfkickers.html

#### Kernel rootkits, LKMs & stuff

1. *Optional*: "A series of posts about the linux kernel and its insides." http://0xax.gitbooks.io/linux-insides/content/index.html
- *Optional*: "Kernel hacking HOWTO" http://kernelnewbies.org/New_Kernel_Hacking_HOWTO
- "Anatomy of the Linux kernel" http://www.ibm.com/developerworks/linux/library/l-linux-kernel/index.html
- "Linux process management" http://www.ibm.com/developerworks/linux/library/l-linux-process-management/index.html
- "Linux processes" http://www.cs.columbia.edu/~junfeng/10sp-w4118/lectures/l07-proc-linux.pdf
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
- "(nearly) Complete Linux Loadable Kernel Modules" https://www.thc.org/papers/LKM_HACKING.html
- Check the README for more https://github.com/citypw/citypw-SCFE/tree/master/security/rootkit/hide_file
- "UNIX and Linux based rootkits" http://www.kernelhacking.com/rodrigo/docs/StMichael/BuntenSlides.pdf
- "Sample rootkit for linux" https://github.com/ivyl/rootkit/
- "Linux Rootkit Scanner" https://github.com/dgoulet/kjackal
- "Writing a LKM rootkit that uses LSM hooks" http://vladz.devzero.fr/015_lsm-backdoor.html
- "TCP/UDP symmetric encryption tunnel wrapper" https://github.com/chokepoint/CryptHook
- "Userland rootkit based off of the original LD_PRELOAD technique from Jynx rootkit" https://github.com/chokepoint/azazel
- "an experimental linux kernel module (rootkit) with a keylogger and built-in IRC bot" https://github.com/bones-codes/the_colonel
- "An LKM rootkit targeting Linux 2.6/3.x on x86(_64), and ARM" https://github.com/mncoppola/suterusu
- "Linux rootkit adapted for 2.6 and 3.x" https://github.com/trimpsyw/adore-ng
- https://github.com/mfontanini/Programs-Scripts/blob/master/rootkit/rootkit.c
- "Linux: Creating an entry in /proc file system (Part 1: The hello_proc pseudo file)" http://pointer-overloading.blogspot.in/2013/09/linux-creating-entry-in-proc-file.html
- Answer to "Ripping out the hidden kernel module by reading kernel memory directly?" http://stackoverflow.com/a/18464599
- "MoVP 1.5 KBeast Rootkit, Detecting Hidden Modules, and sysfs " http://volatility-labs.blogspot.sk/2012/09/movp-15-kbeast-rootkit-detecting-hidden.html
- "tool to locally check for signs of a rootkit" http://www.chkrootkit.org/
- "a Unix-based tool that scans for rootkits, backdoors and possible local exploits" http://rkhunter.sourceforge.net/

#### Crackmes and challenges

1. "Exercises for learning Reverse Engineering and Exploitation." https://github.com/wapiflapi/exrs
- "IOLI crackme" http://dustri.org/b/files/IOLI-crackme.tar.gz
- http://security.cs.rpi.edu/courses/binexp-spring2015/lectures/2/challenges.zip from "Modern Binary Exploitation"
- "Exercises" section in http://beginners.re/Reverse_Engineering_for_Beginners-en.pdf

#### Analyzes & "hands-on"

1. "Reverse engineering with Radare2, part 1" http://samsymons.com/blog/reverse-engineering-with-radare2-part-1/
- "Defeating IOLI with Radare2" http://dustri.org/b/defeating-ioli-with-radare2.html
- "Using radare2 to pwn things" http://radare.today/using-radare2/
- "Pwning With Radare2" http://crowell.github.io/blog/2014/11/23/pwning-with-radare2/
- "At Gunpoint Hacklu 2014 With Radare2" http://crowell.github.io/blog/2014/11/23/at-gunpoint-hacklu-2014-with-radare2/
- "manual binary mangling with radare" http://phrack.org/issues/66/14.html#article
- "Analysis of an unknown binary, for the HoneyNet Reverse Challenge" http://old.honeynet.org/reverse/results/sol/sol-06/analysis.html

#### Other
1. "ElfParser blog" http://www.blog.elfparser.com/ 
- binary samples for testing https://github.com/JonathanSalwan
- "Building a concrete alternative to IDA - Radare2 to the rescue!" https://recon.cx/2015/slides/recon2015-04-jeffrey-crowell-julien-voisin-Radare2-building-a-new-IDA.pdf
- "Introduction to Reverse Engineering Software in Linux" http://ouah.org/RevEng/ 
- "Intro to Radare2" http://rada.re/get/condret-r2talk.pdf
- "Radare2 baby steps" http://maijin.fr/slides.pdf
- "Modern Binary Exploitation" http://security.cs.rpi.edu/courses/binexp-spring2015/
- "GCC protections" http://www.sawbox.net/s0t/txt/ssp.html
- "100 GDB tips" https://github.com/hellogcc/100-gdb-tips/tree/master/src
- https://github.com/citypw/citypw-SCFE/tree/master/security
- http://mammon.github.io/
- https://code.google.com/p/corkami/downloads/list & https://code.google.com/p/corkami/source/browse/#svn/trunk/wip/elf
- "How to detect virtualization on Linux" http://www.dmo.ca/blog/detecting-virtualization-on-linux/
- "Mechanisms to determine VMWare VM" http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458
- "Hacking the wholism of GNU/Linux net*" http://kernelnewbies.org/Networking?action=AttachFile&do=get&target=hacking_the_wholism_of_linux_net.txt
- "Linux Device Drivers" https://lwn.net/Kernel/LDD3/
- "Toolkit to detect/crash/attack GNU debugging tools" https://github.com/jvoisin/pangu
- "ld-linux code injector" https://github.com/sduverger/ld-shatner
- "Linux Data Structures" http://tldp.org/LDP/tlk/ds/ds.html
- "Dumps the contents of a SysV shared memory segment" https://github.com/niklata/shmcat
- "ELF Eccentricities - Julian Bangert, Sergey Bratus" https://www.youtube.com/watch?v=4LU6N6THh2U
- https://github.com/jbangert/mithril
- "ELF vs. Mach-O" http://timetobleed.com/dynamic-linking-elf-vs-mach-o/
- "ELF vs. Mach-O 2" http://timetobleed.com/dynamic-symbol-table-duel-elf-vs-mach-o-round-2/
- "Measuring Linux at Runtime" http://www.unixist.com/security/measuring-linux-at-runtime/index.html coupled with https://github.com/unixist/camb
- http://0x90909090.blogspot.fr/2015/07/no-one-expect-command-execution.html
- "Emulating Linux MIPS in Perl" http://schplog.schmorp.de/2015-06-08-emulating-linux-mips-in-perl-1.html
- "Crypto 101" https://www.crypto101.io/
- "REMnux 6" https://zeltser.com/remnux-v6-release-for-malware-analysis/
- "Practice and learning in the world of C RE and exploit analysis " https://github.com/211217613/C-Hacking
- http://io.smashthestack.org/
- http://overthewire.org/wargames/bandit/
- https://people.debian.org/~aurel32/qemu/

#### Books
1. "Malware Forensics Field Guide for Linux Systems" by Cameron H. Malin, Eoghan Casey, James M. Aquilina
- "Linux (Bezpečnosť a exploity)" by Miroslav Dobšíček and Radim Ballner
- "Hacking: The Art of Exploitation" by Jon Erickson
- "The Shellcoder's Handbook: Discovering and Exploiting Security Holes" by Chris Anley, John Heasman, Felix Lindner
- "The Linux Programming Interface" by Michael Kerrisk
