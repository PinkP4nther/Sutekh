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
