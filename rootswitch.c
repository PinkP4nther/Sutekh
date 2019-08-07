#include <stdlib.h>
#include <stdio.h>

int main()
{
	system("umask 22");
	printf("[!] Switch hit!\n");
	system("su");
	system("umask 22");
	return 0;
}
