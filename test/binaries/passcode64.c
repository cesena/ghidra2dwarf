#include <stdio.h>
#include <stdlib.h>

/*
padding
























































*/
































































































void login(void)

{
  int passcode1;
  int passcode2;
  
  printf("enter passcode1 : ");
  scanf("%d",&passcode1);
  fflush(stdin);
  printf("enter passcode2 : ");
  scanf("%d",&passcode2);
  puts("checking...");
  if ((passcode1 == 0x528e6) && (passcode2 == 0xcc07c9)) {
    puts("Login OK!");
    system("/bin/cat flag");
    return;
  }
  puts("Login Failed!");
                    /* WARNING: Subroutine does not return */
  exit(0);
}



void welcome(void)

{
  char asd[100];
  char * name = asd;
  int local_10;
  
  //local_10 = *(int *)(in_GS_OFFSET + 0x14);
  printf("enter you name : ");
  scanf("%100s",name);
  printf("Welcome %s!\n",name);
  //if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
  //  __stack_chk_fail();
  //}
  return;
}



int main(void)

{
  puts("Toddler\'s Secure Login System 1.0 beta.");
  welcome();
  login();
  puts("Now I can safely trust you that you have credential :)");
  return 0;
}
