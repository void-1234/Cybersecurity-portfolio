#team/purple 
**Related tools:** Ghira (Software Reverse Engineering) 

The room gives a binary file and the answer for the flag is the correct password that the program expects 

**Steps taken:**
1.  As it is a binary file used the strings command and it does not have the password.
2. Used Ghira and analyzed the main function in the binary file

**Code snippet:**
```
undefined8 main(void)

{
  int iVar1;
  char local_28 [32];
  
  fwrite("Password: ",1,10,stdout);
  __isoc99_scanf("DoYouEven%sCTF",local_28);
  iVar1 = strcmp(local_28,"__dso_handle");
  if ((-1 < iVar1) && (iVar1 = strcmp(local_28,"__dso_handle"), iVar1 < 1)) {
    printf("Try again!");
    return 0;
  }
  iVar1 = strcmp(local_28,"_init");
  if (iVar1 == 0) {
    printf("Correct!");
  }
  else {
    printf("Try again!");
  }
  return 0;
```

**Code explanation:**
- The program has 2 variables iVar1 and local_28. lcaol_28 saves the user input and iVar1 stores the string compare output
- The program prompts user to enter a password 
- scanf function saves the password in local_28
- Now in the line `scanf("DoYouEven%sCTF",local_28);` the scanf function checks the user input and if the user input  matches the pattern "DoYouEven%sCTF" it saves the user input in local_28 variable. 
>[!info] 
>scanf Example
>If the user inputs something that matches the pattern **Generic Example:** * `scanf("Age:%d", &myAge);`
>If the user types "Age:25", the number 25 is saved in `myAge`. If the user just types "25", it fails because it didn't see the word "Age:"
>strcmp Example
>`check = strcmp(user_color, "Red");`
If `user_color` is "Red", `check` becomes 0. If `user_color` is "Blue", `check` becomes 1

- Based on the example if the  user follows the pattern and types "DoYouEvenMypasswordCTF" the scanf saves MypasswordCTF to the local_28 variable. 
>[!info] 
>**%s**
>Matches a sequence of non-white-space characters; the next pointer must be a pointer to character array that is long enough to hold the input sequence and the terminating null byte ('\0'), which is added automatically. The input string stops at white space or at the maximum field width, whichever occurs first.
- If we look at the if condition it says, if the user input has the value of `_init` the  password is considered as correct 
- However based on the input  if we type DoYouEven_initCTF the local_28 will store `_initCTF` in the local_28 which is not equal to `_init`
- As per the scanf documentation the %s input terminates either if it doesn't have space or there is a white space.

**Final result:**
So based one that if i type **DoYouEven_init CTF** with a white space between  the `_init`
and CTF the %s will store only the `_init` value in local_28 variable which in turn returns the output as correct


