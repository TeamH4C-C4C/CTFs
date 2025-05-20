## solution

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s1[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v5; // [rsp+108h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  friendlyFunction(argc, argv, envp);
  puts("What is ze passcode monsieur?");
  __isoc99_scanf("%255s", s1);
  encrypt(s1);
  if ( !strcmp(s1, "brigade") )
    puts("correct password");
  else
    puts("wrong password");
  return 0;
}
```
위처럼 단순하게 encrypt 후 비교하는 로직을 가지고 있다.
```c
int __fastcall encrypt(const char *a1)
{
  size_t i; // rax
  size_t v3; // [rsp+18h] [rbp-8h]

  v3 = 0LL;
  for ( i = strlen(a1); v3 < i; i = strlen(a1) )
  {
    a1[v3] ^= 0x50u; // [A]
    putchar(a1[v3++]);
  }
  return putchar(10);
}
```
[A] 에서 처럼 0x50씩 xor하는 단순한 로직임을 알 수 있다.

### sol.py

```py
target = list(b'brigade')

for i in range(len(target)):
    target[i] ^= 0x50

print(''.join([chr(x) for x in target]))
```