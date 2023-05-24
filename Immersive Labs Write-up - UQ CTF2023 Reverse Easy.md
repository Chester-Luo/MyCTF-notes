# Immersive Labs Write-up - UQ CTF2023 Reverse Easy

## Description of problem

We are given a linux executable program, we need to get flag from it.

![image-20230521024806155](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521024806155.png)

If we open it directly, it shows something strange.

## Analysis

We use objdump to observe assembly code at first:

We can find that it has three interesting functions: main, crypt_func and print_hex, more interesting, there are some hardcord content.

![image-20230521025011313](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521025011313.png)

It may be a little difficult to observe how program works from objdump result, we need reverse engineering tools such as IDA or Ghida. I choose Ghida to solve the problem.

![image-20230521025302194](/Users/luohaochen/Library/Application Support/typora-user-images/image-20230521025302194.png)

We can extract "source code" from it.

```C
void print_hex(char *param_1)

{
  char *local_10;
  
  local_10 = param_1;
  while (*local_10 != '\0') {
    printf("%02x",(ulong)(uint)(int)*local_10);
    local_10 = local_10 + 1;
  }
  putchar(10);
  return;
}

void crypt_func(char *param_1)

{
  size_t sVar1;
  int local_c;
  
  sVar1 = strlen(param_1);
  for (local_c = 0; local_c < (int)sVar1; local_c = local_c + 1) {
    param_1[local_c] = param_1[local_c] ^ 9;
  }
  return;
}
```

We can find that crypt_func do very easy thing: XOR 0x9 for each character in string. And the function print_hex just print the character from HEX.

```C
undefined8 main(void)
{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  size_t sVar4;
  char *local_a8;
  undefined8 local_a0;
  sockaddr local_98;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined2 local_68;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  int local_1c;
  __pid_t local_18;
  int local_14;
  undefined4 local_10;
  int local_c;
  
  lVar2 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar2 == -1) {
    puts("[ERROR] Tampering Detected");
    uVar3 = 1;
  }
  else {
    local_58 = 0x6431647b47414c46;
    local_50 = 0x6c30735f7530795f;
    local_48 = 0x68745f74315f3376;
    local_40 = 0x7934775f38725f33;
    local_38 = 0x6e7478656e207d3f;
    local_30 = 0x662e6674632e7465;
    local_28 = 0x616d6f6468746669;
    local_20 = 0x6e692e;
    local_10 = 0xf;
    sVar4 = strlen((char *)&local_58);
    local_14 = (int)sVar4;
    for (local_c = 0; local_c < local_14; local_c = local_c + 1) {
      *(char *)((long)&local_58 + (long)local_c) =
           (char)local_10 + *(char *)((long)&local_58 + (long)local_c);
    }
    printf((char *)&local_58);
    putchar(10);
    local_88 = 0x716c67726e68656f;
    local_80 = 0x563a3b387d6c677d;
    local_78 = 0x7d6f606f566f7d6a;
    local_70 = 0x6760566864666d61;
    local_68 = 0x74;
    crypt_func(&local_88);
    putchar(10);
    local_18 = fork();
    //...
  }
}
```

We care about the content in hex hardcode content, it looks like strings in HEX format. There are two parts, the operation for part I is adding 15 while the operation for part 2 is XOR 0x9. We use python to decode them:





## Solution

Based on above analysis, we can write a code: