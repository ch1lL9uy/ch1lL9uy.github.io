---
title: "Dreamhack Invitational 2025 Quals"
date: 2025-2-12 01:00:00 +0700
categories: [rev]
tags: [Reverse Engineering, Dreamhack CTF]
---

## Typing Game Goes Hard
file: [here](/assets/Dreamhack%20Invitational%202025%20Quals/Typing%20Game%20Goes%20Hard.zip)

```c
unsigned __int64 sub_18EA()
{
  const char *v0; // rax
  char *v1; // rax
  int buf; // [rsp+8h] [rbp-78h] BYREF
  int i; // [rsp+Ch] [rbp-74h]
  int j; // [rsp+10h] [rbp-70h]
  int fd; // [rsp+14h] [rbp-6Ch]
  time_t time1; // [rsp+18h] [rbp-68h] BYREF
  time_t timer; // [rsp+20h] [rbp-60h] BYREF
  char *s2; // [rsp+28h] [rbp-58h]
  char s1[72]; // [rsp+30h] [rbp-50h] BYREF
  unsigned __int64 v11; // [rsp+78h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  sub_1885();
  sub_13DF();
  fd = open("/dev/urandom", 0);
  read(fd, &buf, 4uLL);
  sub_147B((unsigned __int16)buf);
  printf("Type the following words within %d seconds.\n", 90);
  time(&timer);
  for ( i = 0; i <= 1; ++i )
  {
    puts("----------------------------------------------");
    if ( i )
      v0 = "HARD";
    else
      v0 = "EASY";
    printf("-                 %s MODE                  -\n", v0);
    puts("----------------------------------------------");
    for ( j = 0; j <= 9; ++j )
    {
      s2 = (char *)&unk_4060 + 64 * (unsigned __int64)(unsigned __int16)sub_15D4();
      if ( i )
        v1 = "[REDACTED]";
      else
        v1 = s2;
      printf("Type this word as soon as possible: %s\n", v1);
      printf("> ");
      sub_1833(s1, 64LL);
      time(&time1);
      if ( difftime(time1, timer) > 90.0 || strcmp(s1, s2) )
      {
        puts("Wrong or too slow!");
        exit(0);
      }
    }
  }
  printf("You won! flag is ");
  sub_1329();
  return v11 - __readfsqword(0x28u);
}
```

Thử này bắt chúng ta đoán các từ khớp với chương trình trong 90s    
Với 10 vòng đầu là EASY MODE thì chương trình sẽ hiển thị các từ ra màn hình
![alt text](/assets/Dreamhack%20Invitational%202025%20Quals/image-1.png)

Với 10 vòng còn lại là HARD MODE thì các từ sẽ bị ẩn đi và chúng ta cần phải đoán các từ khớp với chương trình
![alt text](/assets/Dreamhack%20Invitational%202025%20Quals/image.png)

Bắt tay vào phân tích chương trình  
Sau khi đọc các từ từ file, chương trình sẽ tạo một mảng gồm 8 phần tử dựa vào giá trị đã được random ban đầu
![alt text](/assets/Dreamhack%20Invitational%202025%20Quals/image-2.png)

Tiếp đến bắt đầu 20 vòng chơi trong 90s, với 10 vòng EASY MODE và 10 vòng HARD MODE         
Mỗi vòng chương trình sẽ thực hiện tính toán địa chỉ và lấy ra 1 từ, và chúng ta cần phải đoán được chính xác từ đó

Vì kích thước giá trị được random chỉ là 2bytes nên có thể thực hiện bruteforce 

**Script**
```python
from pwn import *

HOST = "host1.dreamhack.games"
PORT = 11335

def sub_147B(ran_val):
    a = []
    a.append(ran_val)
    for i in range(1, 8):
        res = 27655 * (a[i-1] ^ (a[i-1] >> 14)) + i
        a.append(res & 0xffff)
    return a, 8

def sub_1507(a):
    for i in range(8):
        val = a[(i+1) % 8]
        v1 = ((a[i] & 0x8000 | val & 0x7fff) >> 1) & 0xffff
        if val & 1 != 0:
            v1 ^= 0x9908
        res = v1 ^ a[(i+4) % 8]
        a[i] = res & 0xffff
    return a

def sub_15D4(a, cnt):
    if cnt > 7:
        a = sub_1507(a)
        cnt = 0

    v7 = a[cnt]
    cnt += 1
    v6 = v7 >> 12
    HIBYTE = (v7 >> 8)

    v1 = 5 * ((v7 >> 4) & 0xf) + 3 * (v7 & 0xf) + 7 * (HIBYTE & 0xf) + 2 * v6
    v2 = 6 * (HIBYTE & 0xF) + 7 * ((v7 >> 4) & 0xF) + 4 * (v7 & 0xF) + 3 * v6
    v3 = (3 * ((v7 >> 4) & 0xF) + 2 * (v7 & 0xF) + 5 * (HIBYTE & 0xF) + 4 * v6) >> 31
    v4 = 5 * (v7 & 0xF) + 6 * ((v7 >> 4) & 0xF) + 4 * (HIBYTE & 0xF)

    res1 = (((((v3 >> 28) + 3 * ((v7 >> 4) & 0xF) + 2 * (v7 & 0xF) + 5 * (HIBYTE & 0xF) + 4 * v6) & 0xF) - (v3 >> 28)) & 0xff) << 8
    res2 = 16 * (((((v2 >> 28) + 6 * (HIBYTE & 0xF) + 7 * ((v7 >> 4) & 0xF) + 4 * (v7 & 0xF) + 3 * v6) & 0xF) - (v2 >> 28)) & 0xff)
    res3 = ((((v1 >> 28) + 5 * ((v7 >> 4) & 0xF) + 3 * (v7 & 0xF) + 7 * (HIBYTE & 0xF) + 2 * v6) & 0xF) - (v1 >> 28)) & 0xff
    res4 = (((((((v4 + 7 * v6) >> 31) >> 28) + 5 * (v7 & 0xF) + 6 * ((v7 >> 4) & 0xF) + 4 * (HIBYTE & 0xF) + 7 * v6) & 0xF) - (((v4 + 7 * v6) >> 31) >> 28)) & 0xff) << 12
    
    return a, (res1 | res2 | res3 | res4) & 0xffff, cnt

def find_ran_val(dic, word):
    for i in range(0x10000):
        a, cnt = sub_147B(i)
        a, idx, cnt = sub_15D4(a, cnt)
        predicted_word = dic[idx]

        if predicted_word == word:
            break
    return a, cnt

def main():
    # p = process("./chall")
    p = remote(HOST, PORT)
    p.recvuntil(b"possible: ")

    word = p.recvline().strip()
    p.sendlineafter(b"> ", word)

    dic = open('dictionary.txt', 'r').read().split()
    a, cnt = find_ran_val(dic, word.decode())

    for i in range(9):
        a, idx, cnt = sub_15D4(a, cnt)
        word = dic[idx]
        p.sendlineafter(b"> ", word.encode())

    for i in range(10):
        a, idx, cnt = sub_15D4(a, cnt)
        word = dic[idx]
        p.sendlineafter(b"> ", word.encode())

    print(p.recvall().decode())
    p.close()

if __name__ == "__main__":
    main()  

# You won! flag is DH{R3C0V3R4BL3_M3RS3NN3_V4R14N7:/WROpzKHuQdYkWa51kAXqw==} 
``` 