---
title: "Dreamhack CTF Season 7 Round #2 (🌱Div2) "
date: 2025-2-13 02:56:00 +0700
categories: [rev]
tags: [Reverse Engineering, Dreamhack CTF]
---

## Branches and Leaves 
file: [here](/assets/Dreamhack%20CTF%20Season%207%20Round%20#2/Branches%20and%20Leaves.zip)

```c
__int64 __fastcall sub_11E0(const char *a1)
{
  const char *v1; // r8
  int i; // r9d
  const char *v3; // rcx
  int v4; // edx
  char v5; // al
  int v6; // edx
  int v7; // ecx
  __int64 result; // rax
  char v9; // si

  if ( strlen(a1) != 64 )
LABEL_16:
    exit(1);
  v1 = a1 + 4;
  for ( i = 0; i != 64; i += 4 )
  {
    v3 = v1 - 4;
    v4 = 0;
    do
    {
      v5 = *v3;
      v6 = 16 * v4;
      if ( (unsigned __int8)(*v3 - 48) > 9u )
      {
        if ( (unsigned __int8)(v5 - 97) > 5u )
          goto LABEL_16;
        v4 = (char)(v5 - 87) + v6;
      }
      else
      {
        v4 = (char)(v5 - 48) + v6;
      }
      ++v3;
    }
    while ( v1 != v3 );
    v7 = 16;
    result = 0LL;
    while ( 1 )
    {
      v9 = v4;
      v4 >>= 1;
      result = dword_4060[2 * result + (v9 & 1)];
      if ( !--v7 )
        break;
      if ( (_DWORD)result == -1 || (int)result > (int)&unk_3FFFF )
        goto LABEL_16;
    }
    if ( (_DWORD)result != dword_4020[i >> 2] )
      goto LABEL_16;
    v1 += 4;
  }
  return result;
}
```

Đầu tiên, ta thấy rằng chuỗi có độ dài là 64 kí tự
![alt text](/assets/Dreamhack%20CTF%20Season%207%20Round%20#2/image.png)

Tiếp đến, chương trình xử lý từng nhóm 4 kí tự và chuyển đổi thành một số nguyên hex
![alt text](/assets/Dreamhack%20CTF%20Season%207%20Round%20#2/image-1.png)

Thực hiện duyệt qua `dword_4060`
![alt text](/assets/Dreamhack%20CTF%20Season%207%20Round%20#2/image-2.png)

* Thực hiện dịch phải `v4` 16 lần (giá trị vừa được chuyển đổi ở trên)
* Tính `result` bằng cách ánh xạ vào mảng `dword_4060`
* Nếu `result` bằng -1 hoặc lớn hơn 0x3FFF thì sẽ thoát chương trình

Cuối cùng là so sánh `result` với giá trị tương ứng trong bảng `dword_4020`
![alt text](/assets/Dreamhack%20CTF%20Season%207%20Round%20#2/image-3.png)

Ta thấy rằng giá trị mỗi lần được chuyển đổi là 4 kí tự hex, tức là 2bytes -> bruteforce

Trước đó tôi cần xem giá trị bắt đầu của mảng `dword_4060`
![alt text](/assets/Dreamhack%20CTF%20Season%207%20Round%20#2/image-4.png)
Ta thấy rằng nó bắt đầu từ byte thứ 0x3060, nên tôi sẽ đọc toàn bộ bắt đầu từ offset 0x3060

**Script**
```python
dword_4020 = [0x6E42DB36, 0x50EE7196, 0x66F61F93, 0x58F59D02, 
              0x5E4FAE58, 0x6941CEE7, 0x47F8A1AB, 0x59C2E48E, 
              0x5764C85A, 0x62CE2FE1, 0x425BCB1A, 0x65430112, 
              0x7FE80600, 0x5DBF3584, 0x5210221A, 0x6E30EE7F]

f = open('main', 'rb')
f.read(0x3060)
dword_4060 = f.read()

flag = ""
for i in range(0, 64, 4):
    for val in range(0x10000):
            v4 = val
            v7 = 16
            res = 0

            while v7:
                idx = 2 * res + (v4 & 1)
                idx *= 4
                res = int.from_bytes(dword_4060[idx:idx+4], 'little')
                v4 >>= 1
                v7 -= 1

                if not v7:
                    break
                if res == 0xFFFFFFFF or res > 0x3FFFF:
                    break
            
            if res == dword_4020[i >> 2]:
                flag += hex(val)[2:].zfill(4)
                print(f"Current: {flag}")
                break
    
flag = "DH{" + flag + '}'
print(f"Flag: {flag}")
```
`flag: DH{d8f794325872bab95cfaa117545c6c0b77059a74f4dd31d8c2bf130a59745d77}`