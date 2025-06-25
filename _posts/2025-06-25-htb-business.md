---
title: "Global Cyber Skills Benchmark CTF 2025 Operation Blackout (HTB)"
date: 2025-6-25 10:10:00 +0700
categories: [rev]
tags: [Reverse Engineering, HTB]
---

![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-1.png)

> Super thrilled to be part of CTFAE friends! Over the past 4 days, everyone worked hard to climb the leaderboard, and their efforts really motivated me. Big thanks to the team!

## shadow_labyrinth

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  _OWORD v4[6]; // [rsp+0h] [rbp-78h] BYREF
  unsigned __int64 v5; // [rsp+68h] [rbp-10h]

  v5 = __readfsqword(0x28u);
  memset(v4, 0, 90);
  puts("[Central Command Node]: Motion triggered! Labyrinth entrance...");
  fgets((char *)v4, 89, stdin);
  if ( strlen((const char *)v4) == 88 )
  {
    if ( LOBYTE(v4[0]) == 72 || BYTE1(v4[0]) == 84 || BYTE2(v4[0]) == 66 || BYTE3(v4[0]) == 123 || BYTE7(v4[5]) == 125 )
    {
      BYTE7(v4[5]) = 0;
      sub_1660((char *)v4 + 4);
      return 0;
    }
    puts("Invalid flag.");
  }
  else
  {
    puts("Invalid flag length.");
  }
  return 1;
}
```

The program checks if the flag is 88 characters long and follows the HTB{} format. If valid, it calls sub_1660 to verify the flag's contents, split into two parts: the first 48 bytes and the last 35 bytes.

First 48 Bytes:          
* The 48 bytes are permuted using unk_22C0.

    ![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-2.png)

    ![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-3.png)

* Every 4 bytes are multiplied with coefficients from unk_2140, summed, and compared to unk_20E0.

    ![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-4.png)

Let me rewrite this part to make it easier to understand
```python
import struct

# apply the permutation to the flag
def apply_permutation(flag, perm):
    return [flag[i] for i in perm]

# multiply coefficients with a vector
def multiply_coefficients(coeffs, vector, target):
    return (sum(int(c) * int(ord(v)) for c, v in zip(coeffs, vector)) & 0xFFFFFFFFFFFFFFFF) == target

def main():
    flag = input("Enter the flag: ")
    if (len(flag) != 88):
        print("Invalid flag length.")
        return
    if (flag[:4] != "HTB{" or flag[-1] != '}'):
        print("Invalid flag.")
        return
    
    unk_22C0 = b'\x10\x19\x20\x05\x00\x2d\x26\x02\x0e\x28\x18\x11\x07\x21\x17\x1d\x27\x0f\x23\x15\x2e\x1a\x13\x2f\x2b\x14\x0d\x1f\x01\x16\x2c\x2a\x1e\x08\x22\x0b\x12\x1b\x0c\x09\x29\x24\x04\x1c\x03\x06\x25\x0a'
    unk_2140 = b'\x92\x34\xd1\x97\x80\xb7\x0d\xc3\x3a\xfb\x54\x5e\x48\x48\x31\x41\x8d\xa4\xb9\x67\xf5\x8d\x96\xb6\x92\xbc\x64\x79\x91\xc5\x62\x88\x07\x64\xd6\x68\x40\xf9\x92\x4a\x07\xf8\x47\x3a\x0b\xa6\x1f\xeb\x91\x3a\x6f\x0c\x3b\x3a\xdb\x32\xf3\x3a\x82\x6e\xfc\x4c\x29\xca\x8b\x83\xbd\x6c\xf0\x96\x29\x5e\x96\x15\x0e\xce\x3c\xf7\xbc\x95\xb5\xc8\xc9\xb4\x94\x1b\x24\xe4\x97\x5f\xc5\x12\xb2\x9f\x51\x5a\x53\xca\xe7\xe8\xe8\xf8\x04\x19\xf6\x18\x9f\x53\xb8\x61\x3e\x57\x1a\xec\x33\x73\xb3\x13\x8b\x81\x38\x8c\x62\x5a\xcf\x5f\xec\x52\x9b\x45\x62\x16\xf6\xb6\xee\xfa\x0e\x6b\x47\x18\x25\x46\x16\xf8\x9b\xfc\xd9\x23\xec\x26\x3a\xd0\x1b\x90\x2e\xf9\xfd\xc2\x2d\xfc\x5b\x74\xc7\x2b\xa4\xb6\xc0\xb8\x8f\xa5\xff\xf8\x38\xa1\xf1\x6b\x8d\x48\x01\x1c\xfc\xb1\x6e\x66\x75\xe9\xab\x4e\xeb\xab\x6a\xfd\xf8\xff\x13\xa6\x48\x26\xb6\x7d\x6c\x14\xf3\x7d\x2c\x79\x15\x56\x0c\xb8\x8e\x46\xeb\x3a\x70\x5f\xef\x2f\xd7\x73\xf1\x4c\xc3\xe6\x4f\x3e\x1f\xe4\xdf\x67\x08\xa8\x68\x4d\xa3\x9b\x7c\x8d\x16\xb7\x37\xa8\x73\x3e\xae\x7b\x39\x44\xa5\x8e\x3b\xb3\x7c\x7a\x7b\x22\x83\xb0\x0e\x05\xb0\xf5\xe6\xa3\xbb\x8e\xdf\xcd\x8e\xc5\xc0\x3a\x93\x9b\xf7\xce\x21\xa6\x83\xc4\x51\x4b\xbf\x02\x25\xca\x21\x95\xbf\xe0\x67\xe5\x42\x40\x55\x11\x5e\xd5\x9c\xa6\xbb\x51\xc5\x1b\x4d\x48\x09\x0a\xb6\x5a\x01\x13\x0b\x58\x48\xae\xab\xef\x1a\xc4\xc7\x8e\x79\xdd\x93\x68\x57\xbb\x89\xa6\x7c\x77\x08\xc9\xf5\xfa\xb8\x48\xa3\x07\x16\x48\x07\xe7\x3e\xbf\x8a\xd2\x99\x77\xc5\x70\xc6\xdd\xef\xa9\x3a\x33\x8f\x3a\xe4\x9e\xe4\x44\xf0\x2b\xac\xf9\x44\x3b\xe1\x67\xd0\x13\x72\xca\x18\x7f\xb2\x4b\xf9\x92\x33\x33'
    unk_20E0 = b'\x79\x53\x8a\x8d\xcd\x9a\x93\xb8\xdf\x35\x4b\xb4\x31\x81\xdc\xb2\x83\x1b\x41\x89\x37\xf9\x87\x92\xb8\x27\x61\x8b\x32\x26\x7c\x93\xdb\xad\x76\x81\xb3\x85\x65\xa3\xd2\x62\xa3\xb4\x0e\xcf\x88\xaa\x87\xaa\x5a\x69\xcd\x5a\x88\x70\x7c\x69\x16\x5c\xf8\x38\x7d\x8e\x0a\x6f\x8a\xbc\x36\x01\x87\x1c\x1a\x02\xf0\x97\x2a\x0c\x05\xb7\x12\xef\x73\x27\x65\xc5\xb7\x23\xfc\xec\x3c\x4d\x75\xf2\xe4\x6a'

    perm = list(unk_22C0)
    coefficients = struct.unpack("<48Q", unk_2140)
    targets = struct.unpack("<12Q", unk_20E0)

    flag48 = list(flag[4:48+4])

    perm_flag = apply_permutation(flag48, perm)
    for i in range(len(targets)):
        c = coefficients[i * 4:i * 4 + 4]
        if not multiply_coefficients(c, perm_flag[i*4:i*4 + 4], targets[i]):
            print("Flag is incorrect.")
            return
        
    print("[Central Command Node]: Motion triggered! Magnetosphere...")

if __name__ == "__main__":
    main()
```

I used a meet-in-the-middle attack to recover the 48 bytes:

```python
import struct

perm = b'\x10\x19\x20\x05\x00\x2d\x26\x02\x0e\x28\x18\x11\x07\x21\x17\x1d\x27\x0f\x23\x15\x2e\x1a\x13\x2f\x2b\x14\x0d\x1f\x01\x16\x2c\x2a\x1e\x08\x22\x0b\x12\x1b\x0c\x09\x29\x24\x04\x1c\x03\x06\x25\x0a'
mul = b'\x92\x34\xd1\x97\x80\xb7\x0d\xc3\x3a\xfb\x54\x5e\x48\x48\x31\x41\x8d\xa4\xb9\x67\xf5\x8d\x96\xb6\x92\xbc\x64\x79\x91\xc5\x62\x88\x07\x64\xd6\x68\x40\xf9\x92\x4a\x07\xf8\x47\x3a\x0b\xa6\x1f\xeb\x91\x3a\x6f\x0c\x3b\x3a\xdb\x32\xf3\x3a\x82\x6e\xfc\x4c\x29\xca\x8b\x83\xbd\x6c\xf0\x96\x29\x5e\x96\x15\x0e\xce\x3c\xf7\xbc\x95\xb5\xc8\xc9\xb4\x94\x1b\x24\xe4\x97\x5f\xc5\x12\xb2\x9f\x51\x5a\x53\xca\xe7\xe8\xe8\xf8\x04\x19\xf6\x18\x9f\x53\xb8\x61\x3e\x57\x1a\xec\x33\x73\xb3\x13\x8b\x81\x38\x8c\x62\x5a\xcf\x5f\xec\x52\x9b\x45\x62\x16\xf6\xb6\xee\xfa\x0e\x6b\x47\x18\x25\x46\x16\xf8\x9b\xfc\xd9\x23\xec\x26\x3a\xd0\x1b\x90\x2e\xf9\xfd\xc2\x2d\xfc\x5b\x74\xc7\x2b\xa4\xb6\xc0\xb8\x8f\xa5\xff\xf8\x38\xa1\xf1\x6b\x8d\x48\x01\x1c\xfc\xb1\x6e\x66\x75\xe9\xab\x4e\xeb\xab\x6a\xfd\xf8\xff\x13\xa6\x48\x26\xb6\x7d\x6c\x14\xf3\x7d\x2c\x79\x15\x56\x0c\xb8\x8e\x46\xeb\x3a\x70\x5f\xef\x2f\xd7\x73\xf1\x4c\xc3\xe6\x4f\x3e\x1f\xe4\xdf\x67\x08\xa8\x68\x4d\xa3\x9b\x7c\x8d\x16\xb7\x37\xa8\x73\x3e\xae\x7b\x39\x44\xa5\x8e\x3b\xb3\x7c\x7a\x7b\x22\x83\xb0\x0e\x05\xb0\xf5\xe6\xa3\xbb\x8e\xdf\xcd\x8e\xc5\xc0\x3a\x93\x9b\xf7\xce\x21\xa6\x83\xc4\x51\x4b\xbf\x02\x25\xca\x21\x95\xbf\xe0\x67\xe5\x42\x40\x55\x11\x5e\xd5\x9c\xa6\xbb\x51\xc5\x1b\x4d\x48\x09\x0a\xb6\x5a\x01\x13\x0b\x58\x48\xae\xab\xef\x1a\xc4\xc7\x8e\x79\xdd\x93\x68\x57\xbb\x89\xa6\x7c\x77\x08\xc9\xf5\xfa\xb8\x48\xa3\x07\x16\x48\x07\xe7\x3e\xbf\x8a\xd2\x99\x77\xc5\x70\xc6\xdd\xef\xa9\x3a\x33\x8f\x3a\xe4\x9e\xe4\x44\xf0\x2b\xac\xf9\x44\x3b\xe1\x67\xd0\x13\x72\xca\x18\x7f\xb2\x4b\xf9\x92\x33\x33'
targets = b'\x79\x53\x8a\x8d\xcd\x9a\x93\xb8\xdf\x35\x4b\xb4\x31\x81\xdc\xb2\x83\x1b\x41\x89\x37\xf9\x87\x92\xb8\x27\x61\x8b\x32\x26\x7c\x93\xdb\xad\x76\x81\xb3\x85\x65\xa3\xd2\x62\xa3\xb4\x0e\xcf\x88\xaa\x87\xaa\x5a\x69\xcd\x5a\x88\x70\x7c\x69\x16\x5c\xf8\x38\x7d\x8e\x0a\x6f\x8a\xbc\x36\x01\x87\x1c\x1a\x02\xf0\x97\x2a\x0c\x05\xb7\x12\xef\x73\x27\x65\xc5\xb7\x23\xfc\xec\x3c\x4d\x75\xf2\xe4\x6a'

perm = list(perm)
mul = struct.unpack("<48Q", mul)
targets = struct.unpack("<12Q", targets)

# Meet-in-the-middle attack           
def solve_block(idx):
    C = mul[idx * 4: idx * 4 + 4]
    T = targets[idx] & 0xFFFFFFFFFFFFFFFF
    rhs_table = {}
    for c in range(256):
        for d in range(256):
            partial = (C[2] * c + C[3] * d) & 0xFFFFFFFFFFFFFFFF
            rhs_table[partial] = (c, d)

    for a in range(256):
        for b in range(256):
            need = (T - (C[0] * a + C[1] * b)) & 0xFFFFFFFFFFFFFFFF
            pair = rhs_table.get(need)
            if pair:
                return [a, b, *pair]
    raise RuntimeError("unsat")

blocks = [solve_block(i) for i in range(12)]
perm_bytes = [byte for blk in blocks for byte in blk]
flag = "HTB{"
flag48 = ['?'] * 48
flag35 = ['?'] * 35
for a, b in enumerate(perm):
  flag48[b] = chr(perm_bytes[a])

flag48 = ''.join(flag48)
flag35 = ''.join(flag35)
print(f"Flag48: {flag48}")
print(flag + flag48 + flag35 + '}')

'''
Flag48: by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy
HTB{by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy???????????????????????????????????}
'''
```

For the final 35 bytes:

1. The program reads file.bin

    ![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-5.png)

2. XOR with the last 16 bytes (from the permuted 48-byte flag)

    ![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-6.png)

3. decrypts it with AES-256-CBC and decompresses

    ![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-7.png)

4. The result is opcodes for a VM that processes the last 35 bytes.

    ![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-8.png)

So the next step is to extract the contents of file.bin after it's been decrypted.  

Below is the IV 

![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image.png)
![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-14.png)

The key is taken from the first 32 bytes of the permuted flag
![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-12.png)

```python
from pathlib import Path
from Crypto.Cipher import AES
import zlib

AES_KEY = b"tw_db0t_u3_in4gllll1d3ly3ymyynlm"   
XOR_KEY = b"4g_dp____1dp41tn"                   
IV      = bytes.fromhex("8ca2cab229db610aacdd9d437c617af3")

data = bytearray(Path("file.bin").read_bytes())


for i in range(len(data)):
    data[i] ^= XOR_KEY[i & 0xF]


opcode = AES.new(AES_KEY, AES.MODE_CBC, IV).decrypt(bytes(data))

payload = zlib.decompress(opcode)
Path("opcode.bin").write_bytes(payload)
```

After extracting the opcodes, the next step is to understand how the VM works. This was the hardest part — and it drove me crazy. I spent quite a lot of time trying to figure out how the program operates.

Below is the disassembler script   
```python
#!/usr/bin/env python3

import struct
import sys



def read_dword(bytecode, idx):
    base = idx * 4
    if base + 3 < len(bytecode):
        return struct.unpack('<I', bytes(bytecode[base:base+4]))[0]
    return 0


def disassemble(bytecode):
    dwords = [read_dword(bytecode, i) for i in range((len(bytecode) + 3) // 4)]

    opcode_names = {
        0:  'STORE_0',      1:  'STORE_1',      2:  'ADD_IMM',
        3:  'SUB_IMM_FLAG', 4:  'SHL',          5:  'ADD_REG',
        6:  'SUB_REG_FLAG', 7:  'XOR_REG',      8:  'STORE_CODE',
        9:  'LOAD_CODE',   10:  'JNZ',         11:  'JZ',
       12:  'JMP',         13:  'GETCHAR',     14:  'PRINT',
       15:  'EXIT'
    }

    pc = 0
    while pc < len(dwords):
        op = dwords[pc]
        # If opcode > 15, treat as raw data
        if op > 15:
            print(f"{pc:04x}: DATA      0x{op:08x}")
            pc += 1
            continue

        name = opcode_names[op]
        line = f"{pc:04x}: {name}"

        if op in (0, 1):  # STORE_0/STORE_1 idx
            if pc + 1 < len(dwords):
                line += f" idx={dwords[pc+1]}"
                pc += 2
            else:
                pc += 1

        elif op in (2, 3, 4):  # ADD_IMM, SUB_IMM_FLAG, SHL
            if pc + 2 < len(dwords):
                line += f" idx={dwords[pc+1]}, imm={dwords[pc+2]}"
                pc += 3
            else:
                pc += 1

        elif op in (5, 6, 7):  # ADD_REG, SUB_REG_FLAG, XOR_REG
            if pc + 2 < len(dwords):
                line += f" dst={dwords[pc+1]}, src={dwords[pc+2]}"
                pc += 3
            else:
                pc += 1

        elif op == 8:  # STORE_CODE
            if pc + 2 < len(dwords):
                line += f" src_idx={dwords[pc+1]}, off={dwords[pc+2]}"
                pc += 3
            else:
                pc += 1

        elif op == 9:  # LOAD_CODE
            if pc + 2 < len(dwords):
                line += f" dst_idx={dwords[pc+1]}, off={dwords[pc+2]}"
                pc += 3
            else:
                pc += 1

        elif op in (10, 11, 12):  # JNZ, JZ, JMP
            if pc + 1 < len(dwords):
                off = dwords[pc+1]
                if off & 0x80000000:
                    off -= 1 << 32
                target = pc + off
                line += f" -> {target:04x}"
                pc += 2
            else:
                pc += 1

        elif op == 13:  # GETCHAR
            line += " -> mem[0x23]"
            pc += 1

        elif op == 14:  # PRINT
            if pc + 1 < len(dwords):
                off = dwords[pc+1]
                addr = (pc + 2 + off) * 4
                s = ''
                while addr < len(bytecode) and bytecode[addr] != 0:
                    b = bytecode[addr]
                    s += chr(b) if 32 <= b <= 126 else f"\\x{b:02x}"
                    addr += 1
                line += f' "{s}"'
                pc += 2
            else:
                pc += 1

        else:  # EXIT
            pc += 1

        with open("func.txt", "a") as f:
            f.write(line + "\n")
        print(line)


data = list(open("opcode.bin", 'rb').read())
disassemble(data)
```

VM Execution Logic:   
1. Read 35 bytes from the flag
2. Compute 35 values (each 4 bytes) (each iteration computes one value)
3. Use the 35 flag bytes to evaluate a system of 35 equations, then compare the results with the corresponding values computed in step 2

At this point, all we need to do is extract the coefficients and the 35 expected results. Then we can solve the system of 35 equations with 35 unknowns.

While debugging, I was able to recover the first expected value. 
![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image.png)

Using this first value as a reference, I continued debugging to extract the rest. And The address below belongs to this function

![alt text](/assets/Global%20Cyber%20Skills%20Benchmark%20CTF%202025%20Operation%20Blackout/image-13.png)

```bash
pwndbg> b*0x0000555555555640
pwndbg> r
[.....]
HTB{by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy??????????????????????????????????}
[Central Command Node]: Motion triggered! Magnetosphere...
[........]
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /mnt/d/Downloads/rev_shadowlabyrinth/shadow_labyrinth
    [..........]
    0x7fffffbfc000     0x7ffffffff000 rw-p   403000      0 [stack]

pwndbg> find /w 0x7fffffbfc000, 0x7ffffffff000, 0x00080752
0x7fffffc792e8
warning: Unable to access 13845 bytes of target memory at 0x7fffffffb9ec, halting search.
1 pattern found.
pwndbg> x/35w 0x7fffffc792e8
0x7fffffc792e8: 0x00080752      0x0007e64f      0x00077b69      0x00081480
0x7fffffc792f8: 0x0009b4ba      0x00078db9      0x0007a4ea      0x00094824
0x7fffffc79308: 0x0008a016      0x00085b67      0x0007b81a      0x00087ea5
0x7fffffc79318: 0x00071c6d      0x00084525      0x00073901      0x00084b18
0x7fffffc79328: 0x0007b27b      0x000886b6      0x0006684e      0x000758d8
0x7fffffc79338: 0x000898f3      0x0008b051      0x000742b9      0x0007e82b
0x7fffffc79348: 0x0007c7aa      0x0007ec0b      0x00083eaf      0x00077f23
0x7fffffc79358: 0x00074d67      0x000660a9      0x0007b8b7      0x00093764
0x7fffffc79368: 0x0007d7e4      0x00084e30      0x00089b41
pwndbg> dump memory check.bin 0x7fffffc792e8 0x7fffffc792e8+(35*4)
```

Below is the script I used to extract the coefficients.
```python
# gdb -q -x get_coefficients.py
import gdb
import string

gdb.execute("file ./shadow_labyrinth")
gdb.execute("b*0x555555555520")
flag = "HTB{by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy???????????????????????????????????}"
gdb.execute(f"run <<< {flag}")
arr = []
base = 0x7fffffffd3e0
for i in range(35):
    cnt = 0
    for j in range(35):
        val = gdb.execute(f"x/1wx {hex(base + cnt)}", to_string=True).strip().split()[-1]
        arr.append(val)
        cnt += 4
        gdb.execute("continue")

print(arr)
```

```
['0x00000119', '0x0000007b', '0x00000123', '0x0000006e', '0x00000074', '0x00000057', '0x0000000d', '0x00000096', '0x00000007', '0x0000009d', '0x00000100', '0x00000012', '0x0000006f', '0x000000fb', '0x00000036', '0x0000006d', '0x000000e3', '0x000000cd', '0x00000121', '0x00000100', '0x00000097', '0x0000010e', '0x000000a5', '0x000000f7', '0x000000c5', '0x0000003a', '0x00000045', '0x00000014', '0x00000043', '0x000000ea', '0x0000003a', '0x000000f9', '0x0000001d', '0x000000b8', '0x0000006b', '0x00000126', '0x00000070', '0x0000012a', '0x0000000f', '0x00000063', '0x0000003c', '0x00000094', '0x00000118', '0x00000109', '0x00000102', '0x00000011', '0x00000119', '0x00000048', '0x0000000e', '0x00000011', '0x000000eb', '0x00000048', '0x00000129', '0x000000b3', '0x0000008a', '0x000000f6', '0x000000af', '0x00000085', '0x00000096', '0x00000003', '0x000000b8', '0x00000050', '0x00000082', '0x0000005b', '0x00000005', '0x00000075', '0x0000011c', '0x000000e3', '0x0000008f', '0x00000074', '0x000000ec', '0x000000b7', '0x000000ed', '0x0000000a', '0x00000008', '0x00000030', '0x00000114', '0x0000008e', '0x00000095', '0x0000007f', '0x00000040', '0x0000006a', '0x00000067', '0x00000088', '0x000000dc', '0x000000c8', '0x00000061', '0x00000029', '0x0000000e', '0x000000d7', '0x000000f8', '0x00000072', '0x00000104', '0x00000086', '0x000000b2', '0x000000d6', '0x0000003a', '0x000000bc', '0x0000002b', '0x00000118', '0x000000f7', '0x000000cc', '0x00000001', '0x0000005e', '0x000000d6', '0x00000083', '0x00000128', '0x00000048', '0x000000ed', '0x00000126', '0x00000092', '0x0000004f', '0x0000011d', '0x00000081', '0x0000001b', '0x0000006c', '0x00000116', '0x00000105', '0x000000c2', '0x000000a4', '0x000000ba', '0x00000080', '0x000000fc', '0x00000080', '0x000000fd', '0x000000ae', '0x0000010f', '0x00000112', '0x000000e5', '0x00000050', '0x00000010', '0x0000007e', '0x0000004a', '0x00000056', '0x00000047', '0x00000034', '0x0000000f', '0x0000001a', '0x00000032', '0x0000005f', '0x000000bb', '0x00000124', '0x00000104', '0x0000009d', '0x000000ba', '0x0000006a', '0x000000d3', '0x000000f1', '0x000000bf', '0x00000085', '0x00000046', '0x000000de', '0x0000007c', '0x00000084', '0x00000100', '0x0000009d', '0x0000011a', '0x000000f2', '0x000000dc', '0x00000071', '0x00000129', '0x00000069', '0x0000003f', '0x000000d6', '0x000000df', '0x000000cb', '0x000000d7', '0x0000005e', '0x0000005a', '0x0000004f', '0x00000000', '0x00000045', '0x00000106', '0x0000010b', '0x000000da', '0x000000a1', '0x000000e6', '0x0000000b', '0x000000f2', '0x00000027', '0x0000003a', '0x000000c1', '0x00000126', '0x000000b5', '0x00000001', '0x0000006d', '0x00000111', '0x0000010c', '0x000000a7', '0x00000038', '0x00000001', '0x00000013', '0x000000f1', '0x00000052', '0x000000e9', '0x00000055', '0x00000097', '0x00000084', '0x0000006c', '0x00000114', '0x000000df', '0x00000121', '0x0000004e', '0x000000d3', '0x0000005d', '0x00000011', '0x00000018', '0x0000001b', '0x000000e1', '0x00000091', '0x000000ed', '0x0000007e', '0x0000006a', '0x000000e1', '0x0000008b', '0x000000ef', '0x00000056', '0x000000d2', '0x000000eb', '0x0000009c', '0x00000100', '0x00000077', '0x000000f2', '0x0000006b', '0x0000001b', '0x000000c5', '0x0000007d', '0x00000024', '0x00000007', '0x000000e7', '0x00000034', '0x0000011c', '0x000000ef', '0x00000003', '0x0000006b', '0x000000d2', '0x0000001f', '0x000000a6', '0x0000004f', '0x00000047', '0x0000002d', '0x000000eb', '0x00000041', '0x0000009c', '0x000000c2', '0x0000008b', '0x0000005e', '0x0000008f', '0x000000df', '0x000000d4', '0x00000023', '0x000000d4', '0x00000058', '0x00000125', '0x000000ba', '0x00000090', '0x0000012b', '0x00000035', '0x000000c2', '0x00000103', '0x000000a7', '0x00000015', '0x000000a5', '0x0000009d', '0x0000005d', '0x000000dd', '0x0000010d', '0x0000011a', '0x000000fb', '0x00000048', '0x00000110', '0x00000081', '0x000000b0', '0x000000ed', '0x000000a0', '0x0000011d', '0x0000009c', '0x0000010e', '0x00000103', '0x0000001e', '0x00000070', '0x000000b9', '0x000000be', '0x0000010a', '0x0000011e', '0x000000ce', '0x000000f1', '0x0000011e', '0x00000054', '0x000000ff', '0x00000026', '0x00000080', '0x00000038', '0x0000003c', '0x00000096', '0x0000002e', '0x00000063', '0x00000089', '0x00000080', '0x00000120', '0x0000009f', '0x00000103', '0x00000016', '0x00000100', '0x0000002f', '0x000000c9', '0x00000026', '0x000000a6', '0x00000010', '0x000000cb', '0x000000e6', '0x000000d2', '0x0000011a', '0x0000006f', '0x000000d3', '0x00000097', '0x00000094', '0x00000046', '0x0000005b', '0x000000bf', '0x000000d3', '0x000000e0', '0x000000f8', '0x000000d0', '0x000000b0', '0x00000009', '0x0000008a', '0x00000115', '0x000000a8', '0x000000e8', '0x0000000a', '0x000000be', '0x00000043', '0x000000eb', '0x0000006c', '0x00000066', '0x0000006a', '0x00000098', '0x00000049', '0x00000006', '0x00000123', '0x0000007c', '0x0000005e', '0x000000eb', '0x00000058', '0x0000007b', '0x00000081', '0x0000012a', '0x000000b8', '0x0000010d', '0x00000124', '0x000000a2', '0x00000080', '0x000000dd', '0x00000028', '0x00000052', '0x0000007e', '0x00000060', '0x0000009a', '0x0000007b', '0x0000003c', '0x00000120', '0x00000062', '0x00000111', '0x00000108', '0x000000cd', '0x00000019', '0x00000087', '0x0000009b', '0x000000b7', '0x00000078', '0x00000024', '0x0000002b', '0x000000d0', '0x000000c0', '0x0000011c', '0x000000f5', '0x0000000c', '0x0000006b', '0x00000121', '0x00000045', '0x00000028', '0x00000071', '0x0000006a', '0x000000de', '0x000000b7', '0x00000041', '0x00000076', '0x00000071', '0x00000007', '0x0000002e', '0x00000128', '0x00000060', '0x00000081', '0x00000066', '0x000000ad', '0x00000015', '0x00000077', '0x00000092', '0x000000c0', '0x00000033', '0x0000000e', '0x000000fd', '0x00000026', '0x0000012b', '0x00000126', '0x000000b7', '0x000000e4', '0x0000007e', '0x000000cf', '0x000000c6', '0x000000f4', '0x00000104', '0x0000010d', '0x0000011c', '0x00000063', '0x000000bd', '0x00000093', '0x00000100', '0x000000d5', '0x000000c0', '0x000000a7', '0x00000015', '0x00000016', '0x00000063', '0x00000004', '0x00000124', '0x00000027', '0x000000d6', '0x000000ad', '0x000000a9', '0x0000002c', '0x000000c0', '0x00000093', '0x00000021', '0x00000082', '0x000000a8', '0x00000015', '0x00000046', '0x000000a3', '0x0000004e', '0x000000f8', '0x0000011d', '0x0000002b', '0x000000d4', '0x00000062', '0x000000fc', '0x00000066', '0x00000042', '0x00000075', '0x0000010e', '0x000000a0', '0x00000083', '0x0000011e', '0x0000000a', '0x00000001', '0x00000101', '0x0000008b', '0x0000012a', '0x00000025', '0x000000b2', '0x0000008e', '0x000000d6', '0x00000125', '0x00000068', '0x000000cb', '0x00000064', '0x0000003c', '0x000000ff', '0x00000099', '0x000000cc', '0x00000020', '0x0000006a', '0x00000060', '0x00000003', '0x00000067', '0x00000065', '0x00000108', '0x00000119', '0x00000121', '0x0000009b', '0x00000107', '0x00000122', '0x0000009b', '0x00000045', '0x000000e9', '0x00000095', '0x00000008', '0x000000cf', '0x00000052', '0x000000d3', '0x0000009d', '0x00000010', '0x000000b7', '0x00000001', '0x0000005f', '0x00000048', '0x000000a6', '0x00000091', '0x00000071', '0x000000c7', '0x0000005a', '0x000000c0', '0x000000d2', '0x00000000', '0x00000109', '0x000000b6', '0x00000100', '0x00000125', '0x00000061', '0x00000035', '0x0000001a', '0x00000100', '0x00000064', '0x00000031', '0x000000f2', '0x000000f4', '0x0000005f', '0x0000006c', '0x000000d3', '0x00000000', '0x00000028', '0x000000fb', '0x0000002b', '0x000000d0', '0x00000128', '0x000000d1', '0x0000007a', '0x00000064', '0x0000007f', '0x000000a2', '0x000000bb', '0x00000121', '0x000000ad', '0x000000f0', '0x000000b3', '0x000000fd', '0x0000004d', '0x00000099', '0x00000081', '0x00000033', '0x0000007b', '0x0000005e', '0x00000039', '0x0000008e', '0x00000069', '0x00000072', '0x00000073', '0x00000008', '0x0000007f', '0x0000000f', '0x00000067', '0x00000075', '0x000000f3', '0x00000120', '0x000000e4', '0x00000124', '0x000000b7', '0x0000007e', '0x0000005f', '0x0000008a', '0x0000011a', '0x000000aa', '0x000000a0', '0x000000c4', '0x0000003d', '0x0000005d', '0x00000128', '0x00000053', '0x00000089', '0x000000b2', '0x000000d1', '0x0000005f', '0x0000010f', '0x000000d4', '0x000000e2', '0x0000000d', '0x00000110', '0x00000038', '0x00000053', '0x0000005a', '0x000000e0', '0x00000080', '0x000000ad', '0x000000a2', '0x0000006f', '0x00000097', '0x000000e3', '0x0000006b', '0x000000ae', '0x00000019', '0x00000018', '0x0000002e', '0x000000c1', '0x00000022', '0x00000007', '0x0000011c', '0x00000046', '0x000000eb', '0x00000089', '0x0000012a', '0x00000048', '0x0000005a', '0x00000052', '0x0000003c', '0x000000e4', '0x00000106', '0x00000004', '0x000000ba', '0x000000e5', '0x000000af', '0x0000010a', '0x00000066', '0x0000009e', '0x000000a3', '0x000000ca', '0x00000099', '0x00000010', '0x00000043', '0x000000f0', '0x0000008e', '0x000000b3', '0x00000037', '0x000000bf', '0x00000010', '0x000000b1', '0x000000d6', '0x000000ff', '0x00000119', '0x00000107', '0x000000b8', '0x00000048', '0x00000004', '0x00000008', '0x0000007b', '0x00000075', '0x000000d0', '0x0000002d', '0x0000004f', '0x000000bc', '0x0000002a', '0x00000000', '0x00000101', '0x00000067', '0x0000005b', '0x0000004f', '0x00000090', '0x000000ae', '0x000000ed', '0x000000e0', '0x000000f0', '0x00000004', '0x00000012', '0x00000082', '0x00000001', '0x000000f4', '0x0000003e', '0x000000dc', '0x0000003f', '0x0000001e', '0x000000a2', '0x00000065', '0x0000009a', '0x00000128', '0x00000127', '0x0000009a', '0x0000007a', '0x00000127', '0x000000fd', '0x00000005', '0x000000ff', '0x00000018', '0x000000b8', '0x0000009c', '0x00000026', '0x00000046', '0x00000033', '0x0000006a', '0x00000047', '0x00000082', '0x000000ff', '0x00000044', '0x00000072', '0x000000d0', '0x000000a3', '0x000000a7', '0x000000c1', '0x00000045', '0x0000008a', '0x000000ec', '0x000000b6', '0x00000065', '0x000000a7', '0x00000123', '0x000000cf', '0x00000118', '0x00000099', '0x00000032', '0x00000016', '0x0000001f', '0x000000fb', '0x00000080', '0x00000117', '0x00000043', '0x000000aa', '0x000000e8', '0x0000001d', '0x000000c4', '0x00000068', '0x00000127', '0x00000055', '0x0000011c', '0x00000042', '0x000000c6', '0x000000cb', '0x000000ee', '0x000000ff', '0x00000126', '0x000000f6', '0x0000007b', '0x0000009b', '0x00000015', '0x00000086', '0x00000005', '0x00000079', '0x00000034', '0x00000096', '0x00000125', '0x0000003f', '0x0000005a', '0x000000cc', '0x0000004f', '0x0000005c', '0x00000126', '0x000000f4', '0x000000c4', '0x0000011e', '0x00000034', '0x00000057', '0x00000039', '0x00000007', '0x000000cb', '0x00000128', '0x00000110', '0x000000bc', '0x00000098', '0x000000d1', '0x0000010a', '0x00000000', '0x0000009e', '0x000000ae', '0x00000073', '0x000000a7', '0x00000102', '0x000000ac', '0x00000069', '0x0000005e', '0x00000012', '0x000000d4', '0x00000082', '0x00000046', '0x000000cd', '0x000000e0', '0x00000123', '0x0000001a', '0x000000eb', '0x00000125', '0x00000067', '0x000000ba', '0x000000b2', '0x000000ba', '0x00000015', '0x0000001d', '0x0000003d', '0x0000000f', '0x000000cc', '0x0000009c', '0x000000e8', '0x0000002a', '0x000000d9', '0x000000b2', '0x00000026', '0x00000049', '0x0000011b', '0x0000002b', '0x000000d2', '0x00000103', '0x00000005', '0x000000f1', '0x00000092', '0x00000057', '0x000000c1', '0x0000001f', '0x0000008f', '0x000000a6', '0x000000de', '0x000000f9', '0x000000a2', '0x0000005b', '0x000000af', '0x00000031', '0x00000091', '0x000000ec', '0x00000025', '0x0000011a', '0x00000052', '0x000000fc', '0x000000d8', '0x00000071', '0x0000010f', '0x00000098', '0x00000066', '0x00000020', '0x00000082', '0x0000004d', '0x00000082', '0x0000008b', '0x00000066', '0x000000ce', '0x00000010', '0x00000054', '0x000000f2', '0x00000014', '0x00000117', '0x00000115', '0x00000020', '0x0000006b', '0x00000043', '0x000000a4', '0x000000c3', '0x00000095', '0x00000025', '0x00000060', '0x000000da', '0x0000011f', '0x000000c6', '0x00000013', '0x000000d4', '0x0000011b', '0x0000011b', '0x0000003c', '0x00000028', '0x00000025', '0x00000094', '0x000000f4', '0x00000064', '0x000000a8', '0x000000f4', '0x0000002d', '0x00000014', '0x000000df', '0x00000107', '0x000000f8', '0x000000ad', '0x0000002c', '0x000000a2', '0x00000035', '0x0000007d', '0x000000b8', '0x00000083', '0x00000005', '0x000000cd', '0x000000c9', '0x00000122', '0x000000f6', '0x00000064', '0x00000009', '0x00000114', '0x000000f9', '0x000000e8', '0x00000114', '0x00000079', '0x00000080', '0x0000009f', '0x00000077', '0x0000005c', '0x000000b0', '0x00000114', '0x00000113', '0x0000002b', '0x00000007', '0x00000004', '0x000000c7', '0x00000026', '0x00000096', '0x000000dd', '0x0000005d', '0x000000d6', '0x00000078', '0x0000001a', '0x00000091', '0x00000111', '0x00000119', '0x00000032', '0x000000eb', '0x000000d6', '0x00000120', '0x0000005a', '0x00000107', '0x000000e7', '0x0000007e', '0x00000019', '0x00000061', '0x000000ba', '0x000000aa', '0x000000ae', '0x0000004e', '0x000000c9', '0x000000c2', '0x0000000b', '0x0000002d', '0x000000e5', '0x00000117', '0x000000b7', '0x000000bd', '0x000000fc', '0x0000010c', '0x0000004e', '0x00000076', '0x0000007c', '0x0000004a', '0x00000024', '0x00000124', '0x0000012b', '0x000000e6', '0x00000121', '0x0000000c', '0x0000000c', '0x000000fa', '0x00000051', '0x0000004e', '0x00000114', '0x00000073', '0x00000062', '0x000000ed', '0x00000011', '0x00000000', '0x000000eb', '0x00000081', '0x00000098', '0x0000002e', '0x000000a5', '0x00000102', '0x0000007e', '0x00000083', '0x00000096', '0x0000004a', '0x00000091', '0x000000ca', '0x00000044', '0x000000f0', '0x0000000f', '0x00000083', '0x000000dc', '0x0000001c', '0x00000003', '0x00000023', '0x000000d9', '0x00000089', '0x000000fa', '0x0000004e', '0x000000b6', '0x000000b1', '0x00000092', '0x000000c2', '0x0000000c', '0x00000089', '0x00000085', '0x0000010c', '0x000000ea', '0x0000004a', '0x000000a2', '0x00000024', '0x000000fd', '0x0000005e', '0x000000db', '0x00000055', '0x0000000a', '0x000000da', '0x00000116', '0x0000004b', '0x000000bc', '0x0000001d', '0x00000012', '0x000000d5', '0x000000d0', '0x00000079', '0x000000c3', '0x00000073', '0x00000120', '0x0000009f', '0x000000a6', '0x00000061', '0x00000060', '0x00000095', '0x0000006a', '0x00000065', '0x00000094', '0x000000f6', '0x00000005', '0x00000106', '0x00000032', '0x0000003d', '0x000000fd', '0x00000000', '0x000000f3', '0x00000059', '0x0000000f', '0x00000057', '0x00000068', '0x00000014', '0x000000d1', '0x00000082', '0x000000c3', '0x000000a9', '0x00000062', '0x0000000c', '0x0000002e', '0x00000094', '0x0000009a', '0x000000e2', '0x00000097', '0x000000d5', '0x00000082', '0x000000f3', '0x00000056', '0x00000059', '0x00000071', '0x0000003d', '0x00000003', '0x00000049', '0x0000003a', '0x00000030', '0x00000020', '0x00000017', '0x00000091', '0x00000074', '0x00000051', '0x00000044', '0x00000100', '0x0000004c', '0x000000c5', '0x00000095', '0x00000122', '0x00000050', '0x00000044', '0x000000ee', '0x000000be', '0x00000001', '0x00000062', '0x000000c5', '0x00000015', '0x00000062', '0x00000120', '0x000000b1', '0x00000057', '0x0000003c', '0x00000096', '0x0000002f', '0x00000074', '0x000000a9', '0x000000dd', '0x0000001d', '0x00000080', '0x000000ba', '0x0000002d', '0x0000010a', '0x00000041', '0x000000f5', '0x0000012b', '0x00000110', '0x000000c1', '0x000000ae', '0x000000af', '0x00000066', '0x000000fd', '0x0000009c', '0x0000000d', '0x0000001a', '0x000000c8', '0x00000117', '0x00000050', '0x00000078', '0x000000c4', '0x0000002b', '0x000000a5', '0x00000013', '0x0000007d', '0x000000d5', '0x000000fc', '0x0000003a', '0x000000f1', '0x00000097', '0x00000065', '0x000000ee', '0x00000121', '0x000000d1', '0x000000b5', '0x000000ec', '0x00000032', '0x00000104', '0x000000e8', '0x00000114', '0x000000a8', '0x000000bb', '0x00000062', '0x000000f8', '0x000000cf', '0x000000d2', '0x00000081', '0x00000029', '0x00000098', '0x0000011e', '0x000000bc', '0x00000050', '0x000000b1', '0x000000a1', '0x0000010f', '0x000000a3', '0x00000091', '0x00000086', '0x0000009c', '0x00000109', '0x0000001a', '0x000000f9', '0x000000f5', '0x0000011e', '0x000000bb', '0x00000113', '0x00000063', '0x0000009b', '0x0000007f', '0x00000041', '0x00000094', '0x00000021', '0x00000002', '0x00000083', '0x000000ee', '0x00000007', '0x00000081', '0x00000095', '0x0000005b', '0x00000019', '0x000000a1', '0x00000022', '0x00000113', '0x00000061', '0x0000006a', '0x000000c2', '0x0000002e', '0x00000073', '0x00000129', '0x0000008c', '0x000000f0', '0x00000092', '0x00000031', '0x00000088', '0x000000a3', '0x00000084', '0x0000011b', '0x00000081', '0x000000a9', '0x00000082', '0x00000002', '0x00000121', '0x0000005d', '0x000000bb', '0x0000000b', '0x00000117', '0x0000003e', '0x00000058', '0x00000083', '0x000000a8', '0x000000f7', '0x000000f8', '0x0000001c', '0x000000d0', '0x00000125', '0x00000120', '0x00000114', '0x00000072', '0x00000113', '0x00000064', '0x0000011b', '0x00000029', '0x00000126', '0x0000003c', '0x00000115', '0x00000040', '0x0000004f', '0x00000110', '0x00000014', '0x000000b7', '0x00000120', '0x000000d7', '0x000000f1', '0x0000003b', '0x000000e3', '0x0000004d', '0x00000070', '0x0000004b', '0x000000de', '0x000000d3', '0x000000b1', '0x00000111', '0x00000127', '0x0000004e', '0x00000062', '0x000000ac', '0x000000d7', '0x00000097', '0x000000a5', '0x000000e8', '0x00000041', '0x0000010d', '0x00000005', '0x0000009a', '0x0000005c', '0x0000002f', '0x0000010f', '0x00000063', '0x00000059', '0x0000009c', '0x000000e6', '0x00000052']
```

Finally, solve the system of equations.
```python
import numpy as np

check = open('check.bin', 'rb').read()

b = [int.from_bytes(check[i:i+4], byteorder='little') for i in range(0, len(check), 4)]
b = np.array(b)

with open("coefficients.txt") as f:
    raw = f.read().strip()
    hex_list = eval(raw)
    A = np.array([int(x, 16) for x in hex_list]).reshape((35, 35))

x = np.linalg.solve(A, b)

print(x)
flag = "HTB{by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy"
try:
    flag += ''.join(chr(round(i)) for i in x) + '}'
    print("Flag:", flag)
except:
    print("No solution")

```

`Flag: HTB{by_4dd1ng_nd_multiply1ng_w3_pl4y_4_l1ttl3_m3l0dy_tuturututu_n3v3r_g0nna_g1v3_y0u_up}`