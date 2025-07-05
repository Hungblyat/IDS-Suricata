# IDS-Suricata

test web app : DVWA 

set-up DVWA : https://www.youtube.com/watch?v=WkyDxNJkgQ4

## Giới thiệu về Suricata

Suricata là một hệ thống phát hiện xâm nhập và hệ thống ngăn chặn xâm nhập dựa trên mã nguồn mở. Nó được phát triển bởi Open Information Security Foundation.

Tính năng chính
* IDS/IPS	: Phát hiện và ngăn chặn các cuộc tấn công mạng
* Protocol Detection : Phân tích sâu nhiều giao thức như HTTP, TLS, DNS, FTP, SMB, SSH,...
* Multi-threaded Engine :	Hỗ trợ chạy song song (đa luồng) cho hiệu năng cao
* Rule compatibility	: Cú pháp rule giống với của Snort
* Logging nâng cao : Hỗ trợ xuất log theo định dạng EVE JSON, PCAP,...
* NetFlow/Flow-based logging : Ghi log theo luồng (flow), hỗ trợ các giải pháp phân tích mạng
* TLS fingerprinting : Phát hiện máy khách đáng ngờ dù không giải mã nội dung TLS
* File Extraction : Có thể trích xuất file tải xuống từ HTTP/FTP/... để phân tích

## Cài đặt Suricata trên Ubunu/Debian

Sử dụng các lệnh sau để cài đặt Suricata ở version mới nhất : 
```bash
  sudo add-apt-repository ppa:oisf/suricata-stable
  sudo apt-get update
  sudo apt-get install suricata
```
### Cấu trúc câu lệnh của 

Câu lệnh của Suricata hay Snort tuân theo format trên : 

```<Action> <Rule Header> <Rule Options>```

* Action : xác định những gì xảy ra khi quy tắc khớp với nhau.
* Rule Header: Xác định giao thức, địa chỉ IP, cổng và hướng xử lý của quy tắc.
* Rule Options :  Xác định các thông tin chi tiết cụ thể của quy tắc

Action : 
* alert - Sinh ra cảnh báo khi kích hoạt rule
* block - chọn gói tin hiện tại và các gói tin cunf luồng
* drop - bỏ gói tin và sinh ra cảnh báo
* reject - chấm dứt phiên với TCP RESET hoặc ICMP không thể truy cập được

Rule Header : 

bao gồm các trường như : Protocol , Src , src-port ,direction , dst , dst-port 

* Protocol : Suricata hỗ trợ các giao thức cơ bản như : tcp , udp , http , icmp và hầu hết các giao thức cơ bản khác
* Src , dst : chỉ định các địa chỉ rule áp dụng : nó có thể viết cho 1 ip như : 10.10.10.10 hoặc cho 1 dải 10.10.10.0/24 hoặc các dải trong 1 mảng [10.10.10.0/24,192.168.120.121] , có thể sửu dụng dấu ! để phủ 
* src-port, dst-port : chỉ định các cổng : có thể là 80 , 53 , hoặc trong 1 khoảng như 100-500 ,-500 (từ 1 đến 500) ...
* direction : có 2 hướng là -> chỉ định nguồn đến đích và <-> hoặc cả 2 hướng

Rules Options : 

##### General Rule Options

Các tùy chọn quy tắc chung cung cấp thông tin về một quy tắc, nhưng chúng hoàn toàn không thay đổi những gì một quy tắc nhất định tìm kiếm trong một gói

![image](https://github.com/user-attachments/assets/44d8e519-32d4-401f-be70-d113589e7bbb)

###### 1. msg 
msg : Được sử dụng để thêm một thông báo mô tả quy tắc. Thông điệp nên tóm tắt mục đích của quy tắc và nó sẽ được xuất ra cùng với các sự kiện được tạo bởi quy tắc.

format : ```msg:"message";```

###### 2. reference
refence : sử dụng để chèn thêm thông tin tham khảo ngoài vào cảnh báo, thường để chỉ nguồn gốc, tiêu chuẩn hoặc CVE liên quan đến lỗ hổng/tấn công mà rule phát hiện.

format :
```reference:scheme,id;```

ví dụ : reference:url|cve,www.example.com;

###### 3. gid
gid (group id) : Từ khóa GID có thể được sử dụng để cung cấp cho các nhóm chữ ký khác nhau một giá trị ID khác (như trong SID). Suricata theo mặc định sử dụng Gid 1. Có thể sửa đổi giá trị mặc định. 

###### 4. sid 
sid : Số hiêu xác định duy nhất một quy tắc. không thể có 2 rule có cùng 1 sid . sid có thể có giá trị bất kỳ >0 . Có 1 số quy chuẩn để đặt rule như sau https://sidallocation.org/

###### 5. rev
rev : Xác định phiên bản sửa đổi của một quy tắc đã cho. Tùy chọn này nên được sử dụng cùng với từ khóa SID và nên được tăng lên mỗi lần thay đổi theo quy tắc.

ví dụ : 
```
sid:1000001; rev:1;
sid:1000001; rev:2;
```

###### 6. classtype 
classtype : Cung cấp thông tin về việc phân loại các quy tắc và cảnh báo. Nó bao gồm một tên ngắn, một tên dài và một ưu tiên. Nó có thể cho biết ví dụ liệu một quy tắc chỉ là thông tin hay là về CVE. 
- Trong suricata classtype được quy định về phân loại và mức độc trên file /etc/suricata/classification.config

###### 7. priority 
priority : Đi kèm với một giá trị số bắt buộc có thể nằm trong khoảng từ 1 đến 255. Các giá trị 1 đến 4 thường được sử dụng. Ưu tiên cao nhất là 1. Chữ ký với mức độ ưu tiên cao hơn sẽ được kiểm tra trước. Thông thường các chữ ký có mức độ ưu tiên được xác định thông qua định nghĩa classtype

##### Payload Detection Rule Options


ví dụ về 1 rule :


```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)```

### Cấu hình các rule cơ bản 

Phát hiện lưu lượng icmp : 

```alert icmp any any -> any any (msg: "ping alert ";sid:1000001;rev:1;)```

![image](https://github.com/user-attachments/assets/1f3dee95-a48f-425f-aa39-6fd375499557)

Phát hiện lưu lượng http : 

```alert http any any -> any any (msg:"Http traffic"; sid:1000002; rev:1;)```

Thử với câu lệnh : curl http://example.com và xem kết quả

![image](https://github.com/user-attachments/assets/0aded53b-4f68-4b92-97db-2a16813d2322)

Phát hiện lưu lượng tcp với giao thức SSH

```alert tcp anyalert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1000006; rev:1;)```

![image](https://github.com/user-attachments/assets/d44050e5-a291-4dcd-9ecf-9b180018a537)

#### Phát hiện các tấn công : 

Demo với việc tấn công dos bằng việc gửi lượng lớn các lưu lượng đến 1 máy :

Sử dụng tool hping3 để sinh ra lượng lớn lưu lượng đến 1 máy host với giao thức TCP cờ SYN 

```sudo hping3 -c 15000 -d 120 -S -w 64 --flood --rand-source 192.168.184.141```

luật phát hiện : 

```alert tcp any any -> any any (msg:"Dectect TCP SYN FLOOD ATTACK"; flow:to_server; flags: S,12; threshold: type both, track by_dst, count 5000, seconds 5;sid:1000010;)```

![image](https://github.com/user-attachments/assets/a6ce8876-b4aa-4599-bc01-dfa2facd49d7)

#### Phát hiện tấn công SQLi 
```
alert http any any -> any any (msg: "Possible SQL Injection attack contain single quote in GET method"; flow:established,to_server; content:"'"; nocase; http_uri; sid:2000001;)
alert http any any -> any any (msg: "Possible SQL Injection attack contain UNION in Get method"; flow:established,to_server; content:"union"; nocase;  http_uri; sid:2000002;)
alert http any any -> any any (msg: "Possible SQL Injection attack contain SELECT in GET method"; flow:established,to_server; content:"select"; nocase;  http_uri; sid:2000003;)
alert http any any -> any any (msg: "Possible SQL Injection attack contain single quote in POST method"; flow:established,to_server; content:"'"; nocase; http_client_body; sid:2000004;)
alert http any any -> any any (msg: "Possible SQL Injection attack contain UNION in POST method"; flow:established,to_server; content:"union"; nocase;  http_client_body; sid:2000005;)
alert http any any -> any any (msg: "Possible SQL Injection attack contain SELECT in POST method"; flow:established,to_server; content:"select"; nocase;  http_client_body; sid:2000006;)
```

#### Phát hiện tấn công XSS 

```
alert http any any -> any any (msg:"Possible XSS attack, script tag"; content:"script"; nocase; pcre:"/(<|%3C|%253C)script/smi"; classtype:web-application-attack; sid:300001; rev:1;)
alert http any any -> any any (msg:"Possible XSS attack, js event handler"; content:"on"; nocase; pcre:"/on\w+(%3D|=)/smi"; classtype:web-application-attack; sid:300002; rev:1;)
alert http any any -> any any (msg:"Possible XSS attack, js protocol"; content:"javascript"; nocase; pcre:"/javascript(:|%3A)/smi"; classtype:web-application-attack; sid:300003; rev:1;)
```

