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



