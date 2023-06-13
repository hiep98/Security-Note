# SMB ENUM

![](../media/pivoting_1.png)

SCAN SERVICE:![](../media/pivoting_2.png)

SCAN HDH CỦA MÁY CLIENT:

nmap --script smb-os-discovery.nse -sV 10.50.150.158

![](../media/pivoting_3.png)

Enum user thông qua rid: enum4linux -r 10.50.150.158

![](../media/pivoting_4.png)

get password policy information: enum4linux -P 10.50.150.158 ![](../media/pivoting_5.png)

Get user list and detail:  enum4linux -U -d 10.50.150.158

![](../media/pivoting_6.png)

Từ cái này thấy được tài khoản 0 bị khóa, pass 0 hết hạn, có thể bruteforce được

Get share list: enum4linux -r 10.50.150.158

![](../media/pivoting_7.png)

Ở đây share Josephine đáng chú ý. Có thể có khả năng truy cập 0 cần mk

Dùng smbmap để xem quyền : smbmap -H 10.50.150.158

![](../media/pivoting_8.png)

Giờ chúng ta có thể xem được quyền smb. Có thể crack acc smb bằng:

crackmapexec smb 10.50.150.158   --shares -u ‘’ -p ‘’

![](../media/pivoting_9.png)

Truy cập vào thư mục được share: smbclient //10.50.150.158/osephine

![](../media/pivoting_10.png)

Sau đó get file về

![](../media/pivoting_11.png)

Tài khoản này có thể là tk ssh:

![](../media/pivoting_12.png)

Sau đó, tải linpeas về máy tấn công

![](../media/pivoting_13.png)

Rồi tạo web server: python -m SimpleHTTPServer

![](../media/pivoting_14.png)

Bên máy ssh thì rồi wget tải linpeas từ máy tấn công về rồi chạy.

![](../media/pivoting_15.png)

Tìm thấy được khá nhiều thứ có thể khai thác

![](../media/pivoting_16.png)

Bài này dễ nên sẽ dùng cách đơn giản hơn

![](../media/pivoting_17.png)

Có tài khoản root

![](../media/pivoting_18.png)

Lên quyền root

![](../media/pivoting_19.png)

PIVOTING

![](../media/pivoting_20.png)

Sau khi biết có vcms thì search trên msf

![](../media/pivoting_21.png)

Leo thang nếu chiếm quyền thấp

![](../media/pivoting_22.png)

![](../media/pivoting_23.png)

![](../media/pivoting_24.png)

Xem ip

![](../media/pivoting_25.png)

Autoroute

![](../media/pivoting_26.png)

Tiến hành scan các port trên network mới

![](../media/pivoting_27.png)

Tạo portfw

![](../media/pivoting_28.png)

Scan service vào khai khác

![](../media/pivoting_29.png)

TẠO SHELL VỚI MSFVENOM

![](../media/pivoting_30.png)

VỀ REVERSE_TCP LÀ STAGED PAYLOAD. VÌ VẬY CẦN THÊM 1 LISTENER RIÊNG.  Tham khảo hình dưới

![](../media/pivoting_31.png)

Sau đó, chạy file backdoor vừa tạo để lấy reverse shell

![](../media/pivoting_32.png)

Stageless như hình dưới thì netcat có thể bắt được. còn staged thì nc không bắt được.

![](../media/pivoting_33.png)

