# Network Scanner

Ứng dụng quét mạng để phát hiện và phân tích các thiết bị đang hoạt động trong mạng nội bộ (LAN).

## Cài đặt

1. Cài đặt Python 3.7 hoặc cao hơn
2. Cài đặt các thư viện cần thiết:
```bash
pip install -r requirements.txt
```

3. **Quan trọng**: Trên Windows, bạn cần:
   - Cài đặt Nmap: https://nmap.org/download.html
   - Chạy ứng dụng với quyền Administrator để quét ARP và ICMP

## Sử dụng

Chạy ứng dụng:
```bash
python main.py
```

Hoặc:
```bash
python gui_main.py
```

## Tính năng

- ✅ Quét mạng bằng ARP, ICMP (ping), TCP, hoặc Tổng hợp
- ✅ Tự động phát hiện mạng hiện tại
- ✅ Quét cổng và dịch vụ
- ✅ Phát hiện hệ điều hành
- ✅ Tra cứu vendor từ MAC address
- ✅ Xuất kết quả ra CSV hoặc JSON
- ✅ Giao diện trực quan với Tkinter

## Lưu ý

- Ứng dụng yêu cầu quyền Administrator trên Windows
- Một số thiết bị có thể không phản hồi ping nhưng vẫn online
- Quét mạng lớn có thể mất thời gian

## Cấu trúc dự án

- `main.py` - Entry point
- `gui_main.py` - Giao diện chính
- `network_scanner.py` - Module quét mạng
- `scan_tab.py` - Tab quét mạng
- `results_tab.py` - Tab kết quả
- `analysis_tab.py` - Tab phân tích
- `settings_tab.py` - Tab cài đặt

