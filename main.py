"""
Main Entry Point
Khởi chạy ứng dụng Network Scanner
"""
import sys
import os
import tkinter as tk
from tkinter import messagebox

# Kiểm tra Python version
if sys.version_info < (3, 7):
    messagebox.showerror("Lỗi", "Yêu cầu Python 3.7 trở lên!") #in ra lỗi nếu Python version không đạt yêu cầu
    sys.exit(1)

# Kiểm tra các module cần thiết
missing_modules = [] #danh sách các thư viện cần thiết

try:
    import scapy
except ImportError: #nếu không nhập được scapy thì thêm vào missing_modules
    missing_modules.append("scapy") #thêm scapy vào danh sách các thư viện cần thiết

try:
    import nmap
except ImportError: #nếu không nhập được nmap thì thêm vào missing_modules
    missing_modules.append("python-nmap") #thêm python-nmap vào danh sách các thư viện cần thiết

try:
    import psutil
except ImportError: #nếu không nhập được psutil thì thêm vào missing_modules
    missing_modules.append("psutil") #thêm psutil vào danh sách các thư viện cần thiết

try:
    import pandas
except ImportError: #nếu không nhập được pandas thì thêm vào missing_modules
    missing_modules.append("pandas") #thêm pandas vào danh sách các thư viện cần thiết

if missing_modules: #nếu có thư viện cần thiết thì in ra lỗi
    error_msg = "Thiếu các thư viện cần thiết:\n\n" #lỗi thiếu thư viện cần thiết
    error_msg += "\n".join(f"• {m}" for m in missing_modules) #thêm thư viện cần thiết vào lỗi
    error_msg += "\n\nVui lòng chạy: pip install -r requirements.txt" #chạy requirements.txt để cài đặt các thư viện cần thiết
    messagebox.showerror("Lỗi", error_msg) #hiển thị lỗi
    sys.exit(1) #thoát khỏi ứng dụng

# Nhập và chạy ứng dụng
try:
    from gui_main import NetworkScannerApp #thêm gui_main.py vào
    
    if __name__ == "__main__":
        root = tk.Tk() #tạo cửa sổ
        app = NetworkScannerApp(root) #tạo ứng dụng
        
        # Căn giữa cửa sổ
        root.update_idletasks() #cập nhật cửa sổ
        width = root.winfo_width() #lấy chiều rộng cửa sổ
        height = root.winfo_height() #lấy chiều cao cửa sổ
        x = (root.winfo_screenwidth() // 2) - (width // 2) #tính toán vị trí của cửa sổ
        y = (root.winfo_screenheight() // 2) - (height // 2) #tính toán vị trí của cửa sổ
        root.geometry(f'{width}x{height}+{x}+{y}') #đặt kích thước và vị trí của cửa sổ
        
        root.mainloop() #chạy ứng dụng
except Exception as e:
    messagebox.showerror("Lỗi", f"Không thể khởi chạy ứng dụng:\n{e}")
    import traceback #in ra lỗi
    traceback.print_exc() #in ra lỗi
    sys.exit(1) #thoát ứng dụng

