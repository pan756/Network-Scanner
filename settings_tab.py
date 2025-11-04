"""
Tab 4 - Cài đặt
Cấu hình ứng dụng và thông tin
"""
import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import os

class SettingsTab: #tạo tab cài đặt
    def __init__(self, parent, app): #khởi tạo tab cài đặt
        self.parent = parent #cửa sổ chính
        self.app = app #ứng dụng chính
        self.settings_file = "settings.json"
        self.settings = self.load_settings() #tải cài đặt từ file
        
        self.setup_ui() #gọi hàm setup_ui
        self.load_settings_to_ui() #gọi hàm load_settings_to_ui
    
    def setup_ui(self): #thiết lập giao diện
        """Thiết lập giao diện"""
        # Notebook cho Cài đặt và Thông tin
        main_notebook = ttk.Notebook(self.parent) #tạo notebook cho Settings và Info
        main_notebook.pack(fill=tk.BOTH, expand=True) #đặt notebook cho Settings và Info vào cửa sổ
        
        # Tab Cài đặt
        settings_frame = ttk.Frame(main_notebook, padding=20) #tạo khung cho tab Cài đặt
        main_notebook.add(settings_frame, text="⚙️ Cài đặt") #đặt tab Cài đặt vào notebook
        self.setup_settings_tab(settings_frame) #gọi hàm setup_settings_tab
        
        # Tab Tip & Giới thiệu
        info_frame = ttk.Frame(main_notebook, padding=20) #tạo khung cho tab Tip & Giới thiệu
        main_notebook.add(info_frame, text="ℹ️ Tip & Giới thiệu") #đặt tab Tip & Giới thiệu vào notebook
        self.setup_info_tab(info_frame) #gọi hàm setup_info_tab
    
    def setup_settings_tab(self, parent): #thiết lập tab cài đặt
        """Thiết lập tab cài đặt"""
        # Khung chính với cuộn
        canvas = tk.Canvas(parent) # tạo khung chính với cuộn
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview) # tạo thanh cuộn
        scrollable_frame = ttk.Frame(canvas) # tạo khung chính với cuộn
        
        scrollable_frame.bind( #sự kiện cuộn
            "<Configure>", #sự kiện cuộn
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")) #sự kiện cuộn
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw") #tạo khung chính với cuộn
        canvas.configure(yscrollcommand=scrollbar.set) #config cho thanh cuộn
        
        # Timeout
        timeout_frame = ttk.LabelFrame(scrollable_frame, text="Thời gian ping", padding=15) #tạo khung thời gian ping
        timeout_frame.pack(fill=tk.X, pady=10)
        
        self.timeout_var = tk.DoubleVar(value=self.settings.get('timeout', 1.0)) #tạo biến thời gian ping
        timeout_scale = ttk.Scale(timeout_frame, #tạo thanh thời gian ping
                                 from_=0.1, #from cho thanh thời gian ping (từ 0.1)
                                 to=5.0, #to cho thanh thời gian ping (tới 5.0)
                                 variable=self.timeout_var, #biến lựa chọn thời gian ping
                                 orient=tk.HORIZONTAL) #tạo thanh thời gian ping
        timeout_scale.pack(fill=tk.X, pady=5) #đặt thanh thời gian ping vào khung
        
        timeout_label = ttk.Label(timeout_frame, #tạo nhãn thời gian ping
                                 textvariable=self.timeout_var, #biến lựa chọn thời gian ping
                                 font=('Segoe UI', 10)) #font cho nhãn thời gian ping
        timeout_label.pack() #đặt nhãn thời gian ping vào khung
        
        timeout_info = ttk.Label(timeout_frame, #tạo nhãn thông tin thời gian ping
                               text="Thời gian chờ phản hồi (giây). Giá trị nhỏ hơn = nhanh hơn nhưng có thể bỏ sót thiết bị.",
                               font=('Segoe UI', 10), #font cho thông tin thời gian ping
                               foreground='gray', #foreground cho thông tin thời gian ping
                               wraplength=500) #wraplength cho thông tin thời gian ping
        timeout_info.pack(pady=5) #đặt thông tin thời gian ping vào khung
        
        # Số luồng (số luồng đồng thời khi quét)
        threads_frame = ttk.LabelFrame(scrollable_frame, text="Số luồng", padding=15) #tạo khung số luồng
        threads_frame.pack(fill=tk.X, pady=10) #đặt khung số luồng vào khung
        
        self.threads_var = tk.IntVar(value=self.settings.get('threads', 100)) #tạo biến số luồng
        threads_scale = ttk.Scale(threads_frame, #tạo thanh số luồng
                                  from_=1, #from cho thanh số luồng (từ 1)
                                  to=200, #to cho thanh số luồng (tới 200)
                                  variable=self.threads_var, #biến lựa chọn số luồng
                                  orient=tk.HORIZONTAL) #tạo thanh số luồng
        threads_scale.pack(fill=tk.X, pady=5) #đặt thanh số luồng vào khung
        
        threads_label = ttk.Label(threads_frame, #tạo nhãn số luồng
                                 textvariable=self.threads_var, #biến lựa chọn số luồng
                                 font=('Segoe UI', 10)) #font cho nhãn số luồng
        threads_label.pack() #đặt nhãn số luồng vào khung
        
        threads_info = ttk.Label(threads_frame, #tạo nhãn thông tin số luồng
                                text="Số luồng đồng thời khi quét. Nhiều hơn = nhanh hơn nhưng tốn tài nguyên.",
                                font=('Segoe UI', 10), #font cho thông tin số luồng
                                foreground='gray', #foreground cho thông tin số luồng
                                wraplength=500) #wraplength cho thông tin số luồng
        threads_info.pack(pady=5) #đặt thông tin số luồng vào khung
        
        # Nmap timing (tốc độ quét Nmap)
        nmap_frame = ttk.LabelFrame(scrollable_frame, text="Tốc độ quét Nmap", padding=15) #tạo khung tốc độ quét Nmap
        nmap_frame.pack(fill=tk.X, pady=10) #đặt khung tốc độ quét Nmap vào khung
        
        self.nmap_timing_var = tk.IntVar(value=self.settings.get('nmap_timing', 3)) #tạo biến tốc độ quét Nmap
        
        timing_options = [ #danh sách tốc độ quét Nmap
            ("T0 - Paranoid (Rất chậm)", 0), #danh sách tốc độ quét Nmap
            ("T1 - Sneaky (Chậm)", 1), #danh sách tốc độ quét Nmap
            ("T2 - Polite (Cẩn thận)", 2), #danh sách tốc độ quét Nmap
            ("T3 - Normal (Bình thường)", 3), #danh sách tốc độ quét Nmap
            ("T4 - Aggressive (Nhanh)", 4), #danh sách tốc độ quét Nmap
            ("T5 - Insane (Rất nhanh)", 5) #danh sách tốc độ quét Nmap
        ]
        
        for text, value in timing_options: #vòng lặp để tạo nút kiểm tra tốc độ quét Nmap
            ttk.Radiobutton(nmap_frame, #tạo nút kiểm tra tốc độ quét Nmap
                           text=text, #text cho nút kiểm tra tốc độ quét Nmap
                           variable=self.nmap_timing_var, #biến lựa chọn tốc độ quét Nmap
                           value=value).pack(anchor=tk.W, pady=2) #đặt nút kiểm tra tốc độ quét Nmap vào khung
        
        nmap_info = ttk.Label(nmap_frame, #tạo nhãn thông tin tốc độ quét Nmap
                             text="Tốc độ quét của Nmap. T3 là mặc định, cân bằng tốt. T4-T5 nhanh hơn nhưng có thể bị phát hiện.",
                             font=('Segoe UI', 10), #font cho thông tin tốc độ quét Nmap
                             foreground='gray', #foreground cho thông tin tốc độ quét Nmap
                             wraplength=500) #wraplength cho thông tin tốc độ quét Nmap
        nmap_info.pack(pady=5) #đặt thông tin tốc độ quét Nmap vào khung
        
        # Deep scan
        deep_frame = ttk.LabelFrame(scrollable_frame, text="Quét chi tiết", padding=15) #tạo khung quét chi tiết
        deep_frame.pack(fill=tk.X, pady=10) #đặt khung quét chi tiết vào khung
        
        self.deep_scan_var = tk.BooleanVar(value=self.settings.get('deep_scan', False)) #tạo biến quét chi tiết
        deep_check = ttk.Checkbutton(deep_frame, #tạo nút kiểm tra quét chi tiết
                                     text="Tự động phân tích sâu tất cả IP bằng python-nmap",
                                     variable=self.deep_scan_var) #tạo nút kiểm tra quét chi tiết
        deep_check.pack(anchor=tk.W) #đặt nút kiểm tra quét chi tiết vào khung
        
        deep_info = ttk.Label(deep_frame, #tạo nhãn thông tin quét chi tiết
                             text="Khi bật, ứng dụng sẽ tự động quét OS và dịch vụ cho tất cả thiết bị phát hiện. Chậm hơn nhưng chi tiết hơn.",
                             font=('Segoe UI', 10), #font cho thông tin quét chi tiết
                             foreground='gray', #foreground cho thông tin quét chi tiết
                             wraplength=500) #wraplength cho thông tin quét chi tiết
        deep_info.pack(pady=5) #đặt thông tin quét chi tiết vào khung
        
        # Buttons
        button_frame = ttk.Frame(scrollable_frame) #tạo khung nút
        button_frame.pack(fill=tk.X, pady=20) #đặt khung nút vào khung
        
        ttk.Button(button_frame, #tạo nút lưu cài đảt
                  text="💾 Lưu cài đặt",
                  command=self.save_settings).pack(side=tk.LEFT, padx=5) #đặt nút lưu cài đảt vào khung
        
        ttk.Button(button_frame, #tạo nút đặt lại mặc định
                  text="🔄 Đặt lại mặc định",
                  command=self.reset_settings).pack(side=tk.LEFT, padx=5) #đặt nút đặt lại mặc định vào khung
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True) #đặt khung chính với cuộn vào khung
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y) #đặt thanh cuộn vào khung
    
    def setup_info_tab(self, parent): #thiết lập tab thông tin
        """Thiết lập tab thông tin"""
        info_text = scrolledtext.ScrolledText(parent, #tạo trường nhập thông tin trạng thái
                                              wrap=tk.WORD, #wrap cho trường nhập thông tin trạng thái
                                              font=('Segoe UI', 11), #font cho trường nhập thông tin trạng thái
                                              height=30) #height cho trường nhập thông tin trạng thái
        info_text.pack(fill=tk.BOTH, expand=True) #đặt trường nhập thông tin trạng thái vào khung
        #Nội dung thông tin trong tab Tip & Giới thiệu
        content = """
╔══════════════════════════════════════════════════════════════╗
║            NETWORK SCANNER - HƯỚNG DẪN SỬ DỤNG               ║
╚══════════════════════════════════════════════════════════════╝

📋 MÔ TẢ
Ứng dụng quét mạng giúp phát hiện và phân tích các thiết bị đang hoạt động 
trong mạng nội bộ (LAN).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔧 CÁC TÍNH NĂNG CHÍNH

1. Quét mạng (Tab 1)
   • Quét mạng bằng ARP, ICMP (ping), TCP, hoặc Tổng hợp
   • Tự động phát hiện mạng hiện tại
   • Quét cổng cụ thể
   • Hiển thị tiến trình quét real-time

2. Kết quả (Tab 2)
   • Xem danh sách thiết bị phát hiện
   • Thông tin: IP, Hostname, MAC, Status, Ports, OS, Service, Vendor
   • Tìm kiếm và lọc kết quả
   • Xuất kết quả ra CSV hoặc JSON
   • Menu ngữ cảnh để copy hoặc phân tích sâu

3. Phân tích (Tab 3)
   • Phân tích chi tiết một thiết bị cụ thể
   • Quét cổng và dịch vụ
   • Phát hiện hệ điều hành
   • Xem thông tin raw từ Nmap

4. Cài đặt (Tab 4)
   • Cấu hình thời gian timeout
   • Điều chỉnh số luồng
   • Cấu hình tốc độ quét Nmap
   • Bật/tắt quét chi tiết tự động

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 CÁC MẸO SỬ DỤNG

• Quét ARP: Nhanh nhất, chỉ hoạt động trong cùng subnet
• Quét ICMP: Phát hiện thiết bị có phản hồi ping
• Quét TCP: Tìm thiết bị có cổng mở cụ thể
• Quét Tổng hợp: Kết hợp tất cả phương pháp (chậm nhất nhưng đầy đủ nhất)

• Để quét nhanh: Giảm timeout, tăng số luồng, dùng ARP scan
• Để quét chi tiết: Bật Deep Scan, quét cổng phổ biến (80,443,22,21,3389)

• Khi quét mạng lớn: Nên dùng ARP scan trước, sau đó phân tích sâu từng IP

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ LƯU Ý

• Ứng dụng yêu cầu quyền Administrator để quét ARP và ICMP
• Quét mạng có thể mất thời gian, đặc biệt với mạng lớn
• Một số thiết bị có thể không phản hồi ping (ICMP) nhưng vẫn online
• Quét quá nhanh có thể bị firewall chặn

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📚 THÔNG TIN KỸ THUẬT

• Ngôn ngữ: Python 3.7+
• Thư viện chính:
  - Scapy: ARP/ICMP quét
  - python-nmap: Port quét, phát hiện OS
  - mac-vendor-lookup: Tra cứu vendor từ MAC
  - psutil: Phát hiện interface mạng

• Hỗ trợ: Windows 10/11

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📞 HỖ TRỢ

Nếu gặp vấn đề, vui lòng kiểm tra:
1. Đã cài đặt đầy đủ dependencies (pip install -r requirements.txt)
2. Đang chạy với quyền Administrator (Windows)
3. Firewall không chặn ứng dụng
4. Nmap đã được cài đặt và có trong PATH

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Version: 1.0.0 - by Phạm Thành Sang
        """
        
        info_text.insert(1.0, content) #insert content vào trường nhập thông tin trạng thái
        info_text.config(state=tk.DISABLED) #config cho trường nhập thông tin trạng thái
    
    def load_settings(self) -> dict: #tải cài đảt từ file
        """Tải cài đặt từ file"""
        default = { #tạo cài đảt mặc định
            'timeout': 1.0, #thời gian ping
            'threads': 100, #số luồng
            'nmap_timing': 3, #tốc độ quét Nmap
            'deep_scan': False #quét sâu tất cả IP bằng python-nmap
        }
        
        if os.path.exists(self.settings_file): #nếu file tồn tại thì tải cài đảt từ file
            try:
                with open(self.settings_file, 'r') as f: #mở file
                    loaded = json.load(f) #tải cài đảt từ file
                    default.update(loaded) #cập nhật cài đảt
            except: #nếu có lỗi thì pass
                pass
        
        return default #trả về cài đảt mặc định
    
    def load_settings_to_ui(self): #tải cài đảt lên UI
        """Tải cài đặt lên UI"""
        self.timeout_var.set(self.settings.get('timeout', 1.0)) #thời gian ping
        self.threads_var.set(self.settings.get('threads', 100)) #số luồng
        self.nmap_timing_var.set(self.settings.get('nmap_timing', 3)) #tốc độ quét Nmap
        self.deep_scan_var.set(self.settings.get('deep_scan', False)) #quét sâu tất cả IP bằng python-nmap
    
    def save_settings(self): #lưu cài đảt
        """Lưu cài đặt"""
        self.settings = { #tạo cài đảt
            'timeout': self.timeout_var.get(), #thời gian ping
            'threads': self.threads_var.get(), #số luồng
            'nmap_timing': self.nmap_timing_var.get(), #tốc độ quét Nmap
            'deep_scan': self.deep_scan_var.get() #quét sâu tất cả IP bằng python-nmap
        }
        
        try:
            with open(self.settings_file, 'w') as f: #mở file
                json.dump(self.settings, f, indent=2) #lưu cài đảt vào file
            
            from tkinter import messagebox
            messagebox.showinfo("Thành công", "Đã lưu cài đặt!") #hiển thị thông báo thành công
        except Exception as e:
            from tkinter import messagebox 
            messagebox.showerror("Lỗi", f"Không thể lưu cài đặt:\n{e}") #hiển thị thông báo lỗi
    
    def reset_settings(self):
        """Đặt lại mặc định"""
        self.settings = { #tạo cài đảt mặc định
            'timeout': 1.0, #thời gian ping
            'threads': 100, #số luồng
            'nmap_timing': 3, #tốc độ quét Nmap
            'deep_scan': False #quét chi tiết   
        }
        self.load_settings_to_ui() #gọi hàm load_settings_to_ui
        self.save_settings() #gọi hàm save_settings
    
    def get_timeout(self) -> float: #lấy cài đảt thời gian ping
        """Lấy timeout"""
        return self.timeout_var.get() #lấy cài đảt thời gian ping
    
    def get_threads(self) -> int: #lấy cài đảt số luồng
        """Lấy số luồng"""
        return self.threads_var.get() #lấy cài đảt số luồng
    
    def get_nmap_timing(self) -> int: #lấy cài đảt tốc độ quét Nmap
        """Lấy Nmap timing"""
        return self.nmap_timing_var.get() #lấy cài đảt tốc độ quét Nmap
    
    def get_deep_scan(self) -> bool: #lấy cài đảt quét chi tiết
        """Lấy deep scan setting"""
        return self.deep_scan_var.get() #lấy cài đảt quét chi tiết

