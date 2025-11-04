"""
Tab 1 - Quét mạng
Giao diện và chức năng quét mạng
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import ipaddress
from datetime import datetime
from network_scanner import NetworkScanner #thêm network_scanner.py vào để thực hiện quét mạng (NetworkScanner)

class ScanTab: #tạo tab quét mạng
    def __init__(self, parent, app): #khởi tạo tab quét mạng
        self.parent = parent #cửa sổ chính
        self.app = app #ứng dụng chính
        self.scanner = None #trình quét
        self.scan_thread = None #thread quét
        self.results = [] #kết quả quét
        self.scanning = False #trạng thái quét
        
        self.setup_ui() #gọi hàm setup_ui
        # Tải cài đặt sau khi UI được tạo, nhưng chỉ khi settings_tab đã sẵn sàng
        self.parent.after(100, self.load_settings) #gọi hàm load_settings sau 100ms
    
    def setup_ui(self): #thiết lập giao diện
        """Thiết lập giao diện"""
        # KhungKhung chính
        main_frame = ttk.Frame(self.parent, padding=20) #tạo khung chính
        main_frame.pack(fill=tk.BOTH, expand=True) #đặt khung chính vào cửa sổ
        
        # Tiêu đề
        title_label = ttk.Label(main_frame, #tạo nhãn tiêu đề
                               text="Quét mạng", #text cho nhãn tiêu đề
                               font=('Segoe UI', 14, 'bold')) #font cho nhãn tiêu đề
        title_label.pack(anchor=tk.W, pady=(0, 20)) #đặt nhãn tiêu đề vào khung
        
        # Khung nhập thông tin
        input_frame = ttk.LabelFrame(main_frame, text="Thông tin quét", padding=15) #tạo khung nhập thông tin
        input_frame.pack(fill=tk.X, pady=(0, 15)) #đặt khung nhập thông tin vào khung
        
        # Khoảng mạng
        network_frame = ttk.Frame(input_frame) #tạo khung khoảng mạng   
        network_frame.pack(fill=tk.X, pady=5) #đặt khung khoảng mạng vào khung
        
        ttk.Label(network_frame, text="Khoảng mạng:", width=15).pack(side=tk.LEFT) #đặt nhãn khoảng mạng vào khung
        self.network_var = tk.StringVar(value="192.168.1.0/24") #tạo biến khoảng mạng
        network_entry = ttk.Entry(network_frame, textvariable=self.network_var, width=25) #tạo trường nhập khoảng mạng
        network_entry.pack(side=tk.LEFT, padx=5) #đặt trường nhập khoảng mạng vào khung
        
        auto_detect_btn = ttk.Button(network_frame, #tạo nút tự động phát hiện
                                     text="🔍 Tự động phát hiện",
                                     command=self.auto_detect_network) #gọi hàm tự động phát hiện
        auto_detect_btn.pack(side=tk.LEFT, padx=10) #đặt nút tự động phát hiện vào khung
        
        # Loại quét
        scan_type_frame = ttk.Frame(input_frame) #tạo khung loại quét
        scan_type_frame.pack(fill=tk.X, pady=5) #đặt khung loại quét vào khung
        
        ttk.Label(scan_type_frame, text="Loại quét:", width=15).pack(side=tk.LEFT) #đặt nhãn loại quét vào khung
        self.scan_type_var = tk.StringVar(value="Tổng hợp") #tạo biến loại quét
        
        scan_types = ["ICMP (ping)", "TCP", "ARP", "Tổng hợp"] #danh sách loại quét
        for stype in scan_types: #vòng lặp để tạo nút lựa chọn
            ttk.Radiobutton(scan_type_frame, #tạo nút lựa chọn
                           text=stype, #text cho nút lựa chọn
                           variable=self.scan_type_var, #biến lựa chọn
                           value=stype).pack(side=tk.LEFT, padx=10) #đặt nút lựa chọn vào khung
        
        # Cổng quét
        ports_frame = ttk.Frame(input_frame) #tạo khung cổng quét
        ports_frame.pack(fill=tk.X, pady=5) #đặt khung cổng quét vào khung
        
        ttk.Label(ports_frame, text="Cổng quét:", width=15).pack(side=tk.LEFT) #đặt nhãn cổng quét vào khung
        self.ports_var = tk.StringVar(value="80,443,22,21,3389,135,139,445") #tạo biến cổng quét
        ports_entry = ttk.Entry(ports_frame, textvariable=self.ports_var, width=50) #tạo trường nhập cổng quét
        ports_entry.pack(side=tk.LEFT, padx=5) #đặt trường nhập cổng quét vào khung
        
        ttk.Label(ports_frame, #tạo nhãn phân tách bằng dấu phẩy
                 text="(phân tách bằng dấu phẩy)",
                 font=('Segoe UI', 8), #font cho nhãn phân tách bằng dấu phẩy
                 foreground='gray').pack(side=tk.LEFT, padx=5) #đặt nhãn phân tách bằng dấu phẩy vào khung
        
        # Nút
        button_frame = ttk.Frame(main_frame) #tạo khung nút
        button_frame.pack(fill=tk.X, pady=10) #đặt khung nút vào khung
        
        self.start_btn = ttk.Button(button_frame, #tạo nút bắt đầu quét
                                    text="▶ Bắt đầu quét",
                                    command=self.start_scan, #gọi hàm bắt đầu quét
                                    style='Accent.TButton') #style cho nút bắt đầu quét
        self.start_btn.pack(side=tk.LEFT, padx=5) #đặt nút bắt đầu quét vào khung
        
        self.stop_btn = ttk.Button(button_frame, #tạo nút dừng quét
                                   text="⏹ Dừng quét",
                                   command=self.stop_scan, #gọi hàm dừng quét
                                   state=tk.DISABLED) #state cho nút dừng quét
        self.stop_btn.pack(side=tk.LEFT, padx=5) #đặt nút dừng quét vào khung
        
        # Thanh tiến trình
        progress_frame = ttk.LabelFrame(main_frame, text="Tiến trình", padding=10) #tạo khung tiến trình
        progress_frame.pack(fill=tk.X, pady=(0, 15)) #đặt khung tiến trình vào khung
        
        self.progress_var = tk.StringVar(value="0/0 (0%) • Trạng thái: Đã sẵn sàng quét") #tạo biến tiến trình
        ttk.Label(progress_frame, textvariable=self.progress_var).pack(anchor=tk.W, pady=5) #đặt biến tiến trình vào khung
        
        self.progress_bar = ttk.Progressbar(progress_frame, #tạo thanh tiến trình
                                           mode='indeterminate', #mode cho thanh tiến trình
                                           length=400) #length cho thanh tiến trình
        self.progress_bar.pack(fill=tk.X, pady=5) #đặt thanh tiến trình vào khung
        
        # Thông tin trạng thái
        status_frame = ttk.LabelFrame(main_frame, text="Thông tin trạng thái", padding=10) #tạo khung thông tin trạng thái
        status_frame.pack(fill=tk.X) #đặt khung thông tin trạng thái vào khung
        
        self.status_text = tk.Text(status_frame, #tạo trường nhập thông tin trạng thái
                                  height=8, #height cho trường nhập thông tin trạng thái
                                  font=('Consolas', 9), #font cho trường nhập thông tin trạng thái
                                  wrap=tk.WORD) #wrap cho trường nhập thông tin trạng thái
        self.status_text.pack(fill=tk.BOTH, expand=True) #đặt trường nhập thông tin trạng thái vào khung
        
        scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.status_text.yview) #tạo thanh cuộn
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y) #đặt thanh cuộn vào khung
        self.status_text.config(yscrollcommand=scrollbar.set) #config cho trường nhập thông tin trạng thái
    
    def load_settings(self): #tải cài đặt từ settings tab
        """Tải cài đặt từ settings tab"""
        try:
            if self.app.settings_tab: #nếu settings tab tồn tại thì lấy timeout và threads từ settings tab
                timeout = self.app.settings_tab.get_timeout() #lấy timeout từ settings tab
                threads = self.app.settings_tab.get_threads() #lấy threads từ settings tab
                self.scanner = NetworkScanner(timeout=timeout, threads=threads) #tạo trình quét
            else:
                self.scanner = NetworkScanner() #tạo trình quét
        except:
            # Mặc định nếu settings_tab chưa sẵn sàng
            self.scanner = NetworkScanner() #tạo trình quét
    
    def auto_detect_network(self): #tự động phát hiện mạng
        """Tự động phát hiện mạng"""
        if not self.scanner: #nếu trình quét không tồn tại thì tải cài đặt từ settings tab
            self.load_settings() #tải cài đặt từ settings tab
        
        interfaces = self.scanner.get_network_interfaces() #lấy interface từ trình quét
        
        if interfaces: #nếu interface tồn tại thì lấy interface đầu tiên
            # Lấy interface đầu tiên
            iface = interfaces[0] #lấy interface đầu tiên
            self.network_var.set(iface['cidr']) #đặt interface vào biến khoảng mạng
            self.log_status(f"Đã phát hiện mạng: {iface['cidr']} (Interface: {iface['name']})") #hiển thị thông tin mạng
        else:
            messagebox.showwarning("Cảnh báo", "Không thể phát hiện mạng. Vui lòng nhập thủ công.") #hiển thị thông báo cảnh báo
    
    def parse_ports(self, ports_str: str) -> list:
        """Parse chuỗi cổng thành danh sách"""
        ports = [] #khởi tạo biến ports
        try:
            for p in ports_str.split(','): #vòng lặp để lấy cổng từ chuỗi cổng
                p = p.strip() #Loại bỏ khoảng trắng
                if '-' in p: #nếu có dấu '-' trong p thì lấy cổng từ p
                    # Range: 80-100
                    start, end = map(int, p.split('-')) #lấy cổng từ p
                    ports.extend(range(start, end + 1)) #thêm cổng vào biến ports
                else: #nếu không có dấu '-' trong p thì thêm cổng vào biến ports
                    ports.append(int(p)) #thêm cổng vào biến ports
        except: #nếu có lỗi thì pass
            pass #nếu có lỗi thì pass
        return sorted(set(ports)) #trả về danh sách cổng
    
    def validate_network(self, network_str: str) -> bool: #kiểm tra định dạng mạng
        """Kiểm tra định dạng mạng"""
        try:
            ipaddress.IPv4Network(network_str, strict=False) #kiểm tra định dạng mạng
            return True #trả về True
        except: #nếu có lỗi thì return False
            return False #trả về False
    
    def start_scan(self):
        """Bắt đầu quét"""
        network = self.network_var.get().strip() #lấy khoảng mạng từ biến khoảng mạng
        scan_type = self.scan_type_var.get() #lấy loại quét từ biến loại quét
        ports_str = self.ports_var.get().strip() #lấy cổng từ biến cổng
        
        # Kiểm tra
        if not network: #nếu khoảng mạng không tồn tại thì hiển thị thông báo lỗi
            messagebox.showerror("Lỗi", "Vui lòng nhập khoảng mạng!") #hiển thị thông báo lỗi
            return #thoát khỏi hàm
        
        if not self.validate_network(network): #nếu định dạng mạng không hợp lệ thì hiển thị thông báo lỗi
            messagebox.showerror("Lỗi", "Định dạng mạng không hợp lệ! Ví dụ: 192.168.1.0/24") #hiển thị thông báo lỗi
            return #thoát khỏi hàm
        
        # Tải cài đặt
        self.load_settings() #tải cài đặt từ settings tab
        
        # Phân tích cổng
        ports = [] #khởi tạo biến ports
        if ports_str: #nếu cổng tồn tại thì phân tích cổng
            ports = self.parse_ports(ports_str) #phân tích cổng
        
        # Update UI
        self.scanning = True #trạng thái quét là True
        self.start_btn.config(state=tk.DISABLED) #config cho nút bắt đầu quét
        self.stop_btn.config(state=tk.NORMAL) #config cho nút dừng quét
        self.progress_bar.start(10) #start cho thanh tiến trình
        self.results = [] #khởi tạo biến results
        self.log_status(f"Bắt đầu quét mạng: {network}") #hiển thị thông tin quét mạng
        self.log_status(f"Loại quét: {scan_type}") #hiển thị thông tin loại quét
        self.log_status(f"Cổng: {ports_str if ports else 'Không quét cổng'}") #hiển thị thông tin cổng
        self.log_status("-" * 50) #hiển thị thông tin cách
        
        # Lấy cài đặt quét chi tiết
        deep_scan = False #khơi tạo biến deep_scan
        if self.app.settings_tab: #nếu settings tab tồn tại thì lấy cài đặt quét chi tiết từ settings tab
            deep_scan = self.app.settings_tab.get_deep_scan() #lấy cài đảt quét chi tiết từ settings tab
        
        # Bắt đầu quét trong luồng
        self.scan_thread = threading.Thread( #tạo luồng quét
            target=self._scan_thread, #target cho luồng quét
            args=(network, scan_type, ports, deep_scan), #args cho luồng quét
            daemon=True #daemon cho luồng quét
        )
        self.scan_thread.start() #bắt đầu quét trong luồng
    
    def _scan_thread(self, network: str, scan_type: str, ports: list, deep_scan: bool): #quét mạng trong luồng
        """Thread quét mạng"""
        try:
            start_time = datetime.now()
            
            # Ánh xạ loại quét
            scan_type_map = { #ánh xạ loại quét
                'ICMP (ping)': 'ICMP', #ánh xạ loại quét ICMP
                'TCP': 'TCP', #ánh xạ loại quét TCP
                'ARP': 'ARP', #ánh xạ loại quét ARP
                'Tổng hợp': 'Tổng hợp' #ánh xạ loại quét Tổng hợp
            }
            actual_type = scan_type_map.get(scan_type, 'Tổng hợp') #lấy loại quét từ ánh xạ loại quét
            
            # Cập nhật tiến trình
            self.parent.after(0, self._update_progress, "Đang quét...") #cập nhật tiến trình
            
            # Thực hiện quét
            results = self.scanner.scan_network( #quét mạng
                network=network, #khoảng mạng
                scan_type=actual_type, #loại quét
                ports=ports, #cổng
                deep_scan=deep_scan #quét chi tiết
            )
            
            self.results = results #lấy kết quả quét
            
            # Cập nhật UI
            end_time = datetime.now() #lấy thời gian hiện tại
            duration = (end_time - start_time).total_seconds() #lấy thời gian quét
            
            self.parent.after(0, self._scan_complete, len(results), duration) #cập nhật UI
        
        except Exception as e: #nếu có lỗi thì in ra lỗi
            import traceback #Traceback là báo cáo chi tiết các bước gọi hàm dẫn đến lỗi, giúp bạn xác định chính xác vị trí lỗi trong chương trình.
            error_msg = f"{str(e)}\n{traceback.format_exc()}" #lấy lỗi từ traceback
            self.parent.after(0, self._scan_error, error_msg) #cập nhật UI
    
    def _scan_complete(self, count: int, duration: float): #hoàn thành quét
        """Hoàn thành quét"""
        self.scanning = False #trạng thái quét là False
        self.start_btn.config(state=tk.NORMAL) #config cho nút bắt đầu quét
        self.stop_btn.config(state=tk.DISABLED) #config cho nút dừng quét
        self.progress_bar.stop() #stop cho thanh tiến trình
        
        self.progress_var.set(f"{count}/{count} (100%) • Trạng thái: Đã hoàn thành") #cập nhật tiến trình
        self.log_status(f"\nQuét hoàn thành!") #hiển thị thông tin quét
        self.log_status(f"Phát hiện {count} thiết bị trong {duration:.2f} giây") #hiển thị thông tin quét
        if count > 0: #nếu số thiết bị lớn hơn 0 thì hiển thị thông tin quét
            self.log_status(f"Kết quả đã được cập nhật trong tab 'Kết quả'") #hiển thị thông tin quét
        
        # Cập nhật kết quả
        if self.app.results_tab: #nếu results tab tồn tại thì cập nhật kết quả
            self.app.results_tab.update_results(self.results) #cập nhật kết quả
        
        # Cập nhật trạng thái chân trang
        self.app.update_footer_status(f"Đã phát hiện {count} thiết bị") #cập nhật trạng thái chân trang
    
    def _scan_error(self, error: str): #xử lý lỗi quét
        """Xử lý lỗi quét"""
        self.scanning = False #trạng thái quét là False
        self.start_btn.config(state=tk.NORMAL) #config cho nút bắt đầu quét
        self.stop_btn.config(state=tk.DISABLED) #config cho nút dừng quét
        self.progress_bar.stop() #stop cho thanh tiến trình
        
        self.progress_var.set("0/0 (0%) • Trạng thái: Lỗi") #cập nhật tiến trình
        self.log_status(f"\nLỗi: {error}") #hiển thị thông tin lỗi
        messagebox.showerror("Lỗi", f"Quét mạng thất bại:\n{error}") #hiển thị thông báo lỗi
    
    def stop_scan(self): #dừng quét
        """Dừng quét"""
        if self.scanner: #nếu trình quét tồn tại thì dừng quét
            self.scanner.stop_scan() #dừng quét
        self.scanning = False #trạng thái quét là False
        self.start_btn.config(state=tk.NORMAL) #config cho nút bắt đầu quét
        self.stop_btn.config(state=tk.DISABLED) #config cho nút dừng quét
        self.progress_bar.stop() #stop cho thanh tiến trình
        
        self.progress_var.set("0/0 (0%) • Trạng thái: Đã dừng") #cập nhật tiến trình
        self.log_status("\nĐã dừng quét") #hiển thị thông tin quét
        self.app.update_footer_status("Đã dừng quét") #cập nhật trạng thái chân trang
    
    def log_status(self, message: str): #ghi log vào status text
        """Ghi log vào status text"""
        timestamp = datetime.now().strftime("%H:%M:%S") #lấy thời gian hiện tại
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n") #ghi log vào status text
        self.status_text.see(tk.END) #scroll xuống dưới
    
    def _update_progress(self, status: str): #cập nhật tiến trình
        """Cập nhật progress"""
        self.progress_var.set(f"Đang quét... • Trạng thái: {status}") #cập nhật tiến trình
    
    def get_results(self): #lấy kết quả quét
        """Lấy kết quả quét"""
        return self.results

