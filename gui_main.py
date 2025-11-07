"""
Main GUI Application
Giao diện chính với 4 tabs
"""
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional
import sys
import os

# Import các tab modules
try:
    from scan_tab import ScanTab #thêm tab quét mạng từ scan_tab.py vào
    from results_tab import ResultsTab #thêm tab kết quả từ results_tab.py vào
    from analysis_tab import AnalysisTab #thêm tab phân tích từ analysis_tab.py vào
    from settings_tab import SettingsTab #thêm tab cài đặt từ settings_tab.py vào
except ImportError as e: #nếu không thể import các tab thì in ra lỗi
    print(f"Import error: {e}") #in ra lỗi
    messagebox.showerror("Error", f"Failed to import modules: {e}") #hiển thị lỗi
    sys.exit(1) #thoát khỏi ứng dụng

class NetworkScannerApp: #tạo ứng dụng
    def __init__(self, root): #khởi tạo ứng dụng
        self.root = root #cửa sổ chính
        self.root.title("Network Scanner - Khám phá mạng") #tiêu đề của cửa sổ
        self.root.geometry("1200x800") #kích thước của cửa sổ
        self.root.minsize(1000, 600) #kích thước tối thiểu của cửa sổ
        
        # Set icon
        self.set_icon() #đặt icon cho cửa sổ
        
        # Cấu hình style
        self.setup_styles() #cấu hình màu sắc cho giao diện
        
        # Tạo header
        self.create_header() #tạo thanh tiêu đề cho giao diện
        
        # Tạo notebook (tabs)
        self.notebook = ttk.Notebook(self.root) #tạo notebook cho giao diện
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5) #đặt notebook vào giao diện
        
        # Khởi tạo các tab
        self.scan_tab = None #tab quét mạng
        self.results_tab = None #tab kết quả
        self.analysis_tab = None #tab phân tích
        self.settings_tab = None #tab cài đặt
        
        self.create_tabs() #tạo các tab cho giao diện
        
        # Tạo footer
        self.create_footer() #tạo chân trangtrang cho giao diện
        
        # Bind events
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change) #sự kiện chuyển tab
    
    def set_icon(self):
        """Thiết lập icon cho cửa sổ"""
        icon_paths = ["icon.ico", #đường dẫn của icon
                     os.path.join(os.path.dirname(__file__), "icon.ico")] #đường dẫn của icon
        
        for path in icon_paths: #vòng lặp để tải icon
            if os.path.exists(path): #nếu đường dẫn của icon tồn tại thì tải icon
                try:
                    self.root.iconbitmap(path) #đặt icon cho cửa sổ
                    break #thoát khỏi vòng lặp
                except Exception as e: #nếu không tải được icon thì in ra lỗi
                    print(f"Không thể tải icon: {e}") #in ra lỗi nếu không tải được icon
    
    def setup_styles(self): #cấu hình style cho giao diện
        """Thiết lập style cho giao diện"""
        style = ttk.Style() #tạo style cho giao diện
        
        # Sử dụng theme hiện đại
        try: #nếu sử dụng được theme vista thì sử dụng theme vista
            style.theme_use('vista') #sử dụng theme vista (vista: hiện đại, clam: cũ, xpnative: cũ, default: cũ,...)
        except: #nếu không sử dụng được theme vista thì pass
            pass
        
        # Cấu hình màu sắc tươi sáng
        style.configure('Header.TLabel', #cấu hình màu sắc cho thanh tiêu đề
                       font=('Segoe UI', 166, 'bold'), #font cho thanh tiêu đề
                       background="#2c503a", #màu nền cho thanh tiêu đề
                       foreground='white') #màu sắc cho thanh tiêu đề
        
        style.configure('Title.TLabel', #cấu hình màu sắc cho tiêu đề
                       font=('Segoe UI', 15, 'bold'), #font cho tiêu đề
                       foreground='#34495e') #màu sắc cho tiêu đề
        
        style.configure('Status.TLabel', #cấu hình màu sắc cho trạng thái
                       font=('Segoe UI', 11), #font cho trạng thái
                       foreground='#7f8c8d') #màu sắc cho trạng thái
        
        style.configure('Accent.TButton', #cấu hình màu sắc cho nút
                       font=('Segoe UI', 11, 'bold')) #font cho nút
        
        # Cấu hình Treeview
        style.configure('Treeview', #cấu hình màu sắc cho treeview
                       font=('Segoe UI', 11), #font cho treeview
                       rowheight=25) #chiều cao của hàng
        
        style.configure('Treeview.Heading', #cấu hình màu sắc cho tiêu đề của treeview
                       font=('Segoe UI', 11, 'bold')) #font cho tiêu đề của treeview
    
    def create_header(self): #tạo thanh tiêu đề cho giao diện
        """Tạo header với logo và toolbar"""
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=60) #tạo khung cho thanh tiêu đề (màu nền: xám, màu chữ: trắng)
        header_frame.pack(fill=tk.X, padx=0, pady=0) #đặt khung cho thanh tiêu đề
        header_frame.pack_propagate(False) #không cho khung phát triển
        
        # Logo và tên app
        logo_frame = tk.Frame(header_frame, bg="#0b9a4b") #tạo khung cho logo
        logo_frame.pack(side=tk.LEFT, padx=15, pady=10) #đặt khung cho logo
        
        title_label = tk.Label(logo_frame, #tạo label cho logo
                              text="🔍 Network Scanner", #text cho logo
                              font=('Segoe UI', 24, 'bold'), #font cho logo
                              bg='#2c3e50', #màu nền cho logo
                              fg='white') #màu sắc cho logo
        title_label.pack() #đặt label cho logo
        
        # Toolbar buttons
        toolbar_frame = tk.Frame(header_frame, bg='#2c3e50') #tạo khung cho thanh công cụ
        toolbar_frame.pack(side=tk.RIGHT, padx=15, pady=10) #đặt khung cho thanh công cụ
        
        settings_btn = tk.Button(toolbar_frame,
                                text="⚙️ Settings", #text cho nút cài đặt
                                bg='#000ff0', #màu nền cho nút cài đặt
                                fg='white', #màu sắc cho nút cài đặt
                                font=('Segoe UI', 12), #font cho nút cài đặt
                                relief=tk.SUNKEN, #kiểu cho nút cài đặt
                                padx=10, #khoảng cách bên ngoài cho nút cài đặt
                                pady=5, #khoảng cách bên trong cho nút cài đặt
                                cursor='hand2', #con trỏ chuột khi di chuột vào nút cài đặt
                                command=self.show_settings) #sự kiện khi nhấn nút cài đặt
        settings_btn.pack(side=tk.RIGHT, padx=5) #đặt nút cài đặt vào khung
        
        help_btn = tk.Button(toolbar_frame, #tạo nút trợ giúp
                            text="❓ Help", #text cho nút trợ giúp
                            bg='#ff000f', #màu nền cho nút trợ giúp
                            fg='white', #màu sắc cho nút trợ giúp
                            font=('Segoe UI', 12), #font cho nút trợ giúp
                            relief=tk.SUNKEN, #kiểu cho nút trợ giúp
                            padx=10, #khoảng cách bên ngoài cho nút trợ giúp
                            pady=5, #khoảng cách bên trong cho nút trợ giúp
                            cursor='hand2', #con trỏ chuột khi di chuột vào nút trợ giúp
                            command=self.show_help) #sự kiện khi nhấn nút trợ giúp
        help_btn.pack(side=tk.RIGHT, padx=5) #đặt nút trợ giúp vào khung
    
    def create_tabs(self): #tạo các tab cho giao diện
        """Tạo các tab"""
        # Tab 1: Quét mạng
        scan_frame = ttk.Frame(self.notebook) #tạo khung cho tab quét mạng
        self.notebook.add(scan_frame, text="📡 Quét mạng") #đặt tab quét mạng vào notebook
        self.scan_tab = ScanTab(scan_frame, self) #tạo tab quét mạng
        
        # Tab 2: Kết quả
        results_frame = ttk.Frame(self.notebook) #tạo khung cho tab kết quả
        self.notebook.add(results_frame, text="📊 Kết quả") #đặt tab kết quả vào notebook
        self.results_tab = ResultsTab(results_frame, self) #tạo tab kết quả
        
        # Tab 3: Phân tích
        analysis_frame = ttk.Frame(self.notebook) #tạo khung cho tab phân tích
        self.notebook.add(analysis_frame, text="🔬 Phân tích") #Đặt tab phân tích vào notebook
        self.analysis_tab = AnalysisTab(analysis_frame, self) #tạo tab phân tích
        
        # Tab 4: Cài đặt
        settings_frame = ttk.Frame(self.notebook) #tạo khung cho tab cài đặt
        self.notebook.add(settings_frame, text="⚙️ Cài đặt") #Đặt tab cài đặt vào notebook
        self.settings_tab = SettingsTab(settings_frame, self) #tạo tab cài đặt
    
    def create_footer(self): #tạo chân trang cho giao diện
        """Tạo footer với thông tin trạng thái"""
        footer_frame = tk.Frame(self.root, bg='#ecf0f1', height=30) #tạo khung cho chân trang
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM) #đặt khung cho chân trang
        footer_frame.pack_propagate(False) #không cho khung tự mở rộng
        
        status_label = tk.Label(footer_frame, #tạo label cho chân trang
                                text="Sẵn sàng | Version 1.0.0", #text cho chân trang
                                font=('Segoe UI', 10), #font cho chân trang
                                bg='#ecf0f1', #màu nền cho chân trang
                                fg='#7f8c8d') #màu sắc cho chân trang
        status_label.pack(side=tk.LEFT, padx=10, pady=5) #đặt chân trang vào khung
        
        self.footer_status = status_label #lưu label cho chân trang
    
    def update_footer_status(self, text: str): #cập nhật trạng thái chân trang
        """Cập nhật trạng thái footer"""
        if hasattr(self, 'footer_status'): #nếu có label cho chân trang thì cập nhật trạng thái chân trang
            current_text = self.footer_status.cget('text') #lấy text cho chân trang
            version = current_text.split('|')[-1] if '|' in current_text else "Version 1.0.0" #lấy version cho chân trang
            self.footer_status.config(text=f"{text} | {version}") #cập nhật text cho chân trang
    
    def on_tab_change(self, event): #xử lý sự kiện chuyển tab
        """Xử lý sự kiện chuyển tab"""
        selected = self.notebook.index(self.notebook.select()) #lấy index của tab được chọn
        
        if selected == 1:  # Tab kết quả
            if self.results_tab: #nếu có tab kết quả thì cập nhật table
                self.results_tab.refresh_table() #cập nhật table
        elif selected == 2:  # Tab phân tích
            if self.analysis_tab: #nếu có tab phân tích thì cập nhật data
                self.analysis_tab.refresh_data() #cập nhật data
    
    def show_settings(self): #hiển thị tab cài đặt
        """Hiển thị tab cài đặt"""
        self.notebook.select(3) #chuyển sang tab cài đặt
    
    def show_help(self): #hiển thị hướng dẫn
        """Hiển thị hướng dẫn"""
        help_text = """
Network Scanner - Hướng dẫn sử dụng

Tab 1 - Quét mạng:
• Nhập dải mạng (ví dụ: 192.168.1.0/24)
• Chọn loại quét: ARP, ICMP, TCP, hoặc Tổng hợp
• Nhập cổng cần quét (phân tách bằng dấu phẩy)
• Nhấn "Bắt đầu quét" để bắt đầu

Tab 2 - Kết quả:
• Xem danh sách thiết bị đã phát hiện
• Sử dụng bộ lọc và tìm kiếm
• Xuất kết quả ra CSV hoặc JSON
• Click chuột phải để xem menu ngữ cảnh

Tab 3 - Phân tích:
• Phân tích chi tiết kết quả quét
• Xem thông tin
 + OS
 + Dịch vụ
 + Cổng
 + Vendor (hãng sản xuất thiết bị)
 + Raw XML
 + Cảnh báo lỗ hổng (lỗ hổng cổng mở)

Tab 4 - Cài đặt:
• Cấu hình thời gian timeout
• Điều chỉnh số luồng
• Cấu hình tốc độ quét Nmap
• Cấu hình màu sắc Treeview
        """
        messagebox.showinfo("Hướng dẫn", help_text) #hiển thị hướng dẫn
    
    def get_results(self): #lấy kết quả từ tab quét mạng
        """Lấy kết quả từ scan tab"""
        if self.scan_tab: #nếu có tab quét mạng thì lấy kết quả từ tab quét mạng
            return self.scan_tab.get_results() #lấy kết quả từ tab quét mạng
        return [] #trả về danh sách rỗng nếu không có tab quét mạng

def main(): #chạy ứng dụng
    root = tk.Tk() #tạo cửa sổ
    app = NetworkScannerApp(root) #tạo ứng dụng
    root.mainloop() #chạy ứng dụng

if __name__ == "__main__":
    main() #chạy ứng dụng

