### ⚡ Lightweight High-Performance HTTP Server in Zig with io_uring & OpenSSL  

🚀 **Ultra-Fast HTTP Server Powered by Zig, io_uring & OpenSSL**  

This is a lightweight, high-performance HTTP server written in **Zig**, utilizing **io_uring** for efficient asynchronous I/O and **OpenSSL** for secure HTTPS connections. Designed for extreme performance, it can handle:  

- **70,000 HTTP requests per second**  
- **4,000 HTTPS requests per second**  

### ✨ Features  
✅ **io_uring-based event loop** for low-latency request handling  
✅ **OpenSSL integration** for secure HTTPS support  
✅ **Minimal resource usage** with high throughput  
✅ **Multi-threaded architecture** to maximize CPU core utilization  
✅ **Optimized memory management** for handling large volumes of concurrent connections  
✅ **Static file serving & basic routing** out of the box  

### 🔧 Installation & Setup  
#### 1. Clone the repository  
```sh
git clone  https://github.com/solenopsys/zig-httpuring
cd http-server-io_uring
```
#### 2. Install dependencies  
You'll need **OpenSSL** and **zig-pico** for compilation:  
```sh
git clone https://github.com/solenopsys/zig-pico ../zig-pico
sudo apt install openssl libssl-dev  # For Debian-based systems
```
#### 3. Build & Run  
```sh
zig build run

siege -c10 -r50000  http://0.0.0.0:8080/
```

### 📌 Roadmap  
- Support for WebSocket 
- Performance optimizations for HTTPS  

⚡ **Ideal for high-load applications, embedded systems, and edge computing!**