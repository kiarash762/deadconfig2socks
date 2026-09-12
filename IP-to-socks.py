import asyncio
import os
import platform
import re

# ==========================================
# تنظیمات کنترل سرعت (Concurrency)
# ==========================================
PING_SEMAPHORE = asyncio.Semaphore(200)  # تعداد پینگ‌های همزمان برای سرعت بالا
NMAP_SEMAPHORE = asyncio.Semaphore(5)    # تعداد اسکن‌های همزمان Nmap برای جلوگیری از کرش

INPUT_FILE = "ip.txt"
OUTPUT_FILE = "configs.txt"

# ==========================================
# مرحله ۱: پینگ آسنکرون آی‌پی‌ها
# ==========================================
async def ping_ip(ip):
    async with PING_SEMAPHORE:
        # تنظیم پارامترها بر اساس سیستم‌عامل (ویندوز یا لینوکس)
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
        
        command = f"ping {param} 1 {timeout_param} {timeout_val} {ip}"
        proc = await asyncio.create_subprocess_shell(
            command, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        return ip if proc.returncode == 0 else None

# ==========================================
# مرحله ۲: اسکن پورت‌ها با Nmap و حل مشکل انکودینگ ویندوز
# ==========================================
async def scan_ports(ip):
    async with NMAP_SEMAPHORE:
        print(f"[*] Scanning ports for active IP: {ip}...")
        # اسکن ۱۰۰ پورت پرکاربرد به صورت سریع روی آی‌پی فعال
        command = f"nmap -p- --open --min-rate 2000 -oG - {ip}"
        
        proc = await asyncio.create_subprocess_shell(
            command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await proc.communicate()
        
        # حل مشکل انکودینگ‌های مختلف در ترمینال ویندوز
        encodings = ['utf-8', 'utf-16', 'utf-16-le', 'utf-16-be', 'cp1252', 'latin-1', 'cp1256']
        output = None
        
        for enc in encodings:
            try:
                output = stdout.decode(enc)
                break
            except UnicodeDecodeError:
                continue
                
        if output is None:
            output = stdout.decode('latin-1', errors='ignore')
        
        open_ports = []
        # استخراج پورت‌های باز از خروجی فرمت Grepable (-oG) ابزار Nmap
        match = re.search(r"Ports:\s+(.*)", output)
        if match:
            ports_raw = match.group(1)
            for port_info in ports_raw.split(','):
                port_match = re.search(r"(\d+)/open", port_info)
                if port_match:
                    open_ports.append(int(port_match.group(1)))
                    
        if open_ports:
            print(f"[+] Found open ports {open_ports} on IP: {ip}")
        return ip, open_ports

# ==========================================
# بدنه اصلی مدیریت مراحل برنامه
# ==========================================
async def main():
    final_ips = set()
    
    # خواندن آی‌پی‌ها و تمیزکاری ورودی از ip.txt
    if os.path.exists(INPUT_FILE):
        print(f"[*] Reading and cleaning IPs from {INPUT_FILE}...")
        with open(INPUT_FILE, "r", encoding='utf-8', errors='ignore') as f:
            for line in f:
                # استخراج آی‌پی خام و تمیز (حذف پورت‌های چسبیده یا فضاهای خالی اضافه)
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line.strip())
                if ip_match:
                    final_ips.add(ip_match.group(1))
    else:
        print(f"Error: {INPUT_FILE} not found! Please create it in the script directory.")
        return

    ips = list(final_ips)

    if not ips:
        print("Error: No valid IPv4 addresses found in the input file.")
        return

    print(f"[!] Loaded {len(ips)} unique IPs from {INPUT_FILE}.")

    # --- مرحله ۱: پینگ گرفتن موازی ---
    print(f"\n--- Stage 1: Pinging {len(ips)} IPs ---")
    ping_tasks = [ping_ip(ip) for ip in ips]
    ping_results = await asyncio.gather(*ping_tasks)
    active_ips = [ip for ip in ping_results if ip is not None]
    print(f">> Stage 1 Completed. Active IPs: {len(active_ips)}\n")

    if not active_ips:
        print("No active IPs found to scan.")
        return

    # --- مرحله ۲: اسکن پورت‌ها با Nmap ---
    print(f"--- Stage 2: Scanning open ports with Nmap ---")
    scan_tasks = [scan_ports(ip) for ip in active_ips]
    scan_results = await asyncio.gather(*scan_tasks)
    print(">> Stage 2 Completed.\n")

    # --- مرحله ۳: ساخت مستقیم کانفیگ‌ها و ذخیره در فایل خروجی ---
    print(f"--- Stage 3: Generating Socks5 Configs & Saving ---")
    
    configs_written = 0
    with open(OUTPUT_FILE, "w", encoding='utf-8') as out_file:
        for ip, ports in scan_results:
            for port in ports:
                # ساخت کانفیگ ساکس بدون هیچ‌گونه تست اتصالی
                socks_uri = f"socks5://{ip}:{port}"
                out_file.write(socks_uri + "\n")
                configs_written += 1
                print(f"[✓] Generated & Saved: {socks_uri}")

    print(f"\n>> All Stages Finished Successfully!")
    print(f">> Total generated configs saved to '{OUTPUT_FILE}': {configs_written}")
    print("Done")

if __name__ == "__main__":
    # اعمال سیاست Proactor برای ویندوز جهت جلوگیری از خطاهای احتمالی کانکشن
    if platform.system().lower() == 'windows':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main())