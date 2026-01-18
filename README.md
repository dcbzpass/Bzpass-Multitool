# ⚡ Bzpass Multitool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-win)
![License](https://img.shields.io/badge/License-MIT-green)

**Bzpass Multitool** is a powerful, terminal-based multitool designed for power users, gamers, and system administrators. It combines deep system analytics with aggressive performance tuning, offering a streamlined interface to manage hardware, network, and Windows internals without the bloat of GUI applications.

---

## 🚀 Key Features

### 🖥️ 1. Advanced System Intelligence
Get a granular view of your hardware environment beyond what Task Manager offers.
- **Deep Hardware Scan**: Retrives real CPU model names, Motherboard vendor/version/product, and GPU details.
- **Real-time Metrics**: Monitors precise CPU frequency and physical vs. logical core counts.
- **Memory Analytics**: Exact total/available RAM calculation.

### 🌐 2. Network Speed Scanner
Integrated speed testing without a browser.
- **Latency Analysis**: Measures ping to the nearest optimal server.
- **Bandwidth Test**: Accurate Download and Upload speed metrics (Mbps).
- **Server Metadata**: Identifies server sponsor and location.

### 🛡️ 3. Process & Security Monitor
A "clean" task manager focused on identifying user-space resource hogs.
- **Smart Filtering**: Automatically hides standard Windows system processes (svchost, dwm, etc.) to focus on *your* apps.
- **Impact Analysis**: Color-coded "Impact" rating (High/Moderate/Low) based on CPU/Memory weight.
- **User Sorting**: Prioritizes processes owned by the current user.

### 🔍 4. Deep File Search
A lightweight alternative to "Everything" that lives in your terminal.
- **Recursive Crawling**: Scans the entire C:\ drive for specific file extensions or names.
- **Fast Matching**: Skips system directories (WinSxS) for speed.
- **Size Reporting**: Displays file sizes for every match found.

### ⚡ 5. Windows Optimization Engine
Aggressive tweaking suite for gamers and performance enthusiasts.
- **Visual FX Tuner**: Disables animations, shadows, and unnecessary UI candy for maximum FPS.
- **Privacy Hardening**: Disables Telemetry, Cortana, Bing Search, and "Soft Landing" ads.
- **Bloat Removal**: Disables maintenance tasks and scheduled background bloatware.
- **Registry Tweaks**: Applies 50+ registry keys for input latency reduction and gaming prioritization.
- **System Cleaner**: One-click temp file and cache purging.

---

## 📦 Installation

### Prerequisites
- Windows 10 or Windows 11
- Python 3.8 or higher

### Setup
1. **Clone the repository:**
   ```bash
   git clone https://github.com/dcbzpass/Bzpass-Multitool.git
   cd Bzpass-Multitool
   ```

2. **Install dependencies:**
   The tool relies on `psutil`, `colorama`, and `speedtest-cli`.
   ```bash
   pip install -r requirements.txt
   ```
   *Or manually:*
   ```bash
   pip install psutil colorama speedtest-cli
   ```

3. **Run the tool:**
   **Note:** Must be run as Administrator to apply Registry tweaks and access system details.
   ```bash
   python main.py
   ```

---

## 🎮 Usage

Upon launching, you will be greeted by the dashboard:

```text
┌──[ DASHBOARD ]──────────────────────────────────────────────────┐
│ 1. System Intelligence    [Hardware/BIOS/Deep Scan]             │
│ 2. WiFi Speed Scan        [Test Servers: DE/UK/US]              │
│ 3. Process Monitor        [Clean List/Memory Sort]              │
│ 4. File Search            ['Everything' Style Search]           │
│ 5. Windows Tweaks         [Optimizations/Cleaner]               │
│ 6. Exit                   [Logout]                              │
└─────────────────────────────────────────────────────────────────┘
```

**Navigation:**
- Type the number of the module you wish to use and press `Enter`.
- For **Windows Tweaks**, select the specific category (Win10 vs Win11) to apply targeted registry patches.

---

## ⚠️ Disclaimer

**Use with caution.** This tool makes significant changes to the Windows Registry and System Services to improve performance. While these tweaks are generally safe for gaming systems:
1.  **Always create a System Restore Point** before applying the "Windows Tweaks".
2.  The "System Cleaner" permanently deletes temporary files.
3.  The developers are not responsible for any system instability or data loss resulting from the misuse of this tool.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
