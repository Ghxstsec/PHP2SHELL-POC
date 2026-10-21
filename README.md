<p align="center">
  <pre>
██████╗  ██╗  ██╗██████╗  ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗ ██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝ ███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
██╔═══╝  ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
██║      ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝      ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
  </pre>
</p>

<p align="center">
  <b>PHP Session Upload Progress Remote Code Execution Exploit (CVE-2026-109618)</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Exploit-RCE-red.svg" alt="Type">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

---

## 📝 About the Vulnerability (CVE-2026-109618)

**CVE-2026-109618** is a critical memory corruption and logic vulnerability in the PHP engine related to file upload progress tracking via sessions (`session.upload_progress`).

The flaw lies in how the external pointer `post_bytes_processed` is cached during the first phase of the request (`FILE_START`) and fails to properly refresh in subsequent upload events. By combining a race condition, the destructive release of Hash trees (`HashTable.pDestructor = zval_ptr_dtor`), and a controlled heap spray using padded structures (`t[]` packed natural tables), it is possible to overwrite internal engine function pointers (such as `zend_call_function`) to redirect execution flow to `system()` with arbitrary commands.

---

## ⚙️ Requirements & Installation

The tool requires the **`rich`** library for rendering the console interface, banners, and interactive panels.

1. Clone the repository:
```
git clone [https://github.com/Ghxstsec/php2shell-poc.git](https://github.com/Ghxstsec/php2shell-poc.git)
cd php2shell-poc
```
Install the required dependencies
```
pip install -r requirements.txt
```
(Or simply: pip install rich)

🚀 Usage & Examples

Run the script with the appropriate parameters for the targeted system:

```
python3 php2shell.py -u "[https://target-domain.com/path/index.php](https://target-domain.com/path/index.php)" -c "uname -a; id"
```

Command Line Options
Parameter	Description	Default Value
-u, --url	Full URL of the vulnerable PHP endpoint	Required
-c, --command	Command to execute on the operating system	uname -a; id; echo JACKALPOC
--sid	Custom session identifier (PHPSESSID)	a1b2c3d4e5f6a7b8c9d0e1f2a3
--stall	Stall duration in seconds	1.35
--dtor	Leaked memory address of zval_ptr_dtor (hex/int)	0
--call	Explicit memory address for zend_call_function	Calculated via offset
--dry	Simulation mode: generates and saves the binary payload to disk	False
🛠️ Technical Details

    Heap Spraying: Utilizes a block of 149 elements (packed natural table with 320-byte bins) to ensure the reuse of the freed memory block.

    SAPI Support: Designed for environments evaluated under CGI/FastCGI architectures and compatible front-end servers (such as LiteSpeed LSAPI / Apache / Nginx).

    Dry Run: Allows dumping the exact byte stream of the generated multipart payload for forensic analysis or debugging using the --dry flag.

🛠️ Technical Details

    Affected Versions: PHP 5.4 up to PHP 8.x (Patches released by PHP maintainers for 8.2, 8.3, 8.4, and 8.5).

    Heap Spraying: Utilizes a block of 149 elements (packed natural table with 320-byte bins) to ensure the reuse of the freed memory block.

    SAPI Support: Designed for environments evaluated under CGI/FastCGI architectures and compatible front-end servers (such as LiteSpeed LSAPI / Apache / Nginx).

    Dry Run: Allows dumping the exact byte stream of the generated multipart payload for forensic analysis or debugging using the --dry flag.

📦 requirements.txt File
```
rich>=13.0.0
urllib3>=1.26.0
```

⚠️ Legal Notice (Disclaimer)

This software has been created exclusively for educational purposes, security research, and authorized auditing use (Pentesting).The author (Ghxstsec) assumes no responsibility for misuse or damage caused by the improper use of this script on unauthorized systems.
