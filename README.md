# SQL Injection Scanner (Timebased)

## Overview
This is a **SQL Injection (SQLi) vulnerability scanner** written in **Go**. It automates the detection of SQL injection vulnerabilities by testing URL parameters and paths with **time-based payloads** for multiple database management systems (DBMS).

## Features
- Supports **multiple databases** (MySQL, MSSQL, PostgreSQL, Oracle, SQLite, SAP HANA, Generic SQL)
- Uses **time-based SQL injection payloads** to detect vulnerabilities
- Scans **both URL paths and query parameters**
- **Concurrent scanning** with adjustable concurrency
- **Verbose logging** option
- Supports **saving results to a file**

## Installation
Make sure you have Go installed, then clone this repository:

```sh
$ git clone https://github.com/vijay922/SQL-Injection-Scanner.git
$ cd SQL-Injection-Scanner
$ go build timesqli.go -o sqli-scanner
```

## Usage
Run the scanner by passing URLs via standard input:

```sh
$ cat urls.txt | ./sqli-scanner [-v] [-o output.txt]
```

### Options:
- `-v` : Enable verbose mode (shows request details)
- `-o <filename>` : Save detected vulnerabilities to a file

## How It Works
### 1. Payloads
The scanner uses **predefined SQL injection payloads** that introduce **time delays** in SQL queries. If a response takes longer than expected, the URL is considered potentially vulnerable.

Supported databases and their respective payloads:
```go
payloads = []Payload{
    {"MySQL", "' AND SLEEP(5) -- ", 5 * time.Second},
    {"MSSQL", "'; WAITFOR DELAY '0:0:5' -- ", 5 * time.Second},
    {"PostgreSQL", "'; SELECT pg_sleep(5) -- ", 5 * time.Second},
    {"Oracle", "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5) -- ", 5 * time.Second},
    {"SQLite", "' OR randomblob(1000000000) -- ", 5 * time.Second},
}
```

### 2. URL Processing
- The scanner reads **URLs from stdin**
- It modifies the **URL path and query parameters** by appending SQL injection payloads
- Each modified URL is sent as an HTTP GET request

### 3. Response Time Analysis
- If the response time is **90% or more** of the expected delay, it reports a possible SQL injection vulnerability.

## Example Output
If a vulnerable URL is found, it prints:
```sh
[+] Potential MySQL SQLi at http://example.com/product?id=1' AND SLEEP(5) --  (response time: 5.02s)
```

In verbose mode (`-v`), it also prints details of each request and response time.

## Notes:
```
This script is for educational and authorized testing purposes only.

Always ensure you have explicit permission to test the target systems.

The script may need further customization depending on the target environment and WAF configurations.
```
<h2 id="donate" align="center">⚡️ Support</h2>

<details>
<summary>☕ Buy Me A Coffee</summary>

<p align="center">
  <a href="https://buymeacoffee.com/vijay922">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black"/>
  </a>
</p>

</details>

<p align="center">
  <b><i>"Keep pushing forward. Never surrender."</i></b>
</p>

<p align="center">🌱</p>

## Author
[chippa vijay kumar](https://github.com/vijay922)

## License
This project is open-source under the MIT License. Contributions are welcome!

