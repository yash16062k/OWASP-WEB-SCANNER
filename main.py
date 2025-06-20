# main.py

from scanner.core import run_scanner
from scanner.report import generate_report

if __name__ == "__main__":
    target_url = input("Enter target URL (e.g. https://example.com): ").strip()

    print(f"\n🔍 Scanning {target_url}...\n")
    results = run_scanner(target_url)

    print("\n📄 Generating report...\n")
    generate_report(target_url, results)

    print("✅ Scan complete. Check /results for your report.")
