import sys
from ..controllers.main_controller import run_analysis, analyze_url

def print_report(report):
    print("\n=== Phishing Email Analysis Report ===\n")

    if report['headers']:
        print("\033[1;31mSuspicious Headers Detected:\033[0m")
        for flag in report['headers']:
            print(f" - {flag}")
    else:
        print("\033[1;32mNo suspicious headers detected.\033[0m")

    if report['links']:
        print("\n\033[1;31mSuspicious Links Detected:\033[0m")
        for flag in report['links']:
            print(f" - {flag}")
    else:
        print("\n\033[1;32mNo suspicious links detected.\033[0m")

    if report['content']:
        print("\n\033[1;31mSuspicious Content Detected:\033[0m")
        for flag in report['content']:
            print(f" - {flag}")
    else:
        print("\n\033[1;32mNo suspicious content detected.\033[0m")

    print(f"\n\033[1;36mOverall Score: {report['score']}\033[0m")
    print(f"\033[1;35mVerdict: {report['verdict']}\033[0m")
    print("\n=== Analysis Complete ===")

def display_menu():
    print("\033[1;31m")
    print(r"""
    ██████╗  ██╗  ██╗ ██╗ ███████╗ ██╗  ██████╗ ██╗  ██╗
    ██╔══██╗ ██║  ██║ ██║ ██╔════╝ ██║ ██╔════╝ ██║ ██╔╝
    ██████╔╝ ███████║ ██║ █████╗   ██║ ██║      █████╔╝ 
    ██╔═══╝  ██╔══██║ ██║ ██╔══╝   ██║ ██║      ██╔═██╗ 
    ██║      ██║  ██║ ██║ ██║      ██║ ╚██████╗ ██║  ██╗
    ╚═╝      ╚═╝  ╚═╝ ╚═╝ ╚═╝      ╚═╝  ╚═════╝ ╚═╝  ╚═╝
    """)
    print("\033[1;33m          P H I S H I N G   D E T E C T I O N   T O O L\033[0m\n")
    print("\033[1;36m" + "="*60 + "\033[0m")
    print("\033[0m")  # Reset color
    print("\033[1;32mBuilt by Sasekani Maluleke - Technical Cybersecurity\033[0m\n")

    print("\033[1;36m" + "="*60 + "\033[0m")  # Bright cyan separator
    print("\033[1;34mCHOOSE AN OPTION:\033[0m".center(60))
    print("\033[1;36m" + "="*60 + "\033[0m")
    print("\033[1m1. Analyze Email Content\033[0m")
    print("\033[1m2. Analyze a URL\033[0m")
    print("\033[1m3. Analyze Email from File\033[0m")
    print("\033[1m4. Exit\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

def main():
    while True:
        display_menu()
        choice = input("\nEnter your choice (1 - 4): ").strip()

        if choice == '1':
            print("\nPaste the full email content below. Press Enter twice to finish:")
            lines = []
            while True:
                try:
                    line = input()
                    if line == '':
                        if len(lines) >= 1 and lines[-1] == '':
                            break
                    lines.append(line)
                except KeyboardInterrupt:
                    print("\nInput interrupted.")
                    return
            email_content = '\n'.join(lines)
            report = run_analysis(email_content)
            print_report(report)

        elif choice == '2':
            url = input("\nEnter the URL to check: ").strip()
            print("\n=== URL Analysis Report ===\n")
            results = analyze_url(url)
            if results['flags']:
                for flag in results['flags']:
                    print(f" - {flag}")
                print(f"\nScore: {results['score']}")
                print(f"Verdict: {results['verdict']}")
            else:
                print("\033[1;32mNo suspicious indicators found in the URL.\033[0m")

        elif choice == '3':
            filename = input("\nEnter file path: ").strip()
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    email_content = f.read()
                report = run_analysis(email_content)
                print_report(report)
            except Exception as e:
                print(f"Error reading file: {str(e)}")

        elif choice == '4':
            print("Exiting. Stay safe!")
            break

        else:
            print("Invalid choice. Please try again.")
