

def display_banner():
    print("\033[1;31m")
    print("██████╗ ██╗  ██╗██╗███████╗██╗ ██████╗██╗  ██╗")
    print("██╔══██╗██║  ██║██║██╔════╝██║██╔════╝██║ ██╔╝")
    print("██████╔╝███████║██║█████╗  ██║██║     █████╔╝ ")
    print("██╔═══╝ ██╔══██║██║██╔══╝  ██║██║     ██╔═██╗ ")
    print("██║     ██║  ██║██║██║     ██║╚██████╗██║  ██╗")
    print("╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝")
    print("             PHISHING DETECTION TOOL")
    print("\033[0m")
    print("Built by Sasekani Maluleke  |  Cybersecurity Analyst\n")

def get_user_choice():
    print("Choose an option:")
    print("1. Analyze Email Content")
    print("2. Analyze a URL")
    print("3. Exit")
    return input("Enter 1, 2, or 3: ").strip()

def get_email_input():
    print("\nPaste the full email content below. Press Enter twice to finish:")
    lines = []
    while True:
        try:
            line = input()
            if line == '':
                break
            lines.append(line)
        except KeyboardInterrupt:
            print("\nInput interrupted.")
            return ''
    return '\n'.join(lines)

def get_url_input():
    return input("Enter the URL to check: ").strip()

def show_email_analysis_report(header_flags, link_flags, content_flags):
    print("\n=== Phishing Email Analysis Report ===\n")

    if header_flags:
        print("\033[91mSuspicious Headers Detected:\033[0m")
        for flag in header_flags:
            print(f" - {flag}")
    else:
        print("\033[92mNo suspicious headers detected.\033[0m")

    if link_flags:
        print("\n\033[91mSuspicious Links Detected:\033[0m")
        for flag in link_flags:
            print(f" - {flag}")
    else:
        print("\n\033[92mNo suspicious links detected.\033[0m")

    if content_flags:
        print("\n\033[91mSuspicious Content Detected:\033[0m")
        for flag in content_flags:
            print(f" - {flag}")
    else:
        print("\n\033[92mNo suspicious content detected.\033[0m")

    print("\n=== Analysis Complete ===")

def show_url_analysis_report(results):
    print("\n=== URL Analysis Report ===\n")
    if results:
        print("\033[91mSuspicious URL Indicators Detected:\033[0m")
        for flag in results:
            print(f" - {flag}")
    else:
        print("\033[92mNo suspicious indicators found in the URL.\033[0m")
