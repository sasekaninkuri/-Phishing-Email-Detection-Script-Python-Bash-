from models.analyzer import analyze_headers, analyze_links, analyze_content
from views.console_view import display_banner, get_user_choice, get_email_input, get_url_input, show_email_analysis_report, show_url_analysis_report
import sys

def run_analysis():
    display_banner()
    choice = get_user_choice()

    if choice == '1':
        email_content = get_email_input()

        headers = ''
        headers_end = email_content.find('\n\n')
        if headers_end != -1:
            headers = email_content[:headers_end]
        else:
            headers = email_content

        header_flags = analyze_headers(headers)
        link_flags = analyze_links(email_content)
        content_flags = analyze_content(email_content)

        show_email_analysis_report(header_flags, link_flags, content_flags)

    elif choice == '2':
        url = get_url_input()
        results = analyze_links(url)
        show_url_analysis_report(results)

    elif choice == '3':
        print("Exiting... Goodbye!")
        sys.exit(0)

    else:
        print("\033[91mInvalid option. Please enter 1, 2, or 3.\033[0m")

