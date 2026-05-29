from core.agent import katana_agent, subfinder_agent, waybackurls_agent


def start_recon():
    print("\n=== RECONNAISSANCE MODULE ===\n")

    print("[1] Subfinder")
    print("[2] Katana")
    print("[3] Waybackurls")

    choice = input("Enter choice (1/2/3): ").strip()

    if choice == "1":
        start_subfinder()
    elif choice == "2":
        start_katana()
    elif choice == "3":
        start_waybackurls()
    else:
        print("Invalid choice. Please select 1, 2, or 3.")


def start_subfinder():

    print("\n=== SUBFINDER MODULE ===\n")

    print("[1] Single Target")
    print("[2] List of Targets")
    print("[3] All Sources")

    choice = input("Enter choice (1/2/3): ").strip()

    if choice == "1":
        target = input("[+] Enter target domain: ").strip()
        subfinder_agent(target, mode="single")

    elif choice == "2":
        target = input("[+] Enter target list file path: ").strip()
        subfinder_agent(target, mode="list")

    elif choice == "3":
        target = input("[+] Enter target domain: ").strip()
        subfinder_agent(target, mode="single", use_all_sources=True)

    else:
        print("Invalid choice. Please select 1, 2, or 3.")


def start_katana():
    print("\n=== KATANA MODULE ===\n")

    target = input("[+] Enter authorized target URL/domain: ").strip()
    katana_agent(target)


def start_waybackurls():
    print("\n=== WAYBACKURLS MODULE ===\n")

    target = input("[+] Enter authorized target URL/domain: ").strip()
    waybackurls_agent(target)
