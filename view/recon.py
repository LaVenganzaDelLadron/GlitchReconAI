from core.agent import (
    assetfinder_agent,
    gau_agent,
    httpx_agent,
    katana_agent,
    subfinder_agent,
    waybackurls_agent,
)


def start_recon():
    print("\n=== RECONNAISSANCE MODULE ===\n")

    print("[1] Subfinder")
    print("[2] Katana")
    print("[3] Waybackurls")
    print("[4] Assetfinder")
    print("[5] GAU")
    print("[6] httpx")

    choice = input("Enter choice (1/2/3/4/5/6): ").strip()

    if choice == "1":
        start_subfinder()
    elif choice == "2":
        start_katana()
    elif choice == "3":
        start_waybackurls()
    elif choice == "4":
        start_assetfinder()
    elif choice == "5":
        start_gau()
    elif choice == "6":
        start_httpx()
    else:
        print("Invalid choice. Please select 1, 2, 3, 4, 5, or 6.")


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


def start_assetfinder():
    print("\n=== ASSETFINDER MODULE ===\n")

    target = input("[+] Enter authorized target domain: ").strip()
    assetfinder_agent(target)


def start_gau():
    print("\n=== GAU MODULE ===\n")

    target = input("[+] Enter authorized target domain: ").strip()
    gau_agent(target)


def start_httpx():
    print("\n=== HTTPX MODULE ===\n")

    targets_file = input("[+] Enter target list file path: ").strip()
    httpx_agent(targets_file)
