from core.agent import subfinder_agent

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
