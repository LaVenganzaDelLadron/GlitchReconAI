import os

from view.recon import start_subfinder


def banner():
    os.system('figlet -c -f slant "GlitchReconAI" | lolcat')
    os.system('figlet -c -f term "Reconnaissance Automation Tool               v.1.0" | lolcat')

def exit():
    os.system('figlet -c -f slant "Goodbye!" | lolcat')
    os.system('figlet -c -f term "Thank you for using GlitchReconAI!" | lolcat')
    quit()

def menu():
    while True:
        print("[1] Create Project")
        print("[2] Project List")
        print("[3] Exit")
    
        try:
            choose = int(input("\n[+] Choose an option: "))

            if choose == 1:
                startProject()
            elif choose == 2:
                print("\n[+] Project List:")
            elif choose == 3:
                exit()
            else:
                print("\n[+] Invalid option. Please try again.\n")
                menu()
        except ValueError:
            print("\n[+] Invalid input. Please enter a number.\n")
            menu()
        except KeyboardInterrupt:
            print("\n\n[+] Exiting...\n")
            exit()


def agentMenu():
    while True:
        print("\n=== AGENT MODULES ===\n")
        print("[1] Reconnaissance")
        print("[2] Intelligence Gathering")
        print("[3] Scanning Enumuration")
        print("[4] Web Application Testing")

        try:
            choose = int(input("\n[+] Choose an option: "))

            if choose == 1:
                print("\n[+] Starting Reconnaissance module...\n")
                start_subfinder()
            elif choose == 2:
                print("\n[+] Starting Intelligence Gathering module...\n")
            elif choose == 3:
                print("\n[+] Starting Scanning Enumuration module...\n")
            elif choose == 4:
                print("\n[+] Starting Web Application Testing module...\n")
            else:
                print("\n[+] Invalid option. Please try again.\n")
                agentMenu()
        except ValueError:
            print("\n[+] Invalid input. Please enter a number.\n")
            agentMenu()
        except KeyboardInterrupt:
            print("\n\n[+] Exiting...\n")
            exit()


def startProject():
    print("\n[+] Starting GlitchReconAI...\n")
    agentMenu()
    




