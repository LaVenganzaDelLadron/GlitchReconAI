import os
from core.agent import scan_target


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

def startProject():
    print("\n[+] Starting GlitchReconAI...\n")
    print("============Create Penetration Testing Project============")
    target = input("\n[+] Enter the target domain: ")
    scan_target(target)

    




