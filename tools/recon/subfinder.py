import subprocess

def sub_finder(target):
    try:
        result = subprocess.run(['subfinder', '-d', target, '-silent'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout.splitlines()
        else:
            print(f"Error running subfinder: {result.stderr}")
            return []
    except Exception as e:
        print(f"Exception occurred: {e}")
        return []