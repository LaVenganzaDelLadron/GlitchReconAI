from core.executor import run_tool

NUCLEI_TIMEOUT_SECONDS = 400

def run_nuclei(target: str) -> str:
    return run_tool("nuclei", target, options={"timeout": NUCLEI_TIMEOUT_SECONDS})
