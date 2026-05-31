from core.executor import run_tool

def run_subfinder(
    target,
    mode="single",
    use_all_sources=False
):
    return run_tool(
        "subfinder",
        target,
        options={
            "mode": mode,
            "use_all_sources": use_all_sources
        }
    )
