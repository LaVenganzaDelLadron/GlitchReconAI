from core.dashboard import Dashboard, set_dashboard
from view import start as view_start


def main() -> None:
    set_dashboard(Dashboard())
    view_start.banner()
    view_start.menu()


if __name__ == "__main__":
    main()
