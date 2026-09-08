"""Allow running ichnos as a module: python -m ichnos."""

from ichnos.cli.main import app_entry

if __name__ == "__main__":
    app_entry()
