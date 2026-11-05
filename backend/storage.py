from pathlib import Path
import os
import shutil

BACKEND_DIR = Path(__file__).resolve().parent

DATA_DIR = Path(
    os.environ.get(
        "RECONSUITE_DATA_DIR",
        str(Path.home() / ".local" / "share" / "reconsuite-lite")
    )
).expanduser().resolve()

DATA_DIR.mkdir(parents=True, exist_ok=True)


def get_database_path(filename):
    destination = DATA_DIR / filename
    source = BACKEND_DIR / filename

    # Migrate an existing database only if the destination does not exist.
    if not destination.exists() and source.exists():
        shutil.copy2(source, destination)

    return destination
