# Тесты для SmartPCAPParser

import os
import tempfile
from pathlib import Path

# Тесты пишут настройки в свою временную папку: настоящий файл пользователя
# не читается и не меняется, и прогон не зависит от его истории и темы.
os.environ.setdefault(
    "SMARTPCAP_SETTINGS",
    str(Path(tempfile.mkdtemp(prefix="smartpcap_tests_")) / "settings.json"),
)
