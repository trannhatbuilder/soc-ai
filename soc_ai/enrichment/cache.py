import json
import time
from pathlib import Path
from typing import Any, Dict, Optional


class JsonCache:
    def __init__(self, cache_file: str = ".cache/abuseipdb_cache.json", ttl_seconds: int = 86400):
        self.cache_file = Path(cache_file)
        self.ttl_seconds = ttl_seconds
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

        if not self.cache_file.exists():
            self._write_cache({})

    def _read_cache(self) -> Dict[str, Any]:
        try:
            with self.cache_file.open("r", encoding="utf-8") as file:
                return json.load(file)
        except json.JSONDecodeError:
            return {}
        except FileNotFoundError:
            return {}

    def _write_cache(self, data: Dict[str, Any]) -> None:
        with self.cache_file.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        cache_data = self._read_cache()

        if key not in cache_data:
            return None

        entry = cache_data[key]
        cached_at = entry.get("cached_at")
        value = entry.get("value")

        if cached_at is None or value is None:
            return None

        current_time = int(time.time())
        age = current_time - int(cached_at)

        if age > self.ttl_seconds:
            return None

        return value

    def set(self, key: str, value: Dict[str, Any]) -> None:
        cache_data = self._read_cache()

        cache_data[key] = {
            "cached_at": int(time.time()),
            "value": value,
        }

        self._write_cache(cache_data)

    def delete(self, key: str) -> None:
        cache_data = self._read_cache()

        if key in cache_data:
            del cache_data[key]
            self._write_cache(cache_data)

    def clear(self) -> None:
        self._write_cache({})