"""
Модуль валидации сетевых индикаторов.

Включает в себя:
- Валидация IPv4-адреса
- Нормализация IPv4/IPv6
- Валидация MAC-адреса (с нормализацией форматов)
- Валидация номера порта (диапазон 1-65535)
"""

import re
from ipaddress import IPv4Address, IPv6Address


class ValidationError(Exception):
    """Исключение для ошибок валидации входных данных."""


# ---------------------------------------------------------------------------
# IPv4 валидация
# ---------------------------------------------------------------------------
IPV4_PATTERN = re.compile(
    r"""^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$""",
    re.VERBOSE,
)


def validate_ipv4(address: str) -> str | None:
    """
    Валидирует и нормализует IPv4-адрес.

    Args:
        address: Строка с IP-адресом.

    Returns:
        Нормализованный IPv4-адрес (например, '192.168.001.001' -> '192.168.1.1')

    Raises:
        ValidationError: Если адрес невалидный.
    """
    if not address:
        raise ValidationError("IPv4-адрес не может быть пустым")

    normalized = address.strip()

    # Проверяем, что формат соответствует IPv4-паттерну
    if not IPV4_PATTERN.match(normalized):
        raise ValidationError(f"Некорректный IPv4-адрес: {address}")

    # Нормализация (убираем ведущие нули)
    try:
        ip_obj = IPv4Address(normalized)
        return str(ip_obj)
    except ValueError as exc:
        raise ValidationError(f"Некорректный IPv4-адрес: {address}") from exc


def is_valid_ipv4(address: str) -> bool:
    """Быстрая проверка IPv4 без выброса исключений."""
    try:
        validate_ipv4(address)
        return True
    except ValidationError:
        return False


# ---------------------------------------------------------------------------
# IPv6 валидация (задел на будущее)
# ---------------------------------------------------------------------------
def validate_ipv6(address: str) -> str | None:
    """
    Валидирует и нормализует IPv6-адрес.

    Args:
        address: Строка с IPv6-адресом.

    Returns:
        Сжатая нормализованная IPv6-строка (по RFC 5952).

    Raises:
        ValidationError: Если адрес невалидный.
    """
    if not address:
        raise ValidationError("IPv6-адрес не может быть пустым")

    try:
        ip_obj = IPv6Address(address.strip())
        # RFC 5952 нормализация
        return ip_obj.compressed
    except ValueError as exc:
        raise ValidationError(f"Некорректный IPv6-адрес: {address}") from exc


def is_valid_ipv6(address: str) -> bool:
    """Быстрая проверка IPv6 без выброса исключений."""
    try:
        validate_ipv6(address)
        return True
    except ValidationError:
        return False


# ---------------------------------------------------------------------------
# MAC-адрес валидация
# ---------------------------------------------------------------------------
# Поддерживаемые форматы:
#   aa:bb:cc:dd:ee:ff  (с двоеточиями)
#   aa-bb-cc-dd-ee-ff  (с дефисами)
#   aabb.ccdd.eeff     (Cisco-формат, три группы по 4 hex-символа)
MAC_OCTET = r"(?:[0-9a-fA-F]{2})"
MAC_PATTERNS = [
    re.compile(rf"^{MAC_OCTET}:{MAC_OCTET}:{MAC_OCTET}:{MAC_OCTET}:{MAC_OCTET}:{MAC_OCTET}$"),  # colon
    re.compile(rf"^{MAC_OCTET}-{MAC_OCTET}-{MAC_OCTET}-{MAC_OCTET}-{MAC_OCTET}-{MAC_OCTET}$"),  # hyphen
    re.compile(rf"^{MAC_OCTET}{MAC_OCTET}\.{MAC_OCTET}{MAC_OCTET}\.{MAC_OCTET}{MAC_OCTET}$"),  # Cisco
]

MAC_TO_COLON = str.maketrans(".-", "::")


def validate_mac_address(mac: str) -> str | None:
    """
    Валидирует и нормализует MAC-адрес.

    Возвращает нормализованный MAC в формате 'aa:bb:cc:dd:ee:ff' (нижний регистр).

    Args:
        mac: Строка с MAC-адресом.

    Returns:
        Нормализованный MAC-адрес.

    Raises:
        ValidationError: Если адрес невалидный.
    """
    if not mac:
        raise ValidationError("MAC-адрес не может быть пустым")

    normalized = mac.strip().lower()

    for pattern in MAC_PATTERNS:
        if pattern.match(normalized):
            return normalized

    raise ValidationError(f"Некорректный MAC-адрес: {mac}")


def is_valid_mac_address(mac: str) -> bool:
    """Быстрая проверка MAC-адреса без выброса исключений."""
    try:
        validate_mac_address(mac)
        return True
    except ValidationError:
        return False


# ---------------------------------------------------------------------------
# Порт валидация
# ---------------------------------------------------------------------------
def validate_port(port: str) -> int | None:
    """
    Валидирует номер порта (1-65535).

    Args:
        port: Строка с номером порта.

    Returns:
        Корректный номер порта (int).

    Raises:
        ValidationError: Если порт вне диапазона.
    """
    if not port:
        raise ValidationError("Номер порта не может быть пустым")

    try:
        port_int = int(port.strip())
    except ValueError as exc:
        raise ValidationError(f"Номер порта должен быть числом: {port}") from exc

    if not (1 <= port_int <= 65535):
        raise ValidationError(f"Номер порта должен быть в диапазоне 1-65535: {port}")

    return port_int


def is_valid_port(port: str) -> bool:
    """Быстрая проверка номера порта без выброса исключений."""
    try:
        validate_port(port)
        return True
    except ValidationError:
        return False


# ---------------------------------------------------------------------------
# Пакетная проверка
# ---------------------------------------------------------------------------
def validate_batch(items: list, validator: str) -> list:
    """
    Пакетно валидирует список значений с указанным типом валидатора.

    Args:
        items: Список строк для проверки.
        validator: Тип валидатора ('ipv4', 'ipv6', 'mac', 'port').

    Returns:
        Список валидных нормализованных значений.

    Raises:
        ValidationError: При первой неудачной валидации.
    """
    validators_map = {
        "ipv4": validate_ipv4,
        "ipv6": validate_ipv6,
        "mac": validate_mac_address,
        "port": validate_port,
    }

    if validator not in validators_map:
        raise ValueError(f"Неизвестный тип валидатора: {validator}")

    validator_func = validators_map[validator]
    result = []

    for item in items:
        normalized = validator_func(item)
        result.append(normalized)

    return result
