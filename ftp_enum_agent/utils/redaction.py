def redact_secret(value: str, show_chars: int = 2) -> str:
    """Show first and last `show_chars` chars, mask the rest."""
    if len(value) <= show_chars * 2:
        return "*" * len(value)
    return value[:show_chars] + "*" * (len(value) - show_chars * 2) + value[-show_chars:]
