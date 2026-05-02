def within_file_limit(size_bytes: int, max_bytes: float) -> bool:
    return size_bytes <= max_bytes


def mb_to_bytes(mb: float) -> int:
    return int(mb * 1024 * 1024)
