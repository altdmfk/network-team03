"""Pagination shared by the dashboard and administrator lists."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Page:
    total: int
    number: int
    size: int = 5

    @classmethod
    def create(cls, total, requested):
        try:
            number = int(requested)
        except (TypeError, ValueError):
            number = 1
        pages = max(1, (total + 4) // 5)
        return cls(total, max(1, min(number, pages)))

    @property
    def pages(self):
        return max(1, (self.total + self.size - 1) // self.size)

    @property
    def offset(self):
        return (self.number - 1) * self.size
