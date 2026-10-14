"""Cooperative worker shutdown at transaction and transport boundaries."""
from threading import Event

_stopping = Event()


class WorkerShutdown(BaseException):
    """Leave the loop without turning an intentional stop into a retry failure."""


def request_shutdown():
    _stopping.set()


def reset_shutdown():
    _stopping.clear()


def shutdown_requested():
    return _stopping.is_set()


def check_shutdown():
    if _stopping.is_set():
        raise WorkerShutdown()
