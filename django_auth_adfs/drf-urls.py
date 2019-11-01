# flake8: noqa
import warnings
from .drf_urls import *

warnings.warn(
    "drf-urls.py is not a valid module name and will be "
    "removed in a future version, use drf_urls.py instead",
    PendingDeprecationWarning
)
