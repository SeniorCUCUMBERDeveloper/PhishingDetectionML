#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from epi_fields import _EPI_FIELDS

_RUNTIME_EPI_FIELDS = _EPI_FIELDS + ("urls", "attachments")
