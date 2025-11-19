#!/usr/bin/env python

import os

def get_shared_secret():
    return os.getenv("SHARED_SECRET", "htb-ctf")