import os
import ctypes
import multiprocessing

def _netns_get_fd(name):
    if name == "":
        return open('/proc/self/ns/net', 'r')
    return open(f'/var/run/netns/{name}', 'r')

def netns_set(name:str):
    name = name.strip()
    ns_fd = _netns_get_fd(name)
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    if libc.setns(ns_fd.fileno(), 0) != 0:
        raise OSError(ctypes.get_errno(), f"Error setting network namespace to {name}")
