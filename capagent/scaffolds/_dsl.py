"""Minimal decorators / helpers so scaffolds are valid, lint-clean Python.

The analyzer never executes scaffolds; it parses their source.  These no-op
definitions exist only so the modules import cleanly and read like real framework
code.  Decorators supply *contract evidence* the extractor can read (e.g. a tool
annotated ``@declassifies`` is a label-clearing transform).
"""
from __future__ import annotations


def tool(name=None, effect=None, resource_arg=None, dest_arg=None):
    def deco(fn):
        fn._tool = name or fn.__name__
        fn._effect = effect
        fn._resource_arg = resource_arg
        fn._dest_arg = dest_arg
        return fn
    return deco


def reads(private=False):
    def deco(fn):
        fn._reads_private = private
        return fn
    return deco


def transform(fn):
    fn._transform = True
    return fn


def declassifies(fn):
    fn._declassifies = True
    return fn


def provenance_check(fn):
    fn._provenance_check = True
    return fn


# -- plan-side helpers (recognized by acg-builder) -------------------------
def require(kind, region=None, labels=None, provs=None):
    """A guard/policy interaction that grants a capability (paper: require)."""
    return {"kind": kind, "region": region or [], "labels": labels, "provs": provs}


def memread(key, untrusted=False):
    return None


def memwrite(key, value, untrusted=False):
    return None
