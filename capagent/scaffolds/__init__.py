"""Synthetic agent scaffolds used as extraction targets.

Each module is ordinary Python source containing (a) tool *wrapper* functions whose
bodies use recognizable high-impact APIs (os.remove, requests.post, subprocess.run,
apply_patch, ...), and (b) one or more ``plan_*`` functions that a scaffold executor
would run.  ``contract-extractor`` and ``guard-extractor`` read the wrappers/guards;
``acg-builder`` reads the plan control-flow.  The scaffolds are never imported/executed
by the analyzer -- they are parsed with ``ast``.
"""
