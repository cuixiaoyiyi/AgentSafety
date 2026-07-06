"""Milestone 5: real-repository evaluation.

Replaces the synthetic scaffolds with pinned real agent frameworks.  Two things are
automatable at repository scale and are run here:

  * contract / guard / high-impact-**sink inventory** extraction (RQ2), and
  * replay of manually-curated security witnesses that are *grounded* in real sink
    locations discovered by the scanner (RQ1/RQ3), as prescribed by the plan's
    Milestones 2 + 5.

Building a fully faithful Action-Capability Graph for an arbitrary framework's agent
loop needs per-framework adapters and is out of scope for this prototype; that
boundary is reported honestly rather than papered over.
"""
