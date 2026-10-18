"""ProvenanceLens: an explainable media authenticity verifier.

Answers two questions about an image with evidence, never with a bare
"fake / real": where did it come from (C2PA content credentials, declared
metadata), and has it been changed (metadata consistency, quantisation-table
fingerprints, double-JPEG statistics, error-level and noise analysis).
Every signal reports what it found, how much weight it carries and why.
"""

__version__ = "0.1.0"
