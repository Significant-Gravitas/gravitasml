"""Pytest configuration for GravitasML tests."""

import os
from hypothesis import settings, Verbosity

# Register Hypothesis profiles for different fuzzing scenarios
settings.register_profile(
    "default",
    max_examples=100,
    verbosity=Verbosity.normal,
)

settings.register_profile(
    "fuzzing",
    max_examples=int(os.environ.get("HYPOTHESIS_MAX_EXAMPLES", "1000")),
    verbosity=Verbosity.normal,
    deadline=None,  # Disable deadline for fuzzing
)

settings.register_profile(
    "ci",
    max_examples=1000,
    verbosity=Verbosity.verbose,
    deadline=None,
)

# Load the default profile
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))