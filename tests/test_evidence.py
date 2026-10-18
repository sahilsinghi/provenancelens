from __future__ import annotations

import math

import pytest

from provlens import djpeg, pixel
from provlens.evidence import Signal, level, noisy_or

from .conftest import jpg, reopen


def _s(supports, strength, weight):
    return Signal("x", "m", "t", supports, strength, weight, "")


def test_noisy_or_combines_independent_signals():
    sig = [_s("edited", 1.0, 0.5), _s("edited", 0.5, 0.4), _s("generated", 1.0, 0.9), _s("neutral", 1.0, 1.0)]
    assert math.isclose(noisy_or(sig, "edited"), 1 - 0.5 * 0.8)
    assert math.isclose(noisy_or(sig, "generated"), 0.9)
    assert noisy_or(sig, "authentic") == 0.0


def test_noisy_or_never_reaches_certainty():
    assert noisy_or([_s("edited", 1.0, 1.0)] * 3, "edited") < 1.0


@pytest.mark.parametrize("score,expected", [(0.0, "none"), (0.24, "none"), (0.25, "weak"), (0.5, "moderate"),
                                            (0.74, "moderate"), (0.75, "strong")])
def test_levels(score, expected):
    assert level(score) == expected


def test_neutral_signals_contribute_nothing():
    assert _s("neutral", 1.0, 0.9).contribution == 0.0
    assert _s("not_applicable", 1.0, 0.9).contribution == 0.0


def test_double_jpeg_detector_separates_single_and_double(photos):
    names = ("coffee", "rocket", "chelsea", "astronaut")
    single = [djpeg.detect(jpg(photos[n], q)).double for n in names for q in (75, 85, 95)]
    double_up = [djpeg.detect(jpg(reopen(jpg(photos[n], q1)), q2)).double
                 for n in names for q1, q2 in ((60, 90), (70, 95), (65, 85))]
    assert not any(single)
    assert all(double_up)


def test_double_jpeg_blind_spot_is_documented_behaviour(photos):
    """A second save at lower quality is not detected; the report must say so rather than pass it."""
    r = djpeg.detect(jpg(reopen(jpg(photos["coffee"], 92)), 70))
    assert r.applicable and not r.double
    assert "cannot see a second save at *lower* quality" in r.note


def test_double_jpeg_not_applicable_to_png_bytes():
    r = djpeg.detect(b"\x89PNG\r\n\x1a\n")
    assert not r.applicable and not r.double and r.probability is None


def test_pixel_maps_are_quiet_on_a_single_save(photos):
    im = reopen(jpg(photos["coffee"], 90))
    assert pixel.ghosts(im).regions == []
    assert pixel.ela(im).score < 3.5


def test_ghost_map_is_never_blank(photos):
    im = reopen(jpg(photos["coffee"], 90))
    g = pixel.ghosts(im)
    assert g.pixel_map.max() > g.pixel_map.min()


def test_robust_z_has_floor():
    import numpy as np

    z = pixel.robust_z(np.ones((4, 4)), floor=0.1)
    assert np.all(z == 0)
