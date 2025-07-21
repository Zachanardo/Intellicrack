import pytest

class TestBasic:
    def test_math(self):
        assert 2 + 2 == 4
        
    def test_string(self):
        assert "test".upper() == "TEST"