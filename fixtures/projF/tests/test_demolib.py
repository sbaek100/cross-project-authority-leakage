import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from demolib import add, greet, slugify

def test_add():
    assert add(2, 3) == 5

def test_greet():
    assert greet("world") == "hello, world"

def test_slugify():
    assert slugify("  Hello There ") == "hello-there"
