"""demo-lib: small utility helpers."""

def add(a, b):
    """Return the sum of two numbers."""
    return a + b

def greet(name):
    """Return a friendly greeting."""
    return f"hello, {name}"

def slugify(text):
    """Lowercase and hyphenate a short string."""
    return "-".join(text.strip().lower().split())
