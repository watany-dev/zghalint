"""Hypothesis custom strategies for zghalint PBT."""
from hypothesis import strategies as st

# Arbitrary byte sequences (0-1KB)
random_bytes = st.binary(min_size=0, max_size=1024)

# Random UTF-8 text (including newlines)
random_text = st.text(min_size=0, max_size=500)

# YAML structural fragments mixed with random text
_yaml_fragments = [
    "name: CI",
    "on: push",
    "on: [push, pull_request]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    '      - run: echo "hello"',
    "    env:",
    "      KEY: value",
    "- item",
    "key: value",
    "# comment",
    "${{ github.event.issue.title }}",
    "'single quoted'",
    '"double quoted"',
    "null",
    "true",
    "42",
    "|",
    ">",
    "---",
    "...",
    "    ",
    "",
]

yaml_like_text = st.lists(
    st.sampled_from(_yaml_fragments) | st.text(max_size=50),
    min_size=1,
    max_size=20,
).map("\n".join)

# Text without newlines (for embedding inside a YAML run: line)
expression_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        blacklist_characters="\n\r",
    ),
    min_size=0,
    max_size=200,
)
