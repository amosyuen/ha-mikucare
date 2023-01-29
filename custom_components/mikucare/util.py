"""Miku Care Utils"""


def snake_case_to_title_space(str):
    return " ".join([w.title() for w in str.split("_")])
