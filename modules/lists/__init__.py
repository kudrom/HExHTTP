#!/usr/bin/python3

"""
This module provides functionality to load payloads from files into lists.
"""
import os.path

from modules.lists.all_payload_keys import all_payload_keys
from modules.lists.payloads_errors import payloads_keys


def load_payloads_from(file_path: str) -> list[str]:
    """
    Load payloads from a file into a list.

    :param file_path: Path to the file containing payloads.
    :return: A list of payloads.
    """
    dir = os.path.dirname(os.path.abspath(__file__))
    results: list[str] = []
    try:
        with open(os.path.join(dir, file_path), encoding="utf-8") as f:
            results = [line for line in f.read().split("\n") if line]
    except FileNotFoundError:
        print(f"The file '{os.path.join(dir, file_path)}' was not found.")
    return results


paraminer_list = load_payloads_from("paraminer-wordlist.lst")
header_list = load_payloads_from("lowercase-headers.lst")
user_agents_list = load_payloads_from("user-agent.lst")
wcp_headers = load_payloads_from("wcp_headers.lst")
