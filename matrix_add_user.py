#!/usr/bin/env python3

import argparse
import sys

from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import re
import requests
from types import SimpleNamespace

TYPE_ERROR_FIELD_EXTRACT_RE = r"[^']+'([^']+)'.*"

reg_path = "/_synapse/admin/v1/register"


@dataclass
class User:
    username: str
    displayname: str
    password: str
    admin: bool
    user_type: str = None


def get_nonce(uri):
    nonce_json = requests.get(uri).json()
    return nonce_json["nonce"]


def generate_mac(user: User, nonce: str):
    mac = hmac.new(
      key=shared_secret,
      digestmod=hashlib.sha1,
    )

    mac.update(nonce.encode('utf8'))
    mac.update(b"\x00")
    mac.update(user.username.encode('utf8'))
    mac.update(b"\x00")
    mac.update(user.password.encode('utf8'))
    mac.update(b"\x00")
    mac.update(b"admin" if user.admin else b"notadmin")
    if user.user_type:
        mac.update(b"\x00")
        mac.update(user.user_type.encode('utf8'))

    return mac.hexdigest()


def register(user: User, nonce: str, mac: str, uri: str):
    reg_payload = {
       "username": user.username,
       "displayname": user.displayname,
       "password": user.password,
       "admin": user.admin,
       "nonce": nonce,
       "mac": mac
    }
    return requests.post(uri, json=reg_payload)


def parse_arguments():
    arg_parser = argparse.ArgumentParser(
            prog="matrix_user_add",
            description="Add a user to Matrix servier using admin API",
            epilog=":)")
    arg_parser.add_argument("filename")
    arg_parser.add_argument('-H', '--host', required=True)
    return arg_parser.parse_args()


def parse_user_file(filename: str) -> str | None:
    """parses a JSON file with user fields. Error handling
    is brittle - trying to translate string messages"""
    with open(filename, "r") as user_file:
        try:
            user_data = json.load(user_file, object_hook=lambda d: User(**d))
        except TypeError as e:
            field_name = re.match(TYPE_ERROR_FIELD_EXTRACT_RE, e.args[0]).group(1)
            if field_name:
                err = "unknown field: "
            else:
                err = ""
            logging.error(f"ERROR parsing user file: {err}{field_name}")
            return None
        except json.decoder.JSONDecodeError:
            logging.error("ERROR parsing user file: invalid JSON")
            return None


    return user_data
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    args = parse_arguments()    

    user_file_name = args.filename
    host = args.host

    reg_uri = f"https://{host}{reg_path}"
    
    shared_secret = input("shared secret: ")
    shared_secret = bytes(shared_secret, "utf-8")

    user_data = parse_user_file(user_file_name)
    if user_data is None:
        exit(1)
    
    nonce = get_nonce(reg_uri)
    logging.debug(f"got nonce: {nonce}")
    mac = generate_mac(user_data, nonce)
    logging.debug(f"got MAC: {mac}")
    reg_res = register(user_data, nonce, mac, reg_uri)
    logging.info(f"registration response:\n{reg_res.text}")

