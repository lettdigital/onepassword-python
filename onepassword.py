import json
import os
import subprocess
from uuid import uuid4
import re


class DeletionFailure(Exception):
    def __init__(self, item_name, vault):
        message = f"Unable to delete item '{item_name}' from vault '{vault}'"

        super().__init__(message)
        self.message = message


class Unauthorized(Exception):
    pass


class MissingCredentials(Exception):
    pass


class SigninFailure(Exception):
    pass


class UnknownResource(Exception):
    pass


class UnknownResourceItem(Exception):
    pass


class UnknownError(Exception):
    pass


class OnePassword(object):

    def __init__(self, secret=None, token=None, shorthand=None, bin_path=""):
        self.op = os.path.join(bin_path, "op")
        if secret is not None:
            self.shorthand = str(uuid4())
            self.session_token = self.get_access_token(secret, shorthand=self.shorthand)
        elif token is not None and shorthand is not None:
            self.shorthand = shorthand
            self.session_token = token
        else:
            raise MissingCredentials()

    def list(self, resource):
        op_command = f"{self.op} list {resource} --session={self.session_token}"
        try:
            return json.loads(run_op_command_in_shell(op_command))
        except json.decoder.JSONDecodeError:
            raise UnknownResource(resource)

    def create_document_in_vault(self, filename, title, vault):
        op_command = f"{self.op} create document {filename} --title='{title}' --vault='{vault}' --session={self.session_token}"
        return json.loads(run_op_command_in_shell(op_command))

    def delete_item(self, item_name, vault):
        op_command = f"{self.op} delete item {item_name} --vault='{vault}' --session={self.session_token}"
        try:
            run_op_command_in_shell(op_command)
        except subprocess.CalledProcessError:
            raise DeletionFailure(item_name, vault)
        except UnknownError as e:
            error_message = str(e)
            if "multiple items found" in error_message:
                multiple_uuids = []
                rg = re.compile(f"\s*for the item {item_name} in vault {vault}: (.*)")
                for line in error_message.split("\n"):
                    match = rg.match(line)
                    if match:
                        multiple_uuids.append(match.group(1))

                return multiple_uuids
        return "ok"

    def get(self, resource, item_name):
        op_command = f"{self.op} get {resource} '{item_name}' --session={self.session_token}"
        try:
            return run_op_command_in_shell(op_command)
        except subprocess.CalledProcessError:
            raise UnknownResourceItem(f"{resource}: {item_name}")

    def get_access_token(self, secret, shorthand):
        try:
            process = subprocess.run(
                (f"echo '{secret['password']}' | "
                 f"{self.op} signin {secret['signin_address']} {secret['username']} {secret['secret_key']} "
                 f"--output=raw --shorthand={shorthand}"),
                shell=True,
                capture_output=True
            )
            process.check_returncode()
            return process.stdout.decode('UTF-8').strip()
        except subprocess.CalledProcessError as e:
            raise SigninFailure(f"Error signing in: '{process.stderr.decode('UTF-8').strip()}'")

    def get_version(self):
        return run_op_command_in_shell(f"{self.op} --version")


def run_op_command_in_shell(op_command):
    process = subprocess.run(op_command,
                             shell=True,
                             check=False,
                             capture_output=True,
                             env=os.environ)
    try:
        process.check_returncode()
    except subprocess.CalledProcessError:
        error_messages = ["not currently signed in",
                          "Authentication required"]
        full_error_message = process.stderr.decode("UTF-8")
        if any(msg in full_error_message for msg in error_messages):
            raise Unauthorized()
        else:
            raise UnknownError(full_error_message)

    return process.stdout.decode("UTF-8").strip()


