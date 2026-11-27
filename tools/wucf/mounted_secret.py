"""Protected operator-mounted lab secret reader; not a vault or API."""
import os
import stat
from dataclasses import dataclass

from execution_plan import validate
from ledger import ContractError, canonical, digest, identifier

MAX_SECRET = 4096


@dataclass(frozen=True)
class Grant:
    environment: str
    instance: str
    revision: str
    reference: str
    generation: str


def grant_for(plan, reference):
    plan = validate(plan)
    return Grant(plan.environment, plan.instance, plan.revision,
                 identifier(reference), plan.credential_generation)


def filename(grant):
    if not isinstance(grant, Grant):
        raise ContractError('invalid credential grant')
    # Scope is part of the filename; no caller-controlled path component.
    return digest(canonical(grant.__dict__)) + '.secret'


class MountedSecret:
    """One exact plan/reference grant; trusted provisioning and protected ancestors.

    Reads an existing owner-only regular file, no write/list/rotation operations.
    Generation is operator-attested, not cryptographic proof of secret contents.
    Secrets exist in process memory; no encryption-at-rest claim. Linux only.
    """
    def __init__(self, directory, plan, reference, owner_uid):
        if type(owner_uid) is not int or owner_uid < 0:
            raise ContractError('invalid credential owner')
        self._grant = grant_for(plan, reference)
        self._owner = owner_uid
        self._directory = os.fspath(directory)
        if not os.path.isabs(self._directory):
            raise ContractError('absolute secret directory required')

    def resolve(self, plan, reference):
        if grant_for(plan, reference) != self._grant:
            raise ContractError('credential grant mismatch')
        directory_fd = file_fd = None
        try:
            directory_fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            directory = os.fstat(directory_fd)
            if directory.st_uid != self._owner or directory.st_mode & 0o077:
                raise ValueError()
            file_fd = os.open(filename(self._grant), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                              dir_fd=directory_fd)
            before = os.fstat(file_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != self._owner
                    or before.st_mode & 0o177 or before.st_nlink != 1
                    or not 1 <= before.st_size <= MAX_SECRET):
                raise ValueError()
            raw = bytearray()
            while len(raw) <= MAX_SECRET:
                chunk = os.read(file_fd, MAX_SECRET + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(file_fd)
            if (len(raw) != before.st_size or len(raw) > MAX_SECRET
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                       (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError()
            value = raw.decode('utf-8', errors='strict')
            if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError()
            return value
        except (OSError, ValueError, UnicodeError):
            raise ContractError('credential unavailable') from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if directory_fd is not None:
                os.close(directory_fd)
