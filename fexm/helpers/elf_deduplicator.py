import uuid

import hashlib
import os


class ElfDeDuplicator:
    """
    This function takes a path to a self of elf binaries
    and returns a list of unique binaries. Two binaries
    are also considered duplicates, if one elf binary is the stripped version of another elf binary.
    """

    @staticmethod
    def md5(fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def calculate_stripped_md5_hash(elf_path):
        from sh import strip
        tmp_elf_path = os.path.join("/tmp", str(uuid.uuid4()))
        strip([elf_path, "-o", tmp_elf_path])
        return ElfDeDuplicator.md5(tmp_elf_path)

    @staticmethod
    def is_binary_stripped(elf_path):
        from sh import file
        result = file(elf_path)
        if "not stripped" in result:
            return False
        else:
            return True

    @staticmethod
    def deduplicate_binaries(elf_binary_list):
        """
        :param elf_binary_list: The list of elf binaries
        """
        rhashdict = {}  # Key: md5hash of stripped version, value list of binaries where the stripped version has this md5has
        result_list = []
        for e in elf_binary_list:
            stripped_elf_md5_hash = ElfDeDuplicator.calculate_stripped_md5_hash(e)
            if rhashdict.get(stripped_elf_md5_hash):
                rhashdict[stripped_elf_md5_hash].append(e)
            else:
                rhashdict[stripped_elf_md5_hash] = [e]
        for md5_hash, binary_list in rhashdict.items():
            if len(binary_list) == 1:
                result_list.append(binary_list[0])
            elif len(binary_list) > 1:
                for b in binary_list:
                    if not ElfDeDuplicator.is_binary_stripped(b):
                        result_list.append(b)
                        continue
        return result_list
