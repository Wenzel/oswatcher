# std
import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# third party
import lief
from see import Hook, Event
from signify.fingerprinter import AuthenticodeFingerprinter

# local
from .filesystem import GuestFSWrapper
from oswatcher.utils import asn1
from oswatcher.utils.asn1 import Decoder
from oswatcher.model import InodeType


@dataclass
class PEChecksec:
    dynamic_base: bool
    no_seh: bool
    guard_cf: bool
    force_integrity: bool
    nx_compat: bool
    high_entropy_va: bool
    num_functions_exported: int
    has_embedded_sig: bool
    has_cat_sig: bool
    cat_filename: str
    imported_libs: list


class StaticAnalyzerHook(Hook):

    VALID_MIME_APP = ['application/x-dosexec']
    CATROOT_PATH = '/Windows/System32/CatRoot'

    def __init__(self, parameters):
        super().__init__(parameters)
        self.catFileName = ''
        self.catalogs = self.configuration.get('catalogs', False)
        self.keep_binaries = self.configuration.get('keep_failed_binaries', False)
        self.neo4j_enabled = self.configuration.get('neo4j', False)
        self.os_node = None
        if self.neo4j_enabled:
            self.os_node = self.configuration['neo4j']['OS']
        # directory to dump executable on which checksec failed
        if self.neo4j_enabled:
            os_id = self.os_node.id
        else:
            os_id = self.context.domain.name()
        default_checksec_failed_dir = Path.cwd() / f"{os_id}_static_analyzer_failed"
        self.keep_binaries_dir = self.configuration.get('keep_failed_dir', default_checksec_failed_dir)
        # subscribe on "filesystem_new_file" events
        self.context.subscribe("filesystem_new_file", self.handle_new_file)

    def search_cat(self, input_stream: Decoder, sha1_hash: str, sha256_hash: str, spc_indirect_found: int) -> bool:
        while not input_stream.eof():
            tag = input_stream.peek()
            if tag.typ == asn1.Types.Primitive:
                tag, value = input_stream.read()
                if tag.nr == asn1.Numbers.ObjectIdentifier:
                    if value == '1.3.6.1.4.1.311.2.1.4':
                        spc_indirect_found = 1
                elif tag.nr == asn1.Numbers.OctetString:
                    if spc_indirect_found == 1:
                        spc_indirect_found = 0
                        image_hash = value.hex().upper()
                        if image_hash == sha256_hash or image_hash == sha1_hash:
                            return True
            elif tag.typ == asn1.Types.Constructed:
                input_stream.enter()
                catalog_found = self.search_cat(
                    input_stream, sha1_hash, sha256_hash, spc_indirect_found)
                if catalog_found:
                    input_stream.leave()
                    return True
                input_stream.leave()
        return False

    def has_cat_signature(self, gfs_wrapper: GuestFSWrapper, filepath: str, sha1_hash: str, sha256_hash: str)\
            -> (bool, Optional[str]):
        for cat_inode in gfs_wrapper.walk_inodes(Path(filepath)):
            if cat_inode.exists and cat_inode.inode_type == InodeType.REG:
                self.logger.debug("Checking for cat signature on %s", cat_inode.path)
                with open(cat_inode.local_file, "rb") as cat_file_obj:
                    cat_data = cat_file_obj.read()
                    decoder = asn1.Decoder()
                    decoder.start(cat_data)
                    catalog_found = self.search_cat(decoder, sha1_hash, sha256_hash, 0)
                    self.logger.debug("Catalog found: %s", catalog_found)
                    if catalog_found:
                        return True, cat_inode.str_path
        return False, None

    def handle_new_file(self, event: Event) -> None:
        # get inode parameter
        inode = event.inode
        gfs_wrapper = event.gfs_wrapper

        # get mime type
        mime_type = inode.py_magic_type

        if mime_type in self.VALID_MIME_APP:
            local_path = inode.local_file
            pe = lief.parse(local_path)
            if not pe:
                self.logger.warning("LIEF failed to parse %s", inode.path)
                if self.keep_binaries:
                    self.keep_binaries_dir.mkdir(parents=True, exist_ok=True)
                    dst = self.keep_binaries_dir / inode.name
                    self.logger.warning("Dumping as %s", dst)
                    shutil.copy(inode.local_file, dst)
                return

            # extraction of relevant DLL characteristics
            dynamic_base = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
            no_seh = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.NO_SEH)
            guard_cf = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.GUARD_CF)
            force_integrity = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.FORCE_INTEGRITY)
            nx_compat = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.NX_COMPAT)
            high_entropy_va = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA)

            # Authenticode checks (embedded and detached signatures)
            has_embedded_sig = pe.has_signature

            cat_filepath = None
            has_cat_sig = None
            if self.catalogs:
                if not has_embedded_sig:
                    with open(local_path, "rb") as pe_file_obj:
                        fingerprinter = AuthenticodeFingerprinter(pe_file_obj)
                        fingerprinter.add_authenticode_hashers(
                            hashlib.sha1, hashlib.sha256)
                        hashes = (fingerprinter.hashes()).get('authentihash')
                        sha1_hash = hashes.get('sha1').hex().upper()
                        sha256_hash = hashes.get('sha256').hex().upper()
                        has_cat_sig, cat_filepath = self.has_cat_signature(
                            gfs_wrapper, self.CATROOT_PATH,
                            sha1_hash, sha256_hash)

            # image implementation characteristics
            num_functions_exported = len(pe.exported_functions)
            imported_libs = []
            for importedLib in pe.imports:
                imported_libs.append(importedLib.name)
            check_pe = PEChecksec(dynamic_base, no_seh, guard_cf, force_integrity,
                                  nx_compat, high_entropy_va,
                                  num_functions_exported,
                                  has_embedded_sig, has_cat_sig,
                                  cat_filepath, imported_libs)
            self.logger.info(check_pe)
