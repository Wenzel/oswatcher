# 1st
from dataclasses import dataclass
from pathlib import Path
import hashlib

# 3rd
import lief
from see import Hook
from .filesystem import Inode
from signify.fingerprinter import AuthenticodeFingerprinter
import asn1


global_catFileName = ''


@dataclass
class checkPE:
    dynamicBase: bool
    noSEH: bool
    guardCF: bool
    forceIntegrity: bool
    nxCompat: bool
    highEntropyVA: bool
    codeSize: str
    numFunctionsExported: int
    imageSize: str
    hasEmbeddedSig: bool
    hasCatSig: bool
    catFileName: str
    importedLibs: list


class StaticAnalyzerHook(Hook):

    VALID_MIME_APP = ['application/x-dosexec']

    def __init__(self, parameters):
        super().__init__(parameters)
        self.catalogs = self.configuration.get('catalogs', False)
        # subscribe on "filesystem_new_file" events
        self.context.subscribe("filesystem_new_file", self.handle_new_file)

    def formatSize(self, size, precision=2):
        suffix = ['B', 'KB', 'MB', 'GB']
        suffixIndex = 0

        if size == 0:
            return "0"
        else:
            while size > 1024 and suffixIndex < 3:
                suffixIndex += 1
                size = size/1024.0

        return "%.*f%s" % (precision, size, suffix[suffixIndex])

    def search_cat(self, input_stream, sha1Hash, sha256Hash, spcIndirectFound):
        while not input_stream.eof():
            tag = input_stream.peek()
            if tag.typ == asn1.Types.Primitive:
                tag, value = input_stream.read()
                if tag.nr == asn1.Numbers.ObjectIdentifier:
                    if value == '1.3.6.1.4.1.311.2.1.4':
                        spcIndirectFound = 1
                elif tag.nr == asn1.Numbers.OctetString:
                    if spcIndirectFound == 1:
                        spcIndirectFound = 0
                        imageHash = value.hex().upper()
                        if (imageHash == sha256Hash or imageHash == sha1Hash):
                            return True
            elif tag.typ == asn1.Types.Constructed:
                input_stream.enter()
                catalogFound = self.search_cat(
                    input_stream, sha1Hash, sha256Hash, spcIndirectFound
                )
                if catalogFound:
                    input_stream.leave()
                    return True
                input_stream.leave()
        return False

    def has_catSignature(self, gfs, folder, pe_inode, sha1Hash, sha256Hash):
        if gfs.is_dir(folder):
            for entry in gfs.ls(folder):
                path_entry = folder + '/' + entry
                if gfs.is_dir(path_entry):
                    hasCatSig = self.has_catSignature(
                        gfs, path_entry, pe_inode, sha1Hash, sha256Hash
                    )
                    if hasCatSig:
                        return True
                else:
                    cat_inode = Inode(gfs, Path(path_entry))
                    cat_file_obj = open(cat_inode.local_file, "rb")
                    cat_data = cat_file_obj.read()
                    decoder = asn1.Decoder()
                    decoder.start(cat_data)
                    catalogFound = self.search_cat(
                        decoder, sha1Hash, sha256Hash, 0
                    )
                    if catalogFound:
                        global global_catFileName
                        global_catFileName = entry
                        cat_file_obj.close()
                        return True
                    cat_file_obj.close()
            return False
        return False

    def handle_new_file(self, event):
        # get inode parameter
        inode = event.inode
        gfs = event.gfs

        # get mime type
        mime_type = inode.mime_type

        if mime_type in self.VALID_MIME_APP:
            local_path = inode.local_file
            pe = lief.parse(local_path)

            # extraction of relevant DLL characteristics
            dynamicBase = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
                )
            noSEH = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.NO_SEH
                )
            guardCF = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.GUARD_CF
                )
            forceIntegrity = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.FORCE_INTEGRITY
                )
            nxCompat = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.NX_COMPAT
                )
            highEntropyVA = pe.optional_header.has(
                lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA
                )

            # Authenticode checks (embedded and detached signatures)
            hasEmbeddedSig = pe.has_signature

            if self.catalogs:
                hasCatSig = False
                global global_catFileName
                if not hasEmbeddedSig:
                    pe_file_obj = open(local_path, "rb")
                    fingerprinter = AuthenticodeFingerprinter(pe_file_obj)
                    fingerprinter.add_authenticode_hashers(
                        hashlib.sha1, hashlib.sha256
                    )
                    hashes = (fingerprinter.hashes()).get('authentihash')
                    sha1Hash = hashes.get('sha1').hex().upper()
                    sha256Hash = hashes.get('sha256').hex().upper()
                    hasCatSig = self.has_catSignature(
                        gfs, '/Windows/System32/CatRoot', inode,
                        sha1Hash, sha256Hash
                    )
                    pe_file_obj.close()
            else:
                hasCatSig = None
                global global_catFileName
                global_catFileName = None

            # image implementation characteristics
            codeSize = self.formatSize(pe.optional_header.sizeof_code)
            imageSize = self.formatSize(pe.optional_header.sizeof_image)
            numFunctionsExported = len(pe.exported_functions)
            importedLibs = []
            for importedLib in pe.imports:
                importedLibs.append(importedLib.name)
            check_pe = checkPE(dynamicBase, noSEH, guardCF, forceIntegrity,
                               nxCompat, highEntropyVA, codeSize,
                               numFunctionsExported, imageSize,
                               hasEmbeddedSig, hasCatSig,
                               global_catFileName, importedLibs)
            print(check_pe)
