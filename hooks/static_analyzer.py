# 1st
from dataclasses import dataclass

# 3rd
from see import Hook
import lief


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
    importedLibs: list


class StaticAnalyzerHook(Hook):

    VALID_MIME_APP = ['application/x-dosexec']

    def __init__(self, parameters):
        super().__init__(parameters)
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

    def has_catSignature(self):
        # TODO
        # 1. Access /Windows/System32/CatRoot
        # 2. For each .cat file in /Windows/System32/CatRoot
        # 2.1 read file bytes and parse the ASN.1 content
        # 2.2 compare each OCTET STRING with the PE image hash
        # (ContentInfo->Digest using lief)
        # 2.3 if there is a match, the file is catalog-signed,
        # return true, else return false
        pass

    def handle_new_file(self, event):
        # get inode parameter
        inode = event.inode

        # get mime type
        mime_type = inode.mime_type
        if mime_type in self.VALID_MIME_APP:
            self.logger.info("New executable/library: %s", inode.path)
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
            hasEmbeddedSig = pe.has_signature
            hasCatSig = self.has_catSignature()
            # finish has-catSignature: execute only if hasEmbeddedSig is false

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
                               hasEmbeddedSig, hasCatSig, importedLibs)
            print(check_pe)
