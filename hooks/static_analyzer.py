# re
import re

# 3rd
from see import Hook


class StaticAnalyzerHook(Hook):

    VALID_MIME_APP = [
        'application/x-dosexec'
    ]

    def __init__(self, parameters):
        super().__init__(parameters)
        # subscribe on "filesystem_new_file" events
        self.context.subscribe("filesystem_new_file", self.handle_new_file)

    def handle_new_file(self, event):
        # get inode parameter
        inode = event.inode

        # get mime type
        mime_type = inode.mime_type
        if mime_type in self.VALID_MIME_APP:
            self.logger.info("New executable/library: %s", inode.path)
            local_path = inode.local_file
            # load file in LIEF...
            # pe = LIEF.parse(local_path)
