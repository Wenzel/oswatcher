import xml.etree.ElementTree as ET


def get_hard_drive_path(domain):
    root = ET.fromstring(domain.XMLDesc())
    disk = root.find("./devices/disk[@type='file'][@device='disk']")
    if disk is None:
        raise RuntimeError('Cannot find hard disk for domain {}'.format(domain.name()))
    qcow_path = disk.find('source').get('file')
    return qcow_path


def format_size(self, size: int, precision: int = 2) -> str:
    suffix = ['B', 'KB', 'MB', 'GB']
    suffix_index = 0

    if size == 0:
        return "0"
    else:
        while size > 1024 and suffix_index < 3:
            suffix_index += 1
            size = size / 1024.0

    return "%.*f%s" % (precision, size, suffix[suffix_index])
