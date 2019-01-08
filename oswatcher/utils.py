import xml.etree.ElementTree as ET


def get_hard_disk(domain):
    root = ET.fromstring(domain.XMLDesc())
    disk = root.find("./devices/disk[@type='file'][@device='disk']")
    if disk is None:
        raise RuntimeError('Cannot find hard disk for domain {}'.format(domain.name()))
    qcow_path = disk.find('source').get('file')
    return qcow_path
