# packer-templates

Set of `Packer` templates for `OSWatcher`.

## Requirements

- [`Packer`](https://www.packer.io/downloads.html) >= `1.3.4`
- `python3-docopt`
- `python3-libvirt`

## Build

Run `./packer build <template.json>`

Example

    ./packer build windows10.json

## Import in Libvirt

Use the `import_libvirt.py` script

    ./import_libvirt.py output-qemu/windows10.qcow2

See `./import_libvirt.py -h` for the options
