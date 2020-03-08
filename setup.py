import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="oswatcher",
    version="0.0.1",
    author="Mathieu Tarral",
    author_email="mathieu.tarral@protonmail.com",
    description="A tool to capture and extract information from an operating system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wenzel/oswatcher",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    entry_points = {
        'console_scripts': [
            'oswatcher = oswatcher.__main__:main'
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.7',
)