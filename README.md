# BiSignUtils

BiSignUtils is a cross-platform CLI tool for working with addon signatures for the DayZ and ArmA titles. It provides the functionality of DSCreateKey, DSSignFile and DSCheckSignatures in one tool as well as few handy extras.

---

## Features

- Cross-platform: runs on both Windows and Linux. It can be used in CI and Linux server setups;
- Generate private keys;
- Sign PBO files;
- Check the signatures of individual files or of all the addons installed on the server;
- Generate server key files (`.bikey`) from the add-on signatures;
- Work with any RSA key length.

## Installation

BiSignUtils does not require installation. Simply download the executable for your platform (`BiSignUtils.exe` for Windows and `BiSignUtils` without extension for Linux) from the [latest release](https://github.com/rvost/BiSignUtils/releases/latest), and  you're ready to go! For convenience, you may want to add your BiSignUtils location to the `PATH`.

Windows users may occasionally receive a warning from Windows Defender or other anti-virus software. You can safely ignore it. This is because BiSignUtils is not a properly signed application.

## Usage examples

- Generate a private key that is longer than the BI default:
  ```
  BiSignUtils generate MyTag --length=4096
  ```
- Sign addon:
  ```
  BiSignUtils sign MyTag.biprivatekey MyAddon.pbo
  ```
- Check that all of the PBOs in the mod have valid signatures with respect to your server keys (assuming you are in the root of the server):
  ```
  BiSignUtils checkAll ./keys ./@FooModpack
  ```
- Assuming that your current working directory is the server's root folder, extract the .bikeys all installed addons:
  ```
  BiSignUtils bisign2bikey -d=. -o=keys
  ```

You can also use the `--help` key to view all the available commands and options.

## Issues

If you find a bug or have a feature request, please use [Issues](https://github.com/rvost/BiSignUtils/issues) to report it.

## Acknowledgments

The `bisign2bikey` command was inspired by [@Wrdg](https://github.com/wrdg)'s [Bisign2Bikey](https://github.com/wrdg/Bisign2Bikey) utility.