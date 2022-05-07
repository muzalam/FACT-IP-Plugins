# FACT plugins - AlientVault, VirusTotal, XForce

These plugins add IP analysis functionality to [FACT](https://github.com/fkie-cad/FACT_core)

## Installation

Go to FACT's root directory and execute the following lines:

```sh
$ git submodule add https://github.com/muzalam/FACT-IP-Plugins.git src/plugins/analysis/
$ src/install.py -B
``` 

If you add more than one additional plug-in, ```./install.py -B``` must be run just once after you added the last plug-in.
