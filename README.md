# airscan-discover
Discovery tool for sane-airscan compatible devices

This small tool discovers scanner devices, compatible with [sane-airscan](https://github.com/alexpevzner/sane-airscan)
backend.

**This tool is deprecated. Sane-airscan now comes with the similar tool.**

## Building

Assuming you have a Go compiler, execute the following command:

    go get -u github.com/alexpevzner/airscan-discover

It will download everything it need, build an executable and save it to `$HOME/go/bin/airscan-discover`

## Usage

    $ ~/go/bin/airscan-discover
    [devices]
      "Kyocera ECOSYS M2040dn" = http://192.168.1.102:5358/DeviceService/, wsd
      "Kyocera ECOSYS M2040dn" = http://192.168.1.102:9095/eSCL

It will print a list of discovered devices in a form suitable for adding to the `/etc/sane.d/airscan.conf` configuration
file.
