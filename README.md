# pulseaudio-modules-bt

this module is a fork of pulseaudio bluetooth modules

and add ldac encoding support

so you can playing audio with ldac codec

use bluetooth A2DP device (support ldac decoding)

## Usage
#### Arch Linux

install AUR package [pulseaudio-modules-bt-git](https://aur.archlinux.org/packages/pulseaudio-modules-bt-git/)<sup>AUR</sup>

#### General Installation

**requirements**

* pulseaudio,libpulse~=12.0
* bluez,bluez-libs~=5.0
* sbc
* cmake
* pkg-config

**backup original pulseaudio bt modules**

```bash
MODDIR=`pkg-config --variable=modlibexecdir libpulse`

sudo find $MODDIR -regex ".*\(bluez5\|bluetooth\).*\.so" -exec cp {} {}.bak \;
```

**install**

```bash
git clone https://github.com/EHfive/pulseaudio-modules-bt.git
cd pulseaudio-modules-bt
git submodule update --init

git -C pa/ checkout v`pkg-config libpulse --modversion`

mkdir build && cd build
cmake ..
make
sudo make install
```

#### Load Modules

```bash
pulseaudio -k

# if pulseaudio not restart automatically, run
pulseaudio --start
```

then connect your bluetooth device and switch audio profile to 'A2DP Sink'

if there is only profile 'HSP/HFP' and 'off', disconnect and reconnect your device

> [" When the device connects automatically (by powering on after being paired) A2DP is 'unavailable' "   -----Issue: cannot select a2dp profile](https://gitlab.freedesktop.org/pulseaudio/pulseaudio/issues/525)

as an alternative, you can fix it with this [udev script](https://gist.github.com/EHfive/c4f1218a75f95b076f0387403246de78)

#### Module Aruguments

**module-bluez5-discover**

|Key| Value|Desc |Default|
|---|---|---|---|
|ldac|\<boolean\>|enable/disable LDAC codec|true|
|ldac_eqmid|hq|LDAC High Quality|auto|
||sq|LDAC Standard Quality|
||mq|LDAC Mobile use Quality|
||auto /abr|LDAC Adaptive Bit Rate|

#### config

edit `/etc/pulse/deamon.conf`

append arguments to 'load-module module-bluetooth-discover'

(module-bluetooth-discover pass all arguments to module-bluez5-discover)

    # LDAC Standard Quality
    load-module module-bluetooth-discover ldac_eqmid=sq

    # disable LDAC Codec support
    #load-module module-bluetooth-discover ldac=false


equivalent to commands below if you do not use 'module-bluetooth-discover'

    load-module module-bluez5-discover ldac_eqmid=sq

    #load-module module-bluez5-discover ldac=false

#### Others

see [Wiki](https://github.com/EHfive/pulseaudio-modules-bt/wiki)

## TODO

~~add ldac abr (Adaptive Bit Rate) supprot~~

add AAC, APTX , APTX HD Codec support using ffmpeg

