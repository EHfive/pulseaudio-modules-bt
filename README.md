# pulseaudio-modules-bt

this repo is a fork of pulseaudio bluetooth modules

and adds LDAC, APTX, APTX-HD, AAC support

#### Added Codecs
|Codec|Encoding(source role)|Decoding(sink role)|Sample format(s)|Sample frequencies|
|:---:|:---:|:---:|:---:|:---:|
|AAC |✔ |✔ |s16|8, 11.025, 12,16, 22.05, 24, 32, 44.1, 48, 64, 88.2, 96 khz|
|APTX | ✔| ✔ |s16|16, 32, 44.1, 48 khz|
|APTX HD| ✔| ✔ |s24||
|LDAC |✔ |✘|s16,s24,s32,f32|44.1, 48, 88.2, 96 khz|

APTX/APTX_HD sample format fixed to s32 in PA.
(ffmpeg do the sample format transformation)

## Usage
### Packages

[wiki/Packages](https://github.com/EHfive/pulseaudio-modules-bt/wiki/Packages)

also check issue#3

**Configure modules**

See [below](#configure).

### General Installation

**Make Dependencies**

* pulseaudio>=11.59.1
* bluez~=5.0
* dbus
* sbc
* \[Optional] ffmpeg(libavcodec>=58, libavutil>=56) >= 4.0
* \[Optional] fdk-aac(-free)>=0.1.5: pulseaudio-modules-bt use LC-AAC only
* \[Optional] [ldacBT](https://github.com/EHfive/ldacBT)/libldac
* cmake
* pkg-config, libtool, ...

**Runtime Dependencies**

* pulseaudio ( force preopen disabled / built with `--disable-force-preopen`)
* bluez
* dbus
* sbc
* \[ fdk-aac(-free) ]
* \[  libavcodec.so ]: APTX, APTX-HD support \[Optional]
* \[ libldac ]: LDAC encoding support, LDAC ABR support \[Optional]

#### Build

**backup original pulseaudio bt modules**

```bash
MODDIR=`pkg-config --variable=modlibexecdir libpulse`

sudo find $MODDIR -regex ".*\(bluez5\|bluetooth\).*\.so" -exec cp {} {}.bak \;
```

**pull sources**
```bash
git clone https://github.com/EHfive/pulseaudio-modules-bt.git
cd pulseaudio-modules-bt
git submodule update --init
```

**install**

A. build for PulseAudio releases (e.g., v12.0, v12.2, etc.)
```bash
git -C pa/ checkout v`pkg-config libpulse --modversion|sed 's/[^0-9.]*\([0-9.]*\).*/\1/'`

mkdir build && cd build
cmake ..
make
sudo make install
```

B. or build for PulseAudio git master
```bash
git -C pa/ checkout master
mkdir build && cd build
cmake -DFORCE_LARGEST_PA_VERSION=ON ..
make
sudo make install
```

*Cmake A2DP codecs options*: `CODEC_APTX_FF`, `CODEC_APTX_HD_FF`, `CODEC_AAC_FDK`, `CODEC_LDAC`

#### Load Modules

```bash
pulseaudio -k

# if pulseaudio not restart automatically, run
pulseaudio --start
```

if you got a warning like below, you need to rebuild `pulseaudio` with `--disable-force-preopen` flag
```
pulseaudio: symbol lookup error: pulseaudio: undefined symbol: pa_a2dp_codec_sbc
```

### Connect device

Connect your bluetooth device and switch audio profile to 'A2DP Sink';

If there is only profile 'HSP/HFP' and 'off', disconnect and reconnect your device.

The issue has been fixed in bluez 5.51.

#### Module Arguments

**module-bluez5-discover arg:a2dp_config**

Encoders configurations

|Key| Value|Desc |Default|
|---|---|---|---|
|ldac_eqmid|hq|LDAC High Quality|auto|
||sq|LDAC Standard Quality|
||mq|LDAC Mobile use Quality|
||auto /abr|LDAC Adaptive Bit Rate|
|ldac_fmt|s16|16-bit signed (little endian)|auto|
||s24|24-bit signed|
||s32|32-bit signed|
||f32|32-bit float|
||auto|Ref default-sample-format|
|ldac_abr_t1|\<uint>|safety threshold for LDACBT_EQMID_HQ and LDACBT_EQMID_SQ|2|
|ldac_abr_t2|\<uint>|threshold for dangerous trend of TxQueueDepth|4|
|ldac_abr_t3|\<uint>|threshold for critical TxQueueDepth status|6|
|aac_bitrate_mode|\[1, 5\]|Variable Bitrate (VBR)|0|
||0|Constant Bitrate (CBR)|
|aac_afterburner|<on/off>|Enable/Disable AAC encoder afterburner feature|off|
|aac_fmt|s16|16-bit signed (little endian)|auto|
||s32|32-bit signed|
||auto|Ref default-sample-format|

#### Configure

edit `/etc/pulse/default.pa`

append arguments to 'load-module module-bluetooth-discover'

(module-bluetooth-discover pass all arguments to module-bluez5-discover)

    # LDAC Standard Quality
    load-module module-bluetooth-discover a2dp_config="ldac_eqmid=sq"

    # LDAC High Quality; Force LDAC/PA PCM sample format as Float32LE
    #load-module module-bluetooth-discover a2dp_config="ldac_eqmid=hq ldac_fmt=f32"


equivalent to commands below if you do not use 'module-bluetooth-discover'

    load-module module-bluez5-discover a2dp_config="ldac_eqmid=sq"

    #load-module module-bluez5-discover a2dp_config="ldac_eqmid=hq ldac_fmt=f32"

#### Others

see [Wiki](https://github.com/EHfive/pulseaudio-modules-bt/wiki)

## TODO

~~add ldac abr (Adaptive Bit Rate) supprot~~

~~add APTX , APTX HD Codec support using ffmpeg~~

~~add AAC support using Fraunhofer FDK AAC codec library~~

~~add codec switching support using latest blueZ's experimental feature~~

## Copyright
```
  pulseaudio-modules-bt

  Copyright (C) 2018-2019  Huang-Huang Bao

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.
```
