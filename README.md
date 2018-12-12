# pulseaudio-modules-bt

this repo is a fork of pulseaudio bluetooth modules

and adds LDAC, APTX, APTX-HD, AAC support

#### Added Codecs
|Codec|Encoding(source role)|Decoding(sink role)|Sample format|Sample frequnecy|
|:---:|:---:|:---:|:---:|:---:|
|AAC |✔ |✔ |s16|8 ... 96 khz|
|APTX | ✔| ✔ |s16|16 ... 48 khz|
|APTX HD| ✔| ✔ |s24|16 ... 48 khz|
|LDAC |✔ |✘|s16,s24,s32,f32|44.1 ... 96 khz|

APTX/APTX_HD sample format fixed to s32 in PA.

## Usage
### Packages

[wiki/Packages](https://github.com/EHfive/pulseaudio-modules-bt/wiki/Packages)

also check #3

### General Installation

For packager, developer, other PA version user:

I also create patch files, you can find them in releases. Apply patches and recompile/repackage pulseaudio.

And you may use my CmakeList.txt (may also needs modifications) as well, just copy out patched files to src dir and keep file structure.

**Make Dependencies**

* pulseaudio,libpulse~=12.0
* bluez-libs/libbluetooth~=5.0
* libdbus
* ffmpeg(libavcodec>=58, libavutil>=56) >= 4.0
* libsbc
* libfdk-aac
* libtool
* cmake
* pkg-config

**Runtime Dependencies**

* pulseaudio
* bluez
* dbus
* sbc
* libfdk-aac
* [Optional] ffmpeg(libavcodec.so, libavutil.so) --- APTX, APTX-HD support
* [Optional] ldacBT_enc.so ldacBT_abr.so   --- LDAC encoding support, LDAC ABR support

Note: CMakeLists.txt check if [ldacBT](https://github.com/EHfive/ldacBT) installed; If not, it will build libldac and install libldac to PA modules dir.

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

git -C pa/ checkout v`pkg-config libpulse --modversion|sed 's/[^0-9.]*\([0-9.]*\).*/\1/'`

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
|aac_bitrate_mode|\[1, 5\]|Variable Bitrate (VBR)|5|
||0|Constant Bitrate (CBR)|
|aac_afterburner|<on/off>|Enable/Disable AAC encoder afterburner feature|off|
|aac_fmt|s16|16-bit signed (little endian)|auto|
||s32|32-bit signed|
||auto|Ref default-sample-format|

#### config

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

