# pulseaudio-modules-bt

this module is a fork of pulseaudio bluetooth modules

and add ldac encoding support

so you can playing audio with ldac codec

use bluetooth headphones (support ldac decoding)

## Usage
backup original pulseaudio bt modules

    cd /usr/lib/pulse-xx.x/modules
    # xx.x is your current pulseaudio version
    cp module-bluez5-device.so module-bluez5-device.so.bak
    cp libbluez5-util.so libbluez5-util.so.bak

install

    git clone https://github.com/EHfive/pulseaudio-modules-bt.git
    cd pulseaudio-modules-bt
    git submodule update
    cd pa
    git checkout vxx.x # v12.2, v11.1, etc. pulseaudio version

    cd ..
    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX=/usr ..
    make
    make install

run

    pulseaudio -k

    #if pulseaudio not restart automatically run
    pulseaudio --start

then connect your bt headphone and swith audio profile to 'A2DP Sink'

if there is only profile 'HSP/HFP' anf 'off', disconnect and reconncet headphone


## TODO

add ldac abr (Adaptive Bit Rate) supprot

support ACC, APTX , APTX HD Codec using ffmpeg

