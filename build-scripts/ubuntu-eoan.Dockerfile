FROM ubuntu:eoan

RUN apt update && apt install -y build-essential cmake pkg-config libtool cmake git checkinstall
RUN mkdir -p /dist

RUN git clone https://github.com/EHfive/ldacBT.git \
    && cd ldacBT \
    && git submodule update --init \
    && mkdir build && cd build \
    && cmake     -DCMAKE_INSTALL_PREFIX=/usr     -DINSTALL_LIBDIR=/usr/lib      \-DLDAC_SOFT_FLOAT=OFF     ../ \
    && echo 'Homepage: https://github.com/EHfive/ldacBT' > description-pak \
    && checkinstall -y  --install=yes \
        --pkgname=libldac-dev \
        --pkgrelease='eoan' \
        --pkgarch=$(dpkg --print-architecture) \
        --pkglicense='' \
        --provides='libldac,libldac-dev' \
    && cp *.deb /dist \
    && cd ..

RUN apt install -y libsbc-dev libavcodec-dev libavutil-dev libfdk-aac-dev \
        libdbus-1-dev libbluetooth-dev libpulse-dev pulseaudio \
    && git clone https://github.com/EHfive/pulseaudio-modules-bt.git \
    && cd pulseaudio-modules-bt \
    && git submodule update --init \
    && git -C pa/ checkout v`pkg-config libpulse --modversion|sed 's/[^0-9.]*\([0-9.]*\).*/\1/'` \
    && mkdir build && cd build \
    && cmake .. \
    && echo 'Homepage: https://github.com/EHfive/pulseaudio-modules-bt' > description-pak \
    && checkinstall -y --install=no \
        --pkgname=pulseaudio-modules-bt \
        --pkgrelease='eoan' \
        --pkgarch=$(dpkg --print-architecture) \
        --pkglicense='GPLv3' \
        --requires='libfdk-aac1,libsbc1, libdbus-1-3,bluez,libpulse0,pulseaudio' \
        --suggest='libavcodec,libldac' \
        --replaces='pulseaudio-module-bluetooth' \
        --conflicts='pulseaudio-module-bluetooth' \
        --provides='pulseaudio-module-bluetooth' \
    && cp *.deb /dist

RUN ls -l /dist