{ stdenv, libmnl, libnetfilter_queue, libnetfilter_conntrack, systemd, python3 }:

stdenv.mkDerivation rec {
    pname = "dnat-utils";
    version = "0.0.1";

    src = ./.;

    buildInputs = [ libmnl libnetfilter_queue libnetfilter_conntrack systemd python3 ];

    makeFlags = [ "PREFIX=$(out)" ];

    meta = {
        homepage = "https://github.com/dlahoti/dnat-utils";
        description = "some utilities related to DNAT";
        license = stdenv.lib.licenses.gpl3;
        platforms = stdenv.lib.platforms.linux;
    };
}
