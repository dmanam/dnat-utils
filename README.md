Some utilities related to DNAT

`dyndnat` takes a CSV of IPs in the format `original-dest,new-dest` and watches an NFQUEUE to perform the DNAT using `conntrack`. It also optionally adds routes for the destination IPs through a specified interface. The NFQUEUE is probably best added to the `INPUT` or `OUTPUT` chains of table `raw`.

`nfq-unit-start` watches an NFQUEUE and ensures that a specified `systemd` unit is activated before letting any packets through. For example, this could ensure that a VPN (which, say, has an automatic timeout and requires push-notification 2FA) is activated before we try to send packets that should be routed through it.

`resolve-hostsfile` takes a `hosts` file and converts it into a format suitable for `dyndnat`.
