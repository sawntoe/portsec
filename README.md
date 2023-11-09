# PORTSEC
--------
~~ What's a xinetd can I eat it ~~

Portsec serves as an easy and (somewhat) secure way to force users to authenticate before accessing a given port through iptables.

## Configuration

`portsec-port`: Port on which the authentication server runs on.

`mode`: Use username/password pairs or just one singular password. Can be "usernamepassword" or "passwordonly".

`users`: Username/password pairs for use with usernamepassword mode.

`password`: Password for use with passwordonly mode.

`allow`: List of iptables options to allow (not block). Cannot be used with `deny`

`deny`: List of iptables options to deny (block without authentication). Cannot be used with `allow`

`failopen`: Boolean value on whether to fallback to default iptables state before failing. Not recommended.

`failallow`: List of iptables options to allow on fail. Recommended for security. Requires `failopen` to be false. Cannot be used with `faildeny`.

`faildeny`: List of iptables options to deny on fail. Recommended for availability. Requires `failopen` to be false. Cannot be used with `failallow`.

## TODO

[] Error handling
[] Configuration checking

