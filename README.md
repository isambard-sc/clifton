<!--
SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Clifton - an SSH connection manager

Clifton is used to retrieve SSH certificates for accessing remote computers.

See the documentation at https://clifton.readthedocs.io

There are two main commands in `clifton` that you will need, `auth` and `ssh-config`.

## `clifton auth`

`clifton auth` will authenticate with the identity provider and download a signed SSH certificate.
It will send to the server the fingperint of your local SSH identity file.
If you are using a non-standard identity file name, you can specify that file with, e.g.:

```console
clifton auth --identity=~/.ssh/my_key
```

To authenticate, `clifton` will both open your default browser and provide a QR code you can scan.
You can change which browser opens by setting the `BROWSER` environment variable.

## `clifton ssh-config`

This will generate the contents of your SSH config file that you can use to connect to the system.
By default it will print it to the screen so you can copy it manually into your config file.
If you want to write it automatically, call `clifton ssh-config write`.
