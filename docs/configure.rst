.. SPDX-FileCopyrightText: © 2025 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Configure
=========

Clifton can be configured via a config file called ``clifton/config.toml`` in your default config file location.
It won't exist by default, so you will need to create it.

.. dropdown:: Finding the config file
   :icon: search

   The location of the config file will vary depending on your operating system.
   It can also sometimes be modified my setting environment variables.

   .. list-table::
      :header-rows: 1

      *  - Platform
         - Environment variables
         - Example path
      *  - Linux
         - ``$XDG_CONFIG_HOME`` or ``$HOME/.config``
         - ``/home/alice/.config/clifton/config.toml``
      *  - macOS
         - ``$HOME/Library/Application Support``
         - ``/Users/Alice/Library/Application Support/clifton/config.toml``
      *  - Windows
         - ``{FOLDERID_LocalAppData}``
         - ``C:\Users\Alice\AppData\Local\clifton\config.toml``

If you want to specify a different config file, you can do so by passing the ``--config-file`` flag.

An example config file might look like:

.. code-block:: toml
   :caption: ``config.toml``

   write_config = true
   show_qr = false

.. confval:: write_config
   :type: boolean
   :default: false

   Should the SSH config be automatically writen every time ``clifton auth`` is run.

.. confval:: show_qr
   :type: boolean
   :default: true

   Should a QR code be printed out for the authentication URL when running ``clifton auth``.
