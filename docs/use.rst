.. SPDX-FileCopyrightText: © 2025 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Use
===

The primary command you need to run is

.. code-block:: shell-session

   clifton auth

This will communicate with the certificate server and open a browser window so you can log in and grant access.

.. admonition:: Certificate lifetime
   :class: important

   Many certificate servers will return certificates with a limited life span.
   You will likely need to run ``clifton auth`` each time you want to use SSH.
   This could be anything from every hour, every day or every week.

In order to connect via SSH to the remote server, Clifton can generate SSH config.
Run

.. code-block:: shell-session

   clifton ssh-config write

to write this config for you.
It will then also print out the available SSH host alises you can use with the ``ssh`` command.

.. admonition:: Updated resources
   :class: hint

   You only need to run ``clifton ssh-config write`` if the resources you have access to change.
   However, if they *do* change,  then you will need to re-run it to be able to use the SSH aliases.

If you wish, you can combine these two steps into one by running the authentication step with:

.. code-block:: shell-session

   clifton auth --write-config=true

or by setting the :confval:`write_config` configuration setting to ``true``.

More options and commands can be found by running ``clifton -h`` as well as on sub-commands, e.g. ``clifton auth -h``.
