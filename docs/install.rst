.. SPDX-FileCopyrightText: © 2025 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Install
=======

The `latest release of Clifton <https://github.com/isambard-sc/clifton/releases/latest>`__ is available at GitHub but we describe below automatic ways to install it.
To install Clifton choose your operating system from the tabs below:

.. tab-set::

   .. tab-item:: macOS

      Download the binary of Clifton using ``curl``:

      .. tab-set::

         .. tab-item:: Apple Silicon (Arm)

            .. code:: shell-session

               % curl -L https://github.com/isambard-sc/clifton/releases/latest/download/clifton-macos-aarch64 -o clifton
               % chmod u+x clifton

         .. tab-item:: Intel

            .. code:: shell-session

               % curl -L https://github.com/isambard-sc/clifton/releases/latest/download/clifton-macos-x86_64 -o clifton
               % chmod u+x clifton

      If you want it accessible from any directory on your computer, you can place the binary in ``/usr/local/bin`` with:

      .. code:: shell-session

         % sudo mv clifton /usr/local/bin/

      If you don’t, you will need to specify the path to the executable when running it.
      So instead of ``clifton auth`` as described below you would run e.g. ``./clifton auth`` or ``~/clifton auth``.

      To update Clifton, run those same commands again.

      .. admonition:: Allowing Clifton to run on macOS
         :class: hint

         If you download the Clifton through your web browser rather than with ``curl``, you may be presented with a macOS warning dialog when trying to run the executable, e.g.

            “clifton” can’t be opened because Apple cannot check it for malicious software.

         If this occurs you will have to go into “System Settings > Privacy & Security” and allow use of the ``clifton`` executable (see `Open a Mac app from an unidentified developer <https://support.apple.com/en-gb/guide/mac-help/mh40616/mac>`__ from the macOS documentation).
         Note that you will need to have admin privileges to change the settings in “Privacy & Security”.

   .. tab-item:: Linux (including WSL)

      Download the binary of Clifton using ``curl``:

      .. tab-set::
         .. tab-item:: x86_64

            .. code:: shell-session

               $ curl -L https://github.com/isambard-sc/clifton/releases/latest/download/clifton-linux-musl-x86_64 -o clifton
               $ chmod u+x clifton

         .. tab-item:: AArch64

            .. code:: shell-session

               $ curl -L https://github.com/isambard-sc/clifton/releases/latest/download/clifton-linux-musl-aarch64 -o clifton
               $ chmod u+x clifton

      If you want it accessible from any directory on your computer, you can place the binary in ``~/.local/bin`` (or any directory on your ``$PATH`` you wish) with:

      .. code:: shell-session

         $ mkdir -p ~/.local/bin
         $ mv clifton ~/.local/bin/

      .. admonition:: Setting the path
         :class: hint

         Some Linux distributions do not have ``~/.local/bin`` in the ``$PATH`` by default.
         In this cae, either put the program somewhere which is already in the ``$PATH``,
         or add ``~/.local/bin`` with:

         .. code-block:: shell-session

            $ echo 'export PATH="~/.local/bin:$PATH"' >> ~/.bashrc

      If you don’t, you will need to specify the path to the executable when running it.
      So instead of ``clifton auth`` as described below you would run e.g. ``./clifton auth`` or ``~/clifton auth``.

      To update Clifton, run those same commands again.

      Alternatively, a tool like `mise <https://mise.jdx.dev/>`__ can install it for you with ``mise use -g ubi:isambard-sc/clifton``.

   .. tab-item:: Windows

      Clifton is available through WinGet.
      WinGet is a package installer from Microsoft which is installed by default on most Windows computers.

      Open a terminal window (search for “Terminal” or “Powershell” in the search bar at the bottom) and run:

      .. code:: pwsh-session

         > winget install clifton

      You will then need to close and reopen the terminal window before you can run any ``clifton`` commands.

      To update clifton, run ``winget upgrade clifton``.

      If WinGet is not available then you can download the file manually using

      .. code:: pwsh-session

         > curl.exe -L https://github.com/isambard-sc/clifton/releases/latest/download/clifton-windows-x86_64.exe -o clifton.exe

      If you have downloaded Clifton manually, when running it you will need to specify the path.
      So instead of ``clifton auth`` as described below you would run e.g. ``./clifton auth`` or ``~/clifton auth``.

You can check that it successfully installed by running

.. code-block:: shell-session

   clifton --version

which should print out

.. parsed-literal::

   clifton |version|
