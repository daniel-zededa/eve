#!/bin/bash

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# sshd needs its privilege separation directory. The image has it, but a
# native container (NOHYPER) on EVE gets an empty tmpfs on /run.
mkdir -p /run/sshd
/usr/sbin/sshd

# When run as a VM (console attached to a real serial device), stdin stays
# open and this shell is the interactive console. When run as a plain pod
# with no tty/stdin (e.g. NOHYPER), stdin is closed and bash returns
# immediately; fall back to blocking forever so the container doesn't
# crash-loop.
bash
exec sleep infinity
