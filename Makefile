#
#	r4 encrypt/decrypt
#
#	Copyright (C) 2023 lifehackerhansol
#
#	SPDX-License-Identifier: 0BSD
#

r4crypt2: r4crypt2.c
	gcc -Wall -Wextra -Wno-unused-result -std=gnu11 -O3 -o $@ $<

.PHONY: clean

clean:
	rm -rf r4crypt2
