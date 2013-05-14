/*
 * Copyright (C) 2013, Henryk Plötz.
 * Boilerplate code copyright (C) 2010, Romain Tartiere.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>

static int analyze(MifareTag tag)
{
	int retval = EXIT_FAILURE;
	return retval;
}

int main(int argc, char *argv[])
{
	int error = EXIT_SUCCESS;
	nfc_device *device = NULL;
	MifareTag *tags = NULL;

	if(argc > 1) {
		errx(EXIT_FAILURE, "usage: %s", argv[0]);
	}

	nfc_connstring devices[8];
	size_t device_count;

	nfc_context *context;
	nfc_init(&context);

	device_count = nfc_list_devices(context, devices, 8);
	if(device_count <= 0) {
		errx(EXIT_FAILURE, "No NFC device found.");
	}

	for(size_t d = 0; d < device_count; d++) {
		device = nfc_open(context, devices[d]);
		if(!device) {
			warnx("nfc_open() failed.");
			error = EXIT_FAILURE;
			continue;
		}

		tags = freefare_get_tags(device);
		if(!tags) {
			nfc_close(device);
			errx(EXIT_FAILURE, "Error listing tags.");
		}

		for(int i = 0; (!error) && tags[i]; i++) {
			if(DESFIRE != freefare_get_tag_type(tags[i])) {
				continue;
			}

			int res;

			res = mifare_desfire_connect(tags[i]);
			if(res < 0) {
				warnx("Can't connect to Mifare DESFire target.");
				error = 1;
				break;
			}

			analyze(tags[i]);

			mifare_desfire_disconnect(tags[i]);
		}

		freefare_free_tags(tags);
		nfc_close(device);
	}
	nfc_exit(context);
	exit(error);
}

