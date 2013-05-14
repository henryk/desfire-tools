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

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

const uint32_t WELL_KNOWN_AIDS[] = {
		0xFF77F0, 0xFF77F1, 0xFF77F2, 0xFF77F3, 0xFF77F4, 0xFF77F5, 0xFF77F6, 0xFF77F7, 0xFF77F8, 0xFF77F9, 0xFF77FA, 0xFF77FB, 0xFF77FC, 0xFF77FD, 0xFF77FE, 0xFF77FF, // OpenKey
		0xFF77CF, // DOPE
};

struct mifare_desfire_card_information {
	char *uid;
	bool random_uid;

	bool key_settings_retrieved;
	uint8_t key_settings;
	uint8_t max_keys;

	enum mifare_desfire_authentication_mode {
		MIFARE_DESFIRE_AUTHENTICATION_MODE_UNKNOWN,
		MIFARE_DESFIRE_AUTHENTICATION_MODE_DES,
		MIFARE_DESFIRE_AUTHENTICATION_MODE_AES,
	} authentication_mode;

	struct mifare_desfire_application_information {
		uint32_t aid;
		bool key_settings_retrieved;
		uint8_t key_settings;
		uint8_t max_keys;
		enum mifare_desfire_authentication_mode authentication_mode;

		struct mifare_desfire_file_information {
			uint8_t file_id;
			bool file_present;
			bool readable;
			enum mifare_desfire_file_type {
				MIFARE_DESFIRE_FILE_TYPE_UNKNOWN,
				MIFARE_DESFIRE_FILE_TYPE_DATA,
				MIFARE_DESFIRE_FILE_TYPE_RECORD,
				MIFARE_DESFIRE_FILE_TYPE_VALUE,
			} file_type;
			size_t file_length;
		} file[32];
	} app[28];
	bool aids_retrieved;
};

static int get_uid(MifareTag tag, struct mifare_desfire_card_information *ci)
{
	int retval = -1;

	ci->uid = freefare_get_tag_uid(tag);
	if(ci->uid == NULL) {
		goto abort;
	}

	if(strlen(ci->uid) == 4*2) {
		ci->random_uid = 1;
	}

	retval = 0;

abort:
	return retval;
}


static void get_application_list(MifareTag tag, struct mifare_desfire_card_information *ci)
{
	MifareDESFireAID *aids = NULL;
	size_t aid_count;
	int r = mifare_desfire_get_application_ids(tag, &aids, &aid_count);
	if(r < 0) {
		return;
	}

	for(size_t i=0; i<aid_count; i++) {
		if(i >= ARRAY_SIZE(ci->app)) {
			break;
		}
		ci->app[i].aid = mifare_desfire_aid_get_aid(aids[i]);
	}

	mifare_desfire_free_application_ids(aids);
	ci->aids_retrieved = 1;
}

static void try_well_known_aids(MifareTag tag, struct mifare_desfire_card_information *ci)
{
	int pos = 0;
	for(size_t i=0; i<ARRAY_SIZE(ci->app); i++) {
		if(ci->app[i].aid == 0) {
			pos = i;
			break;
		}
	}

	if(ci->app[pos].aid != 0) {
		return;
	}

	for(size_t i=0; i<ARRAY_SIZE(WELL_KNOWN_AIDS); i++) {
		MifareDESFireAID aid = mifare_desfire_aid_new(WELL_KNOWN_AIDS[i]);
		if(aid == NULL) {
			return;
		}

		if(mifare_desfire_select_application(tag, aid) >= 0) {
			ci->app[pos++].aid = WELL_KNOWN_AIDS[i];
		}
		free(aid);

		if(pos >= ARRAY_SIZE(ci->app)) {
			return ;
		}
	}
}

static void analyze_file(MifareTag tag, struct mifare_desfire_file_information *fi)
{
	uint8_t tmp[10];
	int32_t val;
	int r = mifare_desfire_read_data_ex(tag, fi->file_id, 0, 1, tmp, 0);

	if(r == 1) {
		fi->file_type = MIFARE_DESFIRE_FILE_TYPE_DATA;
		fi->readable = 1;
	}

	switch(mifare_desfire_last_picc_error(tag)) {
	case AUTHENTICATION_ERROR:
		fi->file_type = MIFARE_DESFIRE_FILE_TYPE_DATA;
		break;
	}

	r = mifare_desfire_get_value_ex(tag, fi->file_id, &val, 0);
	if(r>=0 || mifare_desfire_last_picc_error(tag) != PERMISSION_ERROR) {
		fi->file_type = MIFARE_DESFIRE_FILE_TYPE_VALUE;
	}
}

static int analyze_app(MifareTag tag, struct mifare_desfire_application_information *ai)
{
	int retval = -1;
	uint8_t *files = NULL;
	size_t count = 0;
	MifareDESFireAID aid = mifare_desfire_aid_new(ai->aid);
	MifareDESFireKey aes_key = NULL, des_key = NULL;
	uint8_t null_key[16] = {0};

	if(aid == NULL) {
		goto abort;
	}

	des_key = mifare_desfire_des_key_new(null_key);
	aes_key = mifare_desfire_aes_key_new(null_key);

	if(des_key == NULL || aes_key == NULL) {
		goto abort;
	}

	int r = mifare_desfire_select_application(tag, aid);
	if(r < 0) {
		goto abort;
	}

	// FIXME: In principle it should be possible to distinguish authentication modes without knowing the key by looking at the first response (which is either AE right away or AF first)
	r = mifare_desfire_authenticate(tag, 0, des_key);
	if(r >= 0) {
		ai->authentication_mode = MIFARE_DESFIRE_AUTHENTICATION_MODE_DES;
	}

	r = mifare_desfire_authenticate(tag, 0, aes_key);
	if(r >= 0) {
		ai->authentication_mode = MIFARE_DESFIRE_AUTHENTICATION_MODE_AES;
	}

	r = mifare_desfire_get_file_ids(tag, &files, &count);
	if(r >= 0) {
		if(count >= ARRAY_SIZE(ai->file)) {
			goto abort;
		}
		for(size_t i=0; i<count; i++) {
			ai->file[i].file_id = files[i];
			ai->file[i].file_present = 1;
		}
	} else {
		uint8_t tmp;
		int pos = 0;
		for(size_t i=0; i<ARRAY_SIZE(ai->file); i++) {
			int present = 0;

			if(mifare_desfire_read_data_ex(tag, i, 0, sizeof(tmp), &tmp, 0) >= 0) {
				present = 1;
			} else switch(mifare_desfire_last_picc_error(tag)) {
			case AUTHENTICATION_ERROR: // Fall-through
			case LENGTH_ERROR:
			case PERMISSION_ERROR:
			case BOUNDARY_ERROR:
			case COUNT_ERROR:
				present = 1;
				break;
			default:
				break;
			}

			if(present) {
				ai->file[pos].file_id = i;
				ai->file[pos].file_present = 1;
				pos++;
			}
		}
	}

	for(size_t i=0; i<ARRAY_SIZE(ai->file); i++) {
		if(!ai->file[i].file_present) {
			continue;
		}
		analyze_file(tag, ai->file + i);
	}



abort:
	free(aid);
	if(files != NULL) {
		free(files);
	}
	if(aes_key != NULL) {
		mifare_desfire_key_free(aes_key);
	}
	if(des_key != NULL) {
		mifare_desfire_key_free(des_key);
	}
	return retval;
}

static int analyze_tag(MifareTag tag, struct mifare_desfire_card_information *ci)
{
	int retval = -1;

	if(tag == NULL || ci == NULL) {
		goto abort;
	}

	if(get_uid(tag, ci) < 0) {
		goto abort;
	}

	get_application_list(tag, ci);
	if(!ci->aids_retrieved) {
		try_well_known_aids(tag, ci);
	}

	for(size_t i=0; i<ARRAY_SIZE(ci->app); i++) {
		if(ci->app[i].aid == 0) {
			continue;
		}
		analyze_app(tag, ci->app+i);
	}

abort:
	return retval;
}

static void print_information(const struct mifare_desfire_card_information *ci)
{
	printf("== Tag UID %s ==\n", ci->uid);
	if(ci->random_uid) {
		printf("\t + UID is random\n");
	}

	if(!ci->aids_retrieved) {
		printf("\t + AID list could not be retrieved\n");
	}

	for(size_t i=0; i<ARRAY_SIZE(ci->app); i++) {
		if(ci->app[i].aid == 0) {
			continue;
		}
		printf("\t== App %06X ==\n", ci->app[i].aid);

		switch(ci->app[i].authentication_mode) {
		case MIFARE_DESFIRE_AUTHENTICATION_MODE_UNKNOWN:
			printf("\t\t + Unknown authentication\n");
			break;
		case MIFARE_DESFIRE_AUTHENTICATION_MODE_AES:
			printf("\t\t + AES authentication\n");
			break;
		case MIFARE_DESFIRE_AUTHENTICATION_MODE_DES:
			printf("\t\t + DES authentication\n");
			break;
		}

		for(size_t j=0; j<ARRAY_SIZE(ci->app[i].file); j++) {
			if(!ci->app[i].file[j].file_present) {
				continue;
			}
			printf("\t\t== File %2i ==\n", ci->app[i].file[j].file_id);
			switch(ci->app[i].file[j].file_type) {
			case MIFARE_DESFIRE_FILE_TYPE_UNKNOWN:
				printf("\t\t\t + File type unknown\n");
				break;
			case MIFARE_DESFIRE_FILE_TYPE_DATA:
				printf("\t\t\t + File type data\n");
				break;
			case MIFARE_DESFIRE_FILE_TYPE_RECORD:
				printf("\t\t\t + File type record\n");
				break;
			case MIFARE_DESFIRE_FILE_TYPE_VALUE:
				printf("\t\t\t + File type value\n");
				break;
			}
		}
	}
}

static void free_information(struct mifare_desfire_card_information *ci)
{
	if(ci == NULL) {
		return;
	}

	if(ci->uid != NULL) {
		free(ci->uid);
	}
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

			struct mifare_desfire_card_information ci;
			memset(&ci, 0, sizeof(ci));

			analyze_tag(tags[i], &ci);
			print_information(&ci);
			free_information(&ci);

			mifare_desfire_disconnect(tags[i]);
		}

		freefare_free_tags(tags);
		nfc_close(device);
	}
	nfc_exit(context);
	exit(error);
}

