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
#include <ctype.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

const uint32_t WELL_KNOWN_AIDS[] = {
		0xFF77F0, 0xFF77F1, 0xFF77F2, 0xFF77F3, 0xFF77F4, 0xFF77F5, 0xFF77F6, 0xFF77F7, 0xFF77F8, 0xFF77F9, 0xFF77FA, 0xFF77FB, 0xFF77FC, 0xFF77FD, 0xFF77FE, 0xFF77FF, // OpenKey
		0xFF77CF, // DOPE
		0x000357, // Legic Advant, found in brute force
};

const struct {
	size_t key_length;
	uint8_t key[24];
} WELL_KNOWN_KEYS[] = {
		{8, {0}},
		{16, {0}},
		{24, {0}},
};

#define RFERROR(tag) (nfc_device_get_last_error(*(nfc_device**)tag) == NFC_ERFTRANS)

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

	struct key_information {
		enum key_information_result {
			KEY_INFORMATION_RESULT_UNKNOWN,
			KEY_INFORMATION_RESULT_DES,
			KEY_INFORMATION_RESULT_3DES,
			KEY_INFORMATION_RESULT_3K3DES,
			KEY_INFORMATION_RESULT_AES,
		} key_information_result;
		uint8_t key[24];
		size_t key_length;
	} key_information;

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

			uint8_t *file_contents;
			size_t file_contents_length;
		} file[32];

		struct key_information key_information[14];
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

		if(RFERROR(tag)) {
			return;
		}

		if(pos >= ARRAY_SIZE(ci->app)) {
			return ;
		}
	}
}

static void try_all_aids(MifareTag tag, struct mifare_desfire_card_information *ci)
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

	for(uint32_t i=1; i<=0xFFFFFF; i++) {
		MifareDESFireAID aid = mifare_desfire_aid_new(i);
		if(aid == NULL) {
			return;
		}

		if(mifare_desfire_select_application(tag, aid) >= 0) {
			ci->app[pos++].aid = i;
		}
		free(aid);

		if(RFERROR(tag)) {
			return;
		}

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
	} if(RFERROR(tag)) {
		return;
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

static void try_keys(MifareTag tag, enum mifare_desfire_authentication_mode authentication_mode, size_t num_keys, struct key_information *ki)
{
	for(size_t i=0; i<num_keys; i++) {
		for(size_t j=0; j<ARRAY_SIZE(WELL_KNOWN_KEYS); j++) {
			if(authentication_mode == MIFARE_DESFIRE_AUTHENTICATION_MODE_AES) {
				if(WELL_KNOWN_KEYS[j].key_length != 16) {
					continue;
				}
			}

			MifareDESFireKey kdes = NULL, k3des = NULL, k3k3des = NULL, kaes = NULL;
			switch(WELL_KNOWN_KEYS[j].key_length) {
			case 8:
				kdes = mifare_desfire_des_key_new((uint8_t*)WELL_KNOWN_KEYS[j].key);
				break;
			case 16:
				k3des = mifare_desfire_3des_key_new((uint8_t*)WELL_KNOWN_KEYS[j].key);
				kaes = mifare_desfire_aes_key_new((uint8_t*)WELL_KNOWN_KEYS[j].key);
				break;
			case 24:
				k3k3des = mifare_desfire_3k3des_key_new((uint8_t*)WELL_KNOWN_KEYS[j].key);
				break;
			default:
				continue;
			}

			if(ki[i].key_information_result == KEY_INFORMATION_RESULT_UNKNOWN && kdes != NULL) {
				if(mifare_desfire_authenticate(tag, i, kdes) >= 0) {
					ki[i].key_information_result = KEY_INFORMATION_RESULT_DES;
				}
			}

			if(RFERROR(tag)) {
				goto skip;
			}

			if(ki[i].key_information_result == KEY_INFORMATION_RESULT_UNKNOWN && k3des != NULL) {
				if(mifare_desfire_authenticate(tag, i, k3des) >= 0) {
					ki[i].key_information_result = KEY_INFORMATION_RESULT_3DES;
				}
			}

			if(RFERROR(tag)) {
				goto skip;
			}

			if(ki[i].key_information_result == KEY_INFORMATION_RESULT_UNKNOWN && k3k3des != NULL) {
				if(mifare_desfire_authenticate(tag, i, k3k3des) >= 0) {
					ki[i].key_information_result = KEY_INFORMATION_RESULT_3K3DES;
				}
			}

			if(RFERROR(tag)) {
				goto skip;
			}

			if(ki[i].key_information_result == KEY_INFORMATION_RESULT_UNKNOWN && kaes != NULL) {
				if(mifare_desfire_authenticate(tag, i, kaes) >= 0) {
					ki[i].key_information_result = KEY_INFORMATION_RESULT_AES;
				}
			}

skip:

			if(kdes != NULL) {
				mifare_desfire_key_free(kdes);
			}
			if(k3des != NULL) {
				mifare_desfire_key_free(k3des);
			}
			if(k3k3des != NULL) {
				mifare_desfire_key_free(k3k3des);
			}
			if(kaes != NULL) {
				mifare_desfire_key_free(kaes);
			}

			if(ki[i].key_information_result != KEY_INFORMATION_RESULT_UNKNOWN) {
				memcpy(ki[i].key, WELL_KNOWN_KEYS[j].key, WELL_KNOWN_KEYS[j].key_length);
				ki[i].key_length = WELL_KNOWN_KEYS[j].key_length;
				break;
			}

			if(RFERROR(tag)) {
				return;
			}

		}
	}
}

enum try_key_result {
	TRY_KEY_RESULT_ERROR,
	TRY_KEY_RESULT_KEY_NO_INVALID,
	TRY_KEY_RESULT_AUTH_MODE_INVALID,
	TRY_KEY_RESULT_OK,
};

static enum try_key_result try_auth(MifareTag tag, uint8_t auth_mode, uint8_t key_no)
{
	// "MifareTag" is struct mifare_desfire_tag, its first member is struct mifare_tag whose first member is nfc_device*,
	//  so derefencing a MifareTag should lead to an nfc_device pointer.
	nfc_device *dev = *(nfc_device**)tag;
	uint8_t outbuf[100];
	size_t outbuf_length = 0;
	uint8_t inbuf[100];
	size_t inbuf_length = sizeof(inbuf);

	// Logic assembled from mifare_desfire.c and by looking at traces:
	//  Outgoing is an ISO 7816 APDU with CLA 90, INS = auth_mode, P1 = P2 = 0, Lc = 1, Body = key_no, Le = 0
	outbuf[0] = 0x90;
	outbuf[1] = auth_mode;
	outbuf[2] = outbuf[3] = 0;
	outbuf[4] = 1;
	outbuf[5] = key_no;
	outbuf[6] = 0;
	outbuf_length = 7;

	int r = nfc_initiator_transceive_bytes(dev, outbuf, outbuf_length, inbuf, inbuf_length, 0);

	if(r == 2) {
		// Card sent an error code in SW2. From experiments:
		if(inbuf[1] == 0x40) {
			// Key number invalid
			return TRY_KEY_RESULT_KEY_NO_INVALID;
		} else if(inbuf[1] == 0xAE) {
			return TRY_KEY_RESULT_AUTH_MODE_INVALID;
		} else {
			return TRY_KEY_RESULT_ERROR;
		}
	} else if(r > 2) {
		// Card sent a challenge back, meaning it accepts the authentication mode and key.
		// In order for it to abort the authentication attempt, we need to send another command, but don't care about the result
		outbuf[1] = 0xaf;
		nfc_initiator_transceive_bytes(dev, outbuf, outbuf_length, inbuf, inbuf_length, 0);
		return TRY_KEY_RESULT_OK;
	} else {
		// Card sent nothing back, it's either gone or something else went wrong
		return TRY_KEY_RESULT_ERROR;
	}
}

static int authenticate(MifareTag tag, struct mifare_desfire_application_information *ai, uint8_t key_no)
{
	MifareDESFireKey k;
	int r;

	switch(ai->key_information[key_no].key_information_result) {
	case KEY_INFORMATION_RESULT_UNKNOWN:
		return -1;
	case KEY_INFORMATION_RESULT_DES:
		k = mifare_desfire_des_key_new(ai->key_information[key_no].key);
		break;
	case KEY_INFORMATION_RESULT_3DES:
		k = mifare_desfire_3des_key_new(ai->key_information[key_no].key);
		break;
	case KEY_INFORMATION_RESULT_3K3DES:
		k = mifare_desfire_3k3des_key_new(ai->key_information[key_no].key);
		break;
	case KEY_INFORMATION_RESULT_AES:
		k = mifare_desfire_aes_key_new(ai->key_information[key_no].key);
		break;
	}

	r = mifare_desfire_authenticate(tag, key_no, k);
	mifare_desfire_key_free(k);

	return r;
}

static int read_file(MifareTag tag, struct mifare_desfire_file_information *fi)
{
	uint8_t buffer[32 + 32];
	size_t buffer_length;

	int cs = MDCM_ENCIPHERED;
	int r = mifare_desfire_read_data_ex(tag, fi->file_id, 0, 1, buffer, cs);
	if(RFERROR(tag)) {
		return -1;
	}

	if(r < 0) {
		cs = MDCM_MACED;
		r = mifare_desfire_read_data_ex(tag, fi->file_id, 0, 1, buffer, cs);
		if(RFERROR(tag)) {
			return -1;
		}
	}

	if(r < 0) {
		cs = MDCM_PLAIN;
		r = mifare_desfire_read_data_ex(tag, fi->file_id, 0, 1, buffer, cs);
		if(RFERROR(tag)) {
			return -1;
		}
	}

	if(r < 0) {
		return -1;
	}

	buffer_length = sizeof(buffer) -32;
	while(buffer_length > 0) {
		r = mifare_desfire_read_data_ex(tag, fi->file_id, fi->file_contents_length, buffer_length, buffer, cs);
		if(RFERROR(tag)) {
			return -1;
		}
		if(r > 0) {
			void *old = fi->file_contents;
			fi->file_contents = realloc(fi->file_contents, fi->file_contents_length + r);
			if(fi->file_contents == NULL) {
				if(old != NULL) {
					free(old);
				}
				return -1;
			}
			memcpy(fi->file_contents + fi->file_contents_length, buffer, r);
			fi->file_contents_length += r;
		} else {
			buffer_length /= 2;
		}
	}
	return 0;
}

static int analyze_app(MifareTag tag, struct mifare_desfire_application_information *ai)
{
	int retval = -1;
	uint8_t *files = NULL;
	size_t count = 0;
	MifareDESFireAID aid = mifare_desfire_aid_new(ai->aid);

	if(aid == NULL) {
		goto abort;
	}

	int r = mifare_desfire_select_application(tag, aid);
	if(r < 0) {
		goto abort;
	}

	r = mifare_desfire_get_key_settings(tag, &ai->key_settings, &ai->max_keys);
	if(r == 0) {
		ai->key_settings_retrieved = 1;
	} else if(RFERROR(tag)) {
		goto abort;
	}

	// First determine the authentication mode
	uint8_t auth_mode = 0;
	r = try_auth(tag, 0x0a, 0);
	if(RFERROR(tag)) {
		goto abort;
	}

	if(r == TRY_KEY_RESULT_OK) {
		ai->authentication_mode = MIFARE_DESFIRE_AUTHENTICATION_MODE_DES;
		auth_mode = 0x0a;
	} else {
		r = try_auth(tag, 0xaa, 0);
		if(RFERROR(tag)) {
			goto abort;
		}

		if(r == TRY_KEY_RESULT_OK) {
			ai->authentication_mode = MIFARE_DESFIRE_AUTHENTICATION_MODE_AES;
			auth_mode = 0xaa;
		}
	}

	// Now, if we know it, try to enumerate keys
	if(!ai->key_settings_retrieved && auth_mode != 0) {
		for(size_t i=1; i<16; i++) {
			r = try_auth(tag, auth_mode, i);
			if(r == TRY_KEY_RESULT_KEY_NO_INVALID) {
				ai->max_keys = i;
				break;
			} else if(r != TRY_KEY_RESULT_OK) {
				if(RFERROR(tag)) {
					goto abort;
				}

				break;
			}
		}
	}

	try_keys(tag, ai->authentication_mode, ai->max_keys, ai->key_information);
	if(RFERROR(tag)) {
		goto abort;
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
		if(RFERROR(tag)) {
			goto abort;
		}

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

			if(RFERROR(tag)) {
				goto abort;
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
		if(RFERROR(tag)) {
			goto abort;
		}
	}

	for(size_t i=0; i<ARRAY_SIZE(ai->file); i++) {
		if(!ai->file[i].file_present) {
			continue;
		}

		if(ai->file[i].file_type == MIFARE_DESFIRE_FILE_TYPE_DATA) {
			if(ai->file[i].readable) {
				read_file(tag, ai->file + i);
				if(RFERROR(tag)) {
					goto abort;
				}
			} else {
				for(size_t j=0; j<ARRAY_SIZE(ai->key_information); j++) {
					if(authenticate(tag, ai, j) >= 0) {
						if(read_file(tag, ai->file + i) >= 0) {
							ai->file[i].readable = 1;
							break;
						}
					}
					if(RFERROR(tag)) {
						goto abort;
					}
				}
			}
		}

	}



abort:
	free(aid);
	if(files != NULL) {
		free(files);
	}
	return retval;
}

static int analyze_tag(MifareTag tag, struct mifare_desfire_card_information *ci, bool do_brute)
{
	int retval = -1;

	if(tag == NULL || ci == NULL) {
		goto abort;
	}

	if(get_uid(tag, ci) < 0) {
		goto abort;
	}

	int r = mifare_desfire_select_application(tag, NULL);
	if(r >= 0) {
		r = try_auth(tag, 0x0a, 0);
		if(RFERROR(tag)) {
			goto abort;
		}

		if(r == TRY_KEY_RESULT_OK) {
			ci->authentication_mode = MIFARE_DESFIRE_AUTHENTICATION_MODE_DES;
		} else {
			r = try_auth(tag, 0xaa, 0);
			if(RFERROR(tag)) {
				goto abort;
			}

			if(r == TRY_KEY_RESULT_OK) {
				ci->authentication_mode = MIFARE_DESFIRE_AUTHENTICATION_MODE_AES;
			}
		}
	} else if(RFERROR(tag)) {
		goto abort;
	}

	r = mifare_desfire_get_key_settings(tag, &ci->key_settings, &ci->max_keys);
	if(r == 0) {
		ci->key_settings_retrieved = 1;
	} else if(RFERROR(tag)) {
		goto abort;
	}

	try_keys(tag, ci->authentication_mode, 1, &(ci->key_information));
	if(RFERROR(tag)) {
		goto abort;
	}

	get_application_list(tag, ci);

	if(RFERROR(tag)) {
		goto abort;
	}

	if(!ci->aids_retrieved) {
		if(do_brute) {
			try_all_aids(tag, ci);
		} else {
			try_well_known_aids(tag, ci);
		}
	}

	if(RFERROR(tag)) {
		goto abort;
	}

	for(size_t i=0; i<ARRAY_SIZE(ci->app); i++) {
		if(ci->app[i].aid == 0) {
			continue;
		}
		analyze_app(tag, ci->app+i);
		if(RFERROR(tag)) {
			goto abort;
		}
	}

abort:
	return retval;
}

static void print_key_settings(int app, uint8_t key_settings)
{
	const char *indent = "\t";
	if(app) {
		indent = "\t\t";
	}

	printf("%s + Key settings (0x%02x):\n", indent, key_settings);
	if(key_settings & 0x08) {
		printf("%s\t + Configuration changeable\n", indent);
	}

	if(key_settings & 0x04) {
		printf("%s\t + PICC Master Key not required for create / delete\n", indent);
	}

	if(key_settings & 0x02) {
		printf("%s\t + Free directory list access without PICC Master Key\n", indent);
	}

	if(key_settings & 0x01) {
		printf("%s\t + Allow changing the Master Key\n", indent);
	}

}

static void print_keys(int app, size_t num_keys, const struct key_information *ki)
{
	const char *indent = "\t";
	if(app) {
		indent = "\t\t";
	}

	for(size_t i=0; i<num_keys; i++) {
		if(ki[i].key_information_result == KEY_INFORMATION_RESULT_UNKNOWN) {
			continue;
		}
		printf("%s + Found key %zi:\n", indent, i);
		switch(ki[i].key_information_result) {
		case KEY_INFORMATION_RESULT_DES:
			printf("%s\t + Key type DES\n", indent);
			break;
		case KEY_INFORMATION_RESULT_3DES:
			printf("%s\t + Key type 3DES\n", indent);
			break;
		case KEY_INFORMATION_RESULT_3K3DES:
			printf("%s\t + Key type 3K3DES\n", indent);
			break;
		case KEY_INFORMATION_RESULT_AES:
			printf("%s\t + Key type AES\n", indent);
			break;
		default:
			printf("%s\t + Unknown key type\n", indent);
			break;
		}
		printf("%s\t + Key", indent);
		for(size_t j=0; j<ki[i].key_length; j++) {
			printf(" %02X", ki[i].key[j]);
		}
		printf("\n");
	}
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
	switch(ci->authentication_mode) {
	case MIFARE_DESFIRE_AUTHENTICATION_MODE_UNKNOWN:
		printf("\t + Unknown authentication\n");
		break;
	case MIFARE_DESFIRE_AUTHENTICATION_MODE_AES:
		printf("\t + AES authentication\n");
		break;
	case MIFARE_DESFIRE_AUTHENTICATION_MODE_DES:
		printf("\t + DES authentication\n");
		break;
	}
	if(ci->key_settings_retrieved) {
		print_key_settings(0, ci->key_settings);
	}
	print_keys(0, 1, &(ci->key_information));

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
			printf("\t\t + App has %i keys\n", ci->app[i].max_keys);
			break;
		case MIFARE_DESFIRE_AUTHENTICATION_MODE_DES:
			printf("\t\t + DES authentication\n");
			printf("\t\t + App has %i keys\n", ci->app[i].max_keys);
			break;
		}
		if(ci->app[i].key_settings_retrieved) {
			print_key_settings(1, ci->app[i].key_settings);
		}
		print_keys(1, ci->app[i].max_keys, ci->app[i].key_information);


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
			if(ci->app[i].file[j].file_contents_length > 0) {
				printf("\t\t\t + Read %zi bytes of data\n", ci->app[i].file[j].file_contents_length);
				for(size_t off = 0; off < ci->app[i].file[j].file_contents_length; off += 16) {
					printf("\t\t\t\t%04zX: ", off);
					for(size_t ind = 0; ind < 16; ind++) {
						if(off+ind >= ci->app[i].file[j].file_contents_length) {
							break;
						}
						printf(" %02X", ci->app[i].file[j].file_contents[off+ind]);
					}
					printf("    ");
					for(size_t ind = 0; ind < 16; ind++) {
						if(off+ind >= ci->app[i].file[j].file_contents_length) {
							break;
						}
						char c = ci->app[i].file[j].file_contents[off+ind];
						printf("%c", isprint(c)?c:',');
					}
					printf("\n");
				}
			}
		}
	}
}

static void free_information(struct mifare_desfire_card_information *ci)
{
	if(ci == NULL) {
		return;
	}

	for(size_t i=0; i<ARRAY_SIZE(ci->app); i++) {
		for(size_t j=0; j<ARRAY_SIZE(ci->app[i].file); j++) {
			if(ci->app[i].file[j].file_contents != NULL) {
				free(ci->app[i].file[j].file_contents);
			}
		}
	}

	if(ci->uid != NULL) {
		free(ci->uid);
	}
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [-B]\n"
			"Options:\n"
			"\t-B\tDo brute force on AIDs (may take a long time)\n\n", progname);
}

int main(int argc, char *argv[])
{
	int error = EXIT_SUCCESS;
	nfc_device *device = NULL;
	MifareTag *tags = NULL;
	bool do_brute = 0, do_exit=0;

	for(int opt; (opt = getopt(argc, argv, "B")) != -1; ) {
		switch(opt) {
		case 'B':
			do_brute = 1;
			break;
		case '?':
		default:
			usage(argv[0]);
			do_exit = 1;
			break;
		}
	}

	if(do_exit) {
		return 0;
	}

	if(optind < argc) {
		usage(argv[0]);
		return 0;
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

			analyze_tag(tags[i], &ci, do_brute);
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

