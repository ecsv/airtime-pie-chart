/*
 * Copyright 2002-2005, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
 * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
 * Copyright (C) 2013-2016 Sven Eckelmann <sven.eckelmann@open-mesh.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define _BSD_SOURCE
#include <endian.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <map>
#include <string.h>
#include <stdlib.h>

using namespace std;

/* config options (for debugging) */
//#define DETAILED_OUTPUT
//#define DETAILED_OUTPUT_EXTRA

struct radiotap_header {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
} __attribute__((__packed__));

struct ieee80211_hdr {
	uint16_t frame_control;
	uint16_t duration_id;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t seq_ctrl;
	uint8_t addr4[6];
} __attribute__ ((packed));

#define IEEE80211_FCTL_FTYPE 0x0c00
#define IEEE80211_FCTL_TODS 0x0001
#define IEEE80211_FCTL_FROMDS 0x0002
#define IEEE80211_FTYPE_DATA 0x0800

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

struct mac_key {
	uint8_t mac[6];
};

bool operator <(mac_key const& lhs, mac_key const& rhs)
{
	return (memcmp(lhs.mac, rhs.mac, 6) < 0);
}

struct speed_key {
	uint8_t is_rate;
	uint8_t rate;
	uint8_t flags;
	uint8_t mcs;
};

bool operator <(speed_key const& lhs, speed_key const& rhs)
{
	if (lhs.is_rate > rhs.is_rate)
		return true;
	if (lhs.is_rate < rhs.is_rate)
		return false;

	if (lhs.rate < rhs.rate)
		return true;
	if (lhs.rate > rhs.rate)
		return false;

	if (lhs.flags < rhs.flags)
		return true;
	if (lhs.flags > rhs.flags)
		return false;

	if (lhs.mcs < rhs.mcs)
		return true;
	if (lhs.mcs > rhs.mcs)
		return false;

	return false;
}

struct speed_value {
	size_t count;
	size_t duration;
};

struct mac_value {
	size_t count;
	map<speed_key, speed_value> speedmap;
};
map<mac_key, mac_value> macmap;

int ieee80211_frame_duration(size_t len,
			     int rate, int short_preamble)
{
	int dur, erp;

	/* calculate duration (in microseconds, rounded up to next higher
	 * integer if it includes a fractional microsecond) to send frame of
	 * len bytes (does not include FCS) at the given rate. Duration will
	 * also include SIFS.
	 *
	 * rate is in 100 kbps, so divident is multiplied by 10 in the
	 * DIV_ROUND_UP() operations.
	 */

	if (rate == 10 || rate == 20 || rate == 55 || rate == 110)
		erp = 0;
	else
		erp = 1;

	if (/*band == IEEE80211_BAND_5GHZ ||*/ erp) {
		/*
		 * OFDM:
		 *
		 * N_DBPS = DATARATE x 4
		 * N_SYM = Ceiling((16+8xLENGTH+6) / N_DBPS)
		 *	(16 = SIGNAL time, 6 = tail bits)
		 * TXTIME = T_PREAMBLE + T_SIGNAL + T_SYM x N_SYM + Signal Ext
		 *
		 * T_SYM = 4 usec
		 * 802.11a - 17.5.2: aSIFSTime = 16 usec
		 * 802.11g - 19.8.4: aSIFSTime = 10 usec +
		 *	signal ext = 6 usec
		 */
		dur = 16; /* SIFS + signal ext */
		dur += 16; /* 17.3.2.3: T_PREAMBLE = 16 usec */
		dur += 4; /* 17.3.2.3: T_SIGNAL = 4 usec */
		dur += 4 * DIV_ROUND_UP((16 + 8 * (len + 4) + 6) * 10,
					4 * rate); /* T_SYM x N_SYM */
	} else {
		/*
		 * 802.11b or 802.11g with 802.11b compatibility:
		 * 18.3.4: TXTIME = PreambleLength + PLCPHeaderTime +
		 * Ceiling(((LENGTH+PBCC)x8)/DATARATE). PBCC=0.
		 *
		 * 802.11 (DS): 15.3.3, 802.11b: 18.3.4
		 * aSIFSTime = 10 usec
		 * aPreambleLength = 144 usec or 72 usec with short preamble
		 * aPLCPHeaderLength = 48 usec or 24 usec with short preamble
		 */
		dur = 10; /* aSIFSTime = 10 usec */
		dur += short_preamble ? (72 + 24) : (144 + 48);

		dur += DIV_ROUND_UP(8 * (len + 4) * 10, rate);
	}

	return dur;
}

unsigned int mcs_index2rate(uint8_t mcs, uint8_t bw, int sgi)
{
	switch (mcs) {
	case 0:
		if (bw != 1) {
			if (!sgi)
				return 65;
			else
				return 72;
		} else {
			if (!sgi)
				return 135;
			else
				return 150;
		}
		break;
	case 1:
		if (bw != 1) {
			if (!sgi)
				return 130;
			else
				return 144;
		} else {
			if (!sgi)
				return 270;
			else
				return 300;
		}
		break;
	case 2:
		if (bw != 1) {
			if (!sgi)
				return 195;
			else
				return 217;
		} else {
			if (!sgi)
				return 405;
			else
				return 450;
		}
		break;
	case 3:
		if (bw != 1) {
			if (!sgi)
				return 260;
			else
				return 289;
		} else {
			if (!sgi)
				return 540;
			else
				return 600;
		}
		break;
	case 4:
		if (bw != 1) {
			if (!sgi)
				return 390;
			else
				return 433;
		} else {
			if (!sgi)
				return 810;
			else
				return 900;
		}
		break;
	case 5:
		if (bw != 1) {
			if (!sgi)
				return 520;
			else
				return 578;
		} else {
			if (!sgi)
				return 1080;
			else
				return 1200;
		}
		break;
	case 6:
		if (bw != 1) {
			if (!sgi)
				return 585;
			else
				return 650;
		} else {
			if (!sgi)
				return 1215;
			else
				return 1350;
		}
		break;
	case 7:
		if (bw != 1) {
			if (!sgi)
				return 650;
			else
				return 722;
		} else {
			if (!sgi)
				return 1350;
			else
				return 1500;
		}
		break;
	case 8:
		if (bw != 1) {
			if (!sgi)
				return 130;
			else
				return 144;
		} else {
			if (!sgi)
				return 270;
			else
				return 300;
		}
		break;
	case 9:
		if (bw != 1) {
			if (!sgi)
				return 260;
			else
				return 289;
		} else {
			if (!sgi)
				return 540;
			else
				return 600;
		}
		break;
	case 10:
		if (bw != 1) {
			if (!sgi)
				return 390;
			else
				return 433;
		} else {
			if (!sgi)
				return 810;
			else
				return 900;
		}
		break;
	case 11:
		if (bw != 1) {
			if (!sgi)
				return 520;
			else
				return 578;
		} else {
			if (!sgi)
				return 1080;
			else
				return 1200;
		}
		break;
	case 12:
		if (bw != 1) {
			if (!sgi)
				return 780;
			else
				return 867;
		} else {
			if (!sgi)
				return 1620;
			else
				return 1800;
		}
		break;
	case 13:
		if (bw != 1) {
			if (!sgi)
				return 1040;
			else
				return 1156;
		} else {
			if (!sgi)
				return 2160;
			else
				return 2400;
		}
		break;
	case 14:
		if (bw != 1) {
			if (!sgi)
				return 1170;
			else
				return 1300;
		} else {
			if (!sgi)
				return 2430;
			else
				return 2700;
		}
		break;
	case 15:
		if (bw != 1) {
			if (!sgi)
				return 1300;
			else
				return 1444;
		} else {
			if (!sgi)
				return 2700;
			else
				return 3000;
		}
		break;
	case 16:
		if (bw != 1) {
			if (!sgi)
				return 195;
			else
				return 217;
		} else {
			if (!sgi)
				return 405;
			else
				return 450;
		}
		break;
	case 17:
		if (bw != 1) {
			if (!sgi)
				return 390;
			else
				return 433;
		} else {
			if (!sgi)
				return 810;
			else
				return 900;
		}
		break;
	case 18:
		if (bw != 1) {
			if (!sgi)
				return 585;
			else
				return 650;
		} else {
			if (!sgi)
				return 1215;
			else
				return 1350;
		}
		break;
	case 19:
		if (bw != 1) {
			if (!sgi)
				return 780;
			else
				return 867;
		} else {
			if (!sgi)
				return 1620;
			else
				return 1800;
		}
		break;
	case 20:
		if (bw != 1) {
			if (!sgi)
				return 1170;
			else
				return 1300;
		} else {
			if (!sgi)
				return 2430;
			else
				return 2700;
		}
		break;
	case 21:
		if (bw != 1) {
			if (!sgi)
				return 1560;
			else
				return 1733;
		} else {
			if (!sgi)
				return 3240;
			else
				return 3600;
		}
		break;
	case 22:
		if (bw != 1) {
			if (!sgi)
				return 1755;
			else
				return 1950;
		} else {
			if (!sgi)
				return 3645;
			else
				return 4050;
		}
		break;
	case 23:
		if (bw != 1) {
			if (!sgi)
				return 1950;
			else
				return 2167;
		} else {
			if (!sgi)
				return 4050;
			else
				return 4500;
		}
		break;
	case 24:
		if (bw != 1) {
			if (!sgi)
				return 260;
			else
				return 288;
		} else {
			if (!sgi)
				return 540;
			else
				return 600;
		}
		break;
	case 25:
		if (bw != 1) {
			if (!sgi)
				return 520;
			else
				return 576;
		} else {
			if (!sgi)
				return 1080;
			else
				return 1200;
		}
		break;
	case 26:
		if (bw != 1) {
			if (!sgi)
				return 780;
			else
				return 868;
		} else {
			if (!sgi)
				return 1620;
			else
				return 1800;
		}
		break;
	case 27:
		if (bw != 1) {
			if (!sgi)
				return 1040;
			else
				return 1156;
		} else {
			if (!sgi)
				return 2160;
			else
				return 2400;
		}
		break;
	case 28:
		if (bw != 1) {
			if (!sgi)
				return 1560;
			else
				return 1732;
		} else {
			if (!sgi)
				return 3240;
			else
				return 3600;
		}
		break;
	case 29:
		if (bw != 1) {
			if (!sgi)
				return 2080;
			else
				return 2312;
		} else {
			if (!sgi)
				return 4320;
			else
				return 4800;
		}
		break;
	case 30:
		if (bw != 1) {
			if (!sgi)
				return 2340;
			else
				return 2600;
		} else {
			if (!sgi)
				return 4860;
			else
				return 5400;
		}
		break;
	case 31:
		if (bw != 1) {
			if (!sgi)
				return 2600;
			else
				return 2888;
		} else {
			if (!sgi)
				return 5400;
			else
				return 6000;
		}
		break;
	default:
		fprintf(stderr, "Unknown MCS %u\n", mcs);
	}

	fprintf(stderr, "Faiure decoding MCS %u, %u, %u\n", mcs, bw, sgi);
	return 0;
}

static void pcap_copy_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	size_t len = h->caplen;

	struct radiotap_header *radiotaphdr;
	const u_char *radiotap_bytes;
	size_t radiotap_len, radiotap_pos;
	struct ieee80211_hdr *wifihdr;
	uint16_t fc;
	struct mac_key dhost;
	struct mac_value value;
	map<mac_key, mac_value>::iterator it;
	map<speed_key, speed_value>::iterator it_speed;
	struct speed_key speed;
	struct speed_value speed_value;
	unsigned int i;
	int has_rate = 0, has_mcs = 0;
	int short_preamble;
	int duration;
	uint32_t extra_flags_field;
	size_t extra_flags_fields = 0;

	if (user)
		return;

	/* Radiotap header */
	if (len < sizeof(*radiotaphdr))
		return;

	radiotaphdr = (struct radiotap_header*)bytes;
	if (sizeof(*radiotaphdr) > le16toh(radiotaphdr->it_len))
		return;

	radiotap_bytes = bytes + sizeof(*radiotaphdr);
	radiotap_len = le16toh(radiotaphdr->it_len) - sizeof(*radiotaphdr);
	radiotap_pos = 0;

	len -= le16toh(radiotaphdr->it_len);
	bytes += le16toh(radiotaphdr->it_len);
	memset(&speed, 0, sizeof(speed));

	/* skip flags we cannot parse */
	extra_flags_field = le32toh(radiotaphdr->it_present);
	while (extra_flags_field & 0x80000000U) {
		if (radiotap_len < sizeof(extra_flags_field)) {
			fprintf(stderr, "Radiotap header is not long enough for extended flags\n");
			exit(1);
		}

		extra_flags_fields++;
		extra_flags_field = le32toh(*(uint32_t *)radiotap_bytes);
		radiotap_bytes += sizeof(extra_flags_field);
		radiotap_len -= sizeof(extra_flags_field);
	}

	/* Align to 64-bit */
	if (extra_flags_fields & 1) {
		if (radiotap_len < sizeof(extra_flags_field)) {
			fprintf(stderr, "Radiotap header is not long enough for extended flags alignment\n");
			exit(1);
		}
		radiotap_bytes += sizeof(extra_flags_field);
		radiotap_len -= sizeof(extra_flags_field);
	}

	/* parse this weird radiotap stuff until we got rate and mcs */
	for (i = 0; i < 20; i++) {
		if (!(le32toh(radiotaphdr->it_present) & (1u << i)))
			continue;

		unsigned int size = 0;
		unsigned int alignment = 1;
		unsigned int padding;

		switch (i) {
		case 0: /* TSF */
			size = 8;
			alignment = 8;
			break;
		case 1: /* Flags */
			size = 1;
			{
				padding = radiotap_pos % alignment;

				if (radiotap_len < (size + padding)) {
					fprintf(stderr, "Radiotap header is not long enough for rate information\n");
					exit(1);
				}
				short_preamble = radiotap_bytes[padding] & 0x2;
			}
			break;
		case 2: /* Rate */
			size = 1;
			{
				has_rate = 1;
				padding = radiotap_pos % alignment;

				if (radiotap_len < (size + padding)) {
					fprintf(stderr, "Radiotap header is not long enough for rate information\n");
					exit(1);
				}
				speed.is_rate = 1;
				speed.rate = radiotap_bytes[padding];
			}
			break;
		case 3: /* Channel */
			size = 4;
			alignment = 2;
			break;
		case 4: /* FHSS */
			size = 2;
			break;
		case 5: /* Antenna signal */
			size = 1;
			break;
		case 6: /* Antenna noise */
			size = 1;
			break;
		case 7: /* Lock quality */
			size = 2;
			alignment = 2;
			break;
		case 8: /* TX attenuation */
			size = 2;
			alignment = 2;
			break;
		case 9: /* dB TX attenuation */
			size = 2;
			alignment = 2;
			break;
		case 10: /* dB TX attenuation */
			size = 1;
			break;
		case 11: /* Antenna */
			size = 1;
			break;
		case 12: /* dB antenna signal */
			size = 1;
			break;
		case 13: /* dB antenna noise */
			size = 1;
			break;
		case 14: /* RX flags */
			size = 2;
			alignment = 2;
			break;
		case 15: /* TX flags */
			size = 2;
			alignment = 2;
			break;
		case 16: /* RTS retries */
			size = 1;
			alignment = 1;
			break;
		case 17: /* Data retries */
			size = 1;
			alignment = 1;
			break;
		case 19: /* MCS */
			size = 3;
			alignment = 1;

			{
				has_mcs = 1;
				padding = radiotap_pos % alignment;

				if (radiotap_len < (size + padding)) {
					fprintf(stderr, "Radiotap header is not long enough for mcs information\n");
					exit(1);
				}
				speed.is_rate = 0;
				speed.flags = radiotap_bytes[padding + 1] & 0x7;
				speed.mcs = radiotap_bytes[padding + 2];
				if ((radiotap_bytes[padding + 0] & 0x7) != 0x7) {
					fprintf(stderr, "Radiotap header has missing information about MCS, bandwidth or guard interval\n");
				}
			}
			break;
		default:
			fprintf(stderr, "Found radiotap present-flag without known decoding: %u\n", i);
			exit(1);
		}

		if (size > 0) {
			padding = radiotap_pos % alignment;

			if ((padding + size) > radiotap_len) {
				fprintf(stderr, "Radiotap is to short to process present-flag: %u\n", i);
				exit(1);
			}
			radiotap_pos += padding + size;
			radiotap_bytes += padding + size;
			radiotap_len -= padding + size;
		}
	}
	if ((has_rate && has_mcs) || (!has_rate && !has_mcs)) {
		fprintf(stderr, "Radiotap has incomplete or conflicting information about rate (%d) and mcs (%d)\n", has_rate, has_mcs);
		exit(1);
	}

	/* (802.11 data frame + LLC)  */
	if (len < sizeof(*wifihdr))
		return;

	wifihdr = (struct ieee80211_hdr*)bytes;
	fc = be16toh(wifihdr->frame_control);

	if ((fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_DATA)
		return;

	if (fc & IEEE80211_FCTL_TODS)
		memcpy(dhost.mac, wifihdr->addr3, 6);
	else
		memcpy(dhost.mac, wifihdr->addr1, 6);

	it = macmap.find(dhost);
	if (it == macmap.end()) {
		value.count = 1;
		macmap.insert(pair<mac_key, mac_value>(dhost, value));
		it = macmap.find(dhost);
	} else {
		it->second.count++;
	}

	if (it == macmap.end()) {
		fprintf(stderr, "Could not insert or find mac entry\n");
		exit(1);
	}

	if (has_rate) {
		duration = ieee80211_frame_duration(h->len - le16toh(radiotaphdr->it_len), speed.rate * 5, short_preamble);
	}

	if (has_mcs) {
		duration = ieee80211_frame_duration(h->len - le16toh(radiotaphdr->it_len), mcs_index2rate(speed.mcs, speed.flags & 0x3, speed.flags & 0x4), short_preamble);
	}

	it_speed = it->second.speedmap.find(speed);
	if (it_speed == it->second.speedmap.end()) {
		speed_value.count = 1;
		speed_value.duration = duration;
		it->second.speedmap.insert(pair<speed_key, struct speed_value>(speed, speed_value));
	} else {
		it_speed->second.count++;
		it_speed->second.duration += duration;
	}
}

void output_detailed(void)
{
	map<mac_key, mac_value>::iterator it;
	map<speed_key, speed_value>::iterator it_speed;

	for (it = macmap.begin(); it != macmap.end(); ++it) {
		size_t duration = 0;
		printf("%02x:%02x:%02x:%02x:%02x:%02x %zu\n", it->first.mac[0], it->first.mac[1], it->first.mac[2], it->first.mac[3], it->first.mac[4], it->first.mac[5], it->second.count);
		for (it_speed = it->second.speedmap.begin(); it_speed != it->second.speedmap.end(); ++it_speed) {
			duration += it_speed->second.duration;
#ifdef DETAILED_OUTPUT_EXTRA
			if (it_speed->first.is_rate) {
				printf("\trate: %uM: %zu (%zums)\n", it_speed->first.rate / 2, it_speed->second.count, it_speed->second.duration);
			} else {
				const char *bw;
				const char *gi;

				switch (it_speed->first.flags & 0x3) {
				case 0:
					bw = "20";
					break;
				case 1:
					bw = "40";
					break;
				case 2:
					bw = "20L";
					break;
				case 3:
					bw = "20U";
					break;
				}

				switch (it_speed->first.flags & 0x4) {
				case 0:
					gi = "LGI";
					break;
				case 4:
					gi = "SGI";
					break;
				}
				
				printf("\tmcs: %u, width: %s, GI: %s: %zu (%zums)\n", it_speed->first.mcs, bw, gi, it_speed->second.count, it_speed->second.duration);
			}
#endif
		}
		printf("\tduration: %zums\n", duration);
	}
}

void output_tabbed(void)
{
	map<mac_key, mac_value>::iterator it;
	map<speed_key, speed_value>::iterator it_speed;

	printf("node              msec\n");
	for (it = macmap.begin(); it != macmap.end(); ++it) {
		size_t duration = 0;
		for (it_speed = it->second.speedmap.begin(); it_speed != it->second.speedmap.end(); ++it_speed)
			duration += it_speed->second.duration;

		printf("%02x:%02x:%02x:%02x:%02x:%02x %zu\n", it->first.mac[0], it->first.mac[1], it->first.mac[2], it->first.mac[3], it->first.mac[4], it->first.mac[5], duration);
	}
}

int main(int argc, char *argv[])
{
	const char *prog = "bandwidth_slowclient_analyzer";
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p;

	if (argc != 2) {
		if (argc >= 1)
			prog = argv[0];
		fprintf(stderr, "USAGE: %s input.pcap\n", prog);
		return 1;
	}

	p = pcap_open_offline(argv[1], errbuf);
	if (!p) {
		fprintf(stderr, "Failed to open input: %s\n", errbuf);
		return 1;
	}

	pcap_loop(p, 0, pcap_copy_handler, NULL);
	pcap_close(p);

#ifdef DETAILED_OUTPUT
	output_detailed();
#else
	output_tabbed();
#endif
}
