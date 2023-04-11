/*
	r4 encrypt/decrypt

	Copyright (C) 2013 Taiju Yamada (Xenon++)
	Copyright (C) 2023 lifehackerhansol

	SPDX-License-Identifier: 0BSD

*/


#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>
#include <limits.h>
#include <unistd.h>

static void r4_crypt(unsigned short k, int fcrypt, int n, unsigned char *p){
	unsigned char xor;
	unsigned short key = n ^ k;
	unsigned int x, y;
	for(unsigned int i = 0; i < 0x200; i++) {
		xor = (key & 3) | ((key >> 4) & 0x0c) | ((key >> 5) & 0x10) | ((key >> 6) & 0x60) | ((key >> 7) & 0x80);
		if(fcrypt) p[i] ^= xor;
		x = y = ((p[i] << 8) ^ key) << 16;
		if(!fcrypt) p[i] ^= xor;
		for(int j=1; j < 32; j++) x ^= y >> j;
		key  = (x >> 25) & 0x0003;
		key ^= (x >> 22) & 0x0300;
		key ^= (x >>  8) & 0x8000;
		key ^= (y >> 24) & 0x0003;
		key ^= (y >> 23) & 0x00fc;
		key ^= (y >> 22) & 0x00fc;
		key ^= (y >>  8) & 0x7f00;
	}
}

static unsigned short r4_bruteforce(FILE *in){
	unsigned char p[512],q[512];
	fseek(in, 0, SEEK_SET);
	fread(p,1,512,in);
	unsigned short key = 0;
	
	printf("Finding key...\n");
	for(;key<0xFFFF;key++){
		memcpy(q,p,512);
		r4_crypt(key,0,0,q);
		if(!memcmp(&q[12], "####",4)) {
			break;
		}
	}
	printf("Key: 0x%04x\n",key);
	return key;
}

static void r4_process(int key, int fcrypt, FILE *in, FILE *out){
	unsigned char p[512];
	int r, n=0, s1=0;
	fseek(in, 0, SEEK_END);
	int s2=ftell(in);
	fseek(in, 0, SEEK_SET);
	fseek(out, 0, SEEK_SET);
	for(int i=0; i<=s2; i+=512) {
		r=fread(p,1,512,in);
		r4_crypt(key,fcrypt,n++,p);
		s1+=r;
		fprintf(stderr,"%s %8d / %8d\r",fcrypt?"Encrypting":"Decrypting",s1,s2);
		fwrite(p,1,r,out);
	}
	fprintf(stderr,"%s %8d / %8d Done.\n",fcrypt?"Encrypting":"Decrypting",s2,s2);
}

void print_help(const char* argv0) {
	printf("Usage:\n");
	printf("Decrypt:  %s -d in out\n", argv0);
	printf("Encrypt:  %s -e in out\n", argv0);
	printf("Find key: %s -f in out\n", argv0);
	printf("\n");
	printf("Optional: specify -k <hex> to {en,de}crypt with a custom key\n");
}

int main(int argc, char** argv) {
	printf("r4crypt2\n\n");

	bool bruteForceKey = false;

	// default to the OG R4 key.
	// There is one other known key, which is the R4 i.L.S. key, 0x4002
	unsigned short key = 0x484a;
	int fcrypt = -1;

    static struct option long_options[] = {
		{"decrypt", no_argument,       0, 'd'},
		{"encrypt", no_argument,       0, 'e'},
		{"find",    no_argument,       0, 'f'},
		{"key",     required_argument, 0, 'k'},
		{0, 0, 0, 0}
	};
	int opt;
	if(argc < 4) {
		print_help(argv[0]);
		return -1;
	}
    while ((opt = getopt_long(argc, argv, "defk:x", long_options, NULL)) != -1) {
        switch (opt) {
			case 'd':
				fcrypt = 0;
				break;
			case 'e':
				fcrypt = 1;
				break;
        	case 'f':
				bruteForceKey = true;
				fcrypt = 0;
				break;
        	case 'k':
				key = (unsigned short)strtoul(optarg, NULL, 0);
				break;
			default:
				print_help(argv[0]);
				return -1;
        }
    }
	char ins[PATH_MAX];
	char outs[PATH_MAX];
	sprintf(ins, "%s", argv[argc-2]);
	sprintf(outs, "%s", argv[argc-1]);
	if(strlen(ins) < 4) {
		fprintf(stderr, "Bad input file name\n");
		return -1;
	}
	if(strlen(outs) < 4) {
		fprintf(stderr, "Bad output file name\n");
		return -1;
	}

	if(fcrypt == 0 && strcasecmp(ins+strlen(ins)-4, ".dat")) {
		fprintf(stderr, "Decryption input file does not end with .dat\n");
		return -1;
	} else if(fcrypt == 1 && strcasecmp(ins+strlen(ins)-4, ".nds")) {
		fprintf(stderr, "Encryption input file does not end with .nds\n");
		return -1;
	}
	FILE* inf = fopen(ins, "rb");
	if(!inf) {
		fclose(inf);
		fprintf(stderr, "Cannot open input file\n");
		return -1;
	}
	FILE* outf = fopen(outs, "wb");
	if(!outf) {
		fclose(outf);
		fprintf(stderr, "Cannot open output file\n");
		return -1;
	}
	if(bruteForceKey) {
		key = r4_bruteforce(inf);
		fseek(inf, 0, SEEK_SET);
	}
	r4_process(key, fcrypt, inf, outf);
	fclose(inf);
	fclose(outf);
	return 0;
}
