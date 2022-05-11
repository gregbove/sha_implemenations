#include <stdint.h>
#include <stdio.h>
#include <stdbool.h> 

void concat_digests(const uint32_t h0, const uint32_t h1, const uint32_t h2,
		const uint32_t h3, const uint32_t h4, const uint32_t h5,
		const uint32_t h6, const uint32_t h7, bool sha_256, char *output);

const uint32_t abc_digests_224[8] = {
		0x23097d22,
		0x3405d822,
		0x8642a477,
		0xbda255b3,
		0x2aadbce4,
		0xbda0b3f7,
		0xe36c9da7,
		0xd2da082d
};

const uint32_t abc_digests_256[8] = {
		0xba7816bf,
		0x8f01cfea,
		0x414140de,
		0x5dae2223,
		0xb00361a3,
		0x96177a9c,
		0xb410ff61,
		0xf20015ad
};

const uint32_t abcdbcd_digests_224[8] = {
		0x8250e65d,
		0xbcf62f84,
		0x66659c33,
		0x33e5e91a,
		0x10c8b7b0,
		0x95392769,
		0x1f1419c2,
		0xfd16f295
};

const uint32_t abcdbcd_digests_256[8] = {
		0x85e655d6,
		0x417a1795,
		0x3363376a,
		0x624cde5c,
		0x76e09589,
		0xcac5f811,
		0xcc4b32c1,
		0xf20e533a
};

const uint32_t kzvuijx_digests_224[8] = {
		0xacfa6946,
		0x854b47a7,
		0x84abd0ab,
		0xdbc67dd0,
		0x3ec7231f,
		0x660bfa0,
		0x77db465f,
		0xdce7d8b4
};

const uint32_t kzvuijx_digests_256[8] = {
		0xafeaa1ae,
		0xa9ca19aa,
		0x7220d18a,
		0x72c204c0,
		0x3570eed8,
		0x9bd03a49,
		0x1be169d4,
		0x631a6bfa
};

void test_concat(char* desc, bool sha_256, const uint32_t* digests) {
	printf("\nTEST: %s\n", desc);

	char output[64] = {0};
	concat_digests(digests[0], digests[1], digests[2], digests[3],
			digests[4], digests[5], digests[6], digests[7], sha_256, output);

	/* Print 8 digests--make sure the function does not assign
	 * past the buffer. */
	printf("Actual:   ");
	for (int i = 0; i < 256 / 8; i++) {
		printf("%02x", output[i] & 0xff);
	}
	printf("\n");
	printf("Expected: ");
	int num_digests = sha_256 ? 8 : 7;
	for (int j = 0; j < num_digests; j++) {
		printf("%08x", digests[j]);
	}
	printf("\n");
}

int main_concat() {
	printf("\n"
			"===============================================================\n"
			"SHA-224\n"
			"===============================================================\n");
	test_concat("message 1 (abc)",
			false, abc_digests_224
	);
	test_concat("message 2 "
			"(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
			false, abcdbcd_digests_224
	);
	test_concat("message 3 "
			"(kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan)",
			false, kzvuijx_digests_224
	);

	printf("\n"
			"===============================================================\n"
			"SHA-256\n"
			"===============================================================\n");
	test_concat("message 1 (abc)",
			true, abc_digests_256
	);
	test_concat("message 2 "
			"(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
			true, abcdbcd_digests_256
	);
	test_concat("message 3 "
			"(kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan)",
			true, kzvuijx_digests_256
	);

	return 0;
}
