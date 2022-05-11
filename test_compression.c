#include <stdint.h>
#include <stdio.h>

void compress(uint32_t* h0, uint32_t* h1, uint32_t* h2, uint32_t* h3,
		uint32_t* h4, uint32_t* h5, uint32_t* h6, uint32_t* h7,
		const uint32_t *w, const uint32_t *k,
		uint32_t *shift_buffer);

const uint32_t init_hash_224[8] = {
		0xc1059ed8,
		0x367cd507,
		0x3070dd17,
		0xf70e5939,
		0xffc00b31,
		0x68581511,
		0x64f98fa7,
		0xbefa4fa4
};

const uint32_t init_hash_256[8] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
};

const uint32_t k[64];

const uint32_t abc_msg_schedule[64] = {
		0x61626380, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000018,
		0x61626380, 0x000f0000, 0x7da86405, 0x600003c6,
		0x3e9d7b78, 0x0183fc00, 0x12dcbfdb, 0xe2e2c38e,
		0xc8215c1a, 0xb73679a2, 0xe5bc3909, 0x32663c5b,
		0x9d209d67, 0xec8726cb, 0x702138a4, 0xd3b7973b,
		0x93f5997f, 0x3b68ba73, 0xaff4ffc1, 0xf10a5c62,
		0x0a8b3996, 0x72af830a, 0x9409e33e, 0x24641522,
		0x9f47bf94, 0xf0a64f5a, 0x3e246a79, 0x27333ba3,
		0x0c4763f2, 0x840abf27, 0x7a290d5d, 0x065c43da,
		0xfb3e89cb, 0xcc7617db, 0xb9e66c34, 0xa9993667,
		0x84badedd, 0xc21462bc, 0x1487472c, 0xb20f7a99,
		0xef57b9cd, 0xebe6b238, 0x9fe3095e, 0x78bc8d4b,
		0xa43fcf15, 0x668b2ff8, 0xeeaba2cc, 0x12b1edeb
};

const uint32_t abc_expected_buffer_224[8] = {
		0xc693fc7a,
		0x13dfb889,
		0x55d1c760,
		0x7e730e00,
		0xfd89031b,
		0x55489ee6
};

const uint32_t abc_expected_digests_224[8] = {
		0x23097d22,
		0x2aadbce4
};

const uint32_t abc_expected_buffer_256[8] = {
		0xb85e2ce9,
		0x961f4894,
		0x04d24d6c,
		0x948d25b6,
		0xd39a2165,
		0xfb121210
};

const uint32_t abc_expected_digests_256[8] = {
		0xba7816bf,
		0xb00361a3
};

const uint32_t abcdbcd_msg_schedule[64] = {
		0x61626364, 0x62636465, 0x63646566, 0x64656667,
		0x65666768, 0x66676869, 0x6768696a, 0x68696a6b,
		0x696a6b6c, 0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f,
		0x6d6e6f70, 0x6e6f7071, 0x80000000, 0x00000000,
		0xeb8012ad, 0xa7c3ae92, 0x76e93ba2, 0xba42e743,
		0x92a92204, 0xd847e75e, 0x9e160036, 0xb280a7cb,
		0xddeb1516, 0xf36586f4, 0x969cd048, 0xe959d99d,
		0x6accc0ec, 0xf54cb098, 0x2af1b2da, 0xee59c4c9,
		0xa835e16a, 0x1dff4429, 0xd6e15959, 0xc397cd6e,
		0x6f1801ca, 0x21574205, 0x35ff7a84, 0x9743ee78,
		0xe44183e7, 0x0d09f00d, 0x9c89af54, 0x042d5bef,
		0x71f134d0, 0x0f94f463, 0x7e49dc63, 0x6f65c997,
		0x0b706583, 0x179312ca, 0x503054e9, 0xba125c39,
		0x7e9392c9, 0xd5cbaa1e, 0x78e0585d, 0xf6e7611c,
		0x8ac830ce, 0x8b47a303, 0xfd6e627f, 0x8c6e2c6a,
		0x4001adf1, 0x1a3dd097, 0xa9df6f62, 0x6aa60a39
};

const uint32_t abcdbcd_expected_buffer_224[8] = {
		0x3cd78fe1,
		0x3e1ca2f1,
		0x35f4bf1c,
		0xba1a8a1b,
		0x86795a7d,
		0x2ce11258
};

const uint32_t abcdbcd_expected_digests_224[8] = {
		0x8250e65d,
		0x10c8b7b0
};

const uint32_t abcdbcd_expected_buffer_256[8] = {
		0xbcfce922,
		0x962d8621,
		0xf6f443f8,
		0xacc75916,
		0x86126910,
		0x2fc08f85
};

const uint32_t abcdbcd_expected_digests_256[8] = {
		0x85e655d6,
		0x76e09589
};

const uint32_t kzvuijx_msg_schedule[64] = {
		0x6b7a7675, 0x696a7878, 0x63726d64, 0x6b73756b,
		0x6d6b6c66, 0x6c687570, 0x7a756a7a, 0x61667964,
		0x65717177, 0x6a6f6f72, 0x646d6e6e, 0x76706774,
		0x73786970, 0x6b7a7278, 0x6e616467, 0x626b616e,
		0xd8702a31, 0x0a4c0030, 0xf12df2af, 0x79769658,
		0x102df20b, 0x15e8210d, 0x7ed8c8de, 0x0cb20b66,
		0x1f6e61d7, 0x2c593b78, 0xdabaae44, 0x364c408a,
		0xed648393, 0x2cb64031, 0x55666480, 0xdc21f4b0,
		0x64dff9c4, 0xe76c4658, 0x4587ddfd, 0x7b60efe3,
		0x630a2ed9, 0x5672c7b0, 0xfd00c353, 0xe2749992,
		0x3be5074e, 0x8b17e001, 0x7be35ef9, 0xc00b42a0,
		0x0058a548, 0x86119358, 0x84f85e97, 0x8e112da8,
		0xd1655055, 0x1bd71d37, 0xfa092f62, 0x1e0639c5,
		0x770e0b24, 0x3fd7ba40, 0x6fec2a7b, 0xb91abc04,
		0xd299f68b, 0xb9038ffe, 0xe8b31cf3, 0xa6a1befb,
		0xf32635d9, 0x06bbe80f, 0x26324d7f, 0xcf4e0696
};

const uint32_t kzvuijx_expected_buffer_224[8] = {
		0xe4b82497,
		0x1ded8910,
		0x543af394,
		0x12e1b6b8,
		0x4ece72a0,
		0x9e08aa8f
};

const uint32_t kzvuijx_expected_digests_224[8] = {
		0xacfa6946,
		0x3ec7231f
};

const uint32_t kzvuijx_expected_buffer_256[8] = {
		0xcd720f86,
		0x07399ee1,
		0x35b1de18,
		0xfc5d9029,
		0xee626b25,
		0x00cad1bd
};

const uint32_t kzvuijx_expected_digests_256[8] = {
		0xafeaa1ae,
		0x3570eed8
};


void test_compression(char* desc, const uint32_t* init_vals, const uint32_t* w,
		const uint32_t* k, const uint32_t* expected_buffer,
		const uint32_t* expected_digests) {
	printf("\nTEST: %s\n", desc);

	uint32_t hash_vals[8] = {
			init_vals[0],
			init_vals[1],
			init_vals[2],
			init_vals[3],
			init_vals[4],
			init_vals[5],
			init_vals[6],
			init_vals[7],
	};

	uint32_t shift_buffer[6];

	compress(&hash_vals[0], &hash_vals[1], &hash_vals[2], &hash_vals[3],
			&hash_vals[4], &hash_vals[5], &hash_vals[6], &hash_vals[7],
			w, k, shift_buffer);

	printf("Actual shift buffer:   %08x %08x %08x %08x %08x %08x\n",
			shift_buffer[0], shift_buffer[1], shift_buffer[2],
			shift_buffer[3], shift_buffer[4], shift_buffer[5]
	);
	printf("Expected shift buffer: %08x %08x %08x %08x %08x %08x\n",
			expected_buffer[0], expected_buffer[1],
			expected_buffer[2], expected_buffer[3],
			expected_buffer[4], expected_buffer[5]
	);
	printf("Actual digest values:   %08x %08x\n",
			hash_vals[0], hash_vals[4]
	);
	printf("Expected digest values: %08x %08x\n",
			expected_digests[0],
			expected_digests[1]
	);
}

int main_compression() {
	printf("\n"
			"===============================================================\n"
			"SHA-224\n"
			"===============================================================\n");
	test_compression("short (abc)",
			init_hash_224, abc_msg_schedule, k,
			abc_expected_buffer_224, abc_expected_digests_224
	);
	test_compression("shorter than block "
			"(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
			init_hash_224, abcdbcd_msg_schedule, k,
			abcdbcd_expected_buffer_224, abcdbcd_expected_digests_224
	);
	test_compression("as long as block "
			"(kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan)",
			init_hash_224, kzvuijx_msg_schedule, k,
			kzvuijx_expected_buffer_224, kzvuijx_expected_digests_224
	);

	printf("\n"
			"===============================================================\n"
			"SHA-256\n"
			"===============================================================\n");
	test_compression("short (abc)",
			init_hash_256, abc_msg_schedule, k,
			abc_expected_buffer_256, abc_expected_digests_256
	);
	test_compression("shorter than block "
			"(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
			init_hash_256, abcdbcd_msg_schedule, k,
			abcdbcd_expected_buffer_256, abcdbcd_expected_digests_256
	);
	test_compression("as long as block "
			"(kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan)",
			init_hash_256, kzvuijx_msg_schedule, k,
			kzvuijx_expected_buffer_256, kzvuijx_expected_digests_256
	);

	return 0;
}
