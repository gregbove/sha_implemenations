#include <stdint.h>
#include <stdio.h>

void modify_final_vals(uint32_t* h1, uint32_t* h2, uint32_t* h3, uint32_t* h5,
		uint32_t* h6, uint32_t* h7, const uint32_t *shift_buffer);
 
uint32_t abc_original_digests_224[8] = {
		0x23097d22,
		0x367cd507,
		0x3070dd17,
		0xf70e5939,
		0x2aadbce4,
		0x68581511,
		0x64f98fa7,
		0xbefa4fa4
};

const uint32_t abc_buffer_224[8] = {
		0xc693fc7a,
		0x13dfb889,
		0x55d1c760,
		0x7e730e00,
		0xfd89031b,
		0x55489ee6
};

const uint32_t abc_all_expected_digests_224[8] = {
		0x23097d22,
		0x3405d822,
		0x8642a477,
		0xbda255b3,
		0x2aadbce4,
		0xbda0b3f7,
		0xe36c9da7,
		0xd2da082d
};

uint32_t abc_original_digests_256[8] = {
		0xba7816bf,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0xb00361a3,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
};

const uint32_t abc_buffer_256[8] = {
		0xb85e2ce9,
		0x961f4894,
		0x04d24d6c,
		0x948d25b6,
		0xd39a2165,
		0xfb121210
};

const uint32_t abc_all_expected_digests_256[8] = {
		0xba7816bf,
		0x8f01cfea,
		0x414140de,
		0x5dae2223,
		0xb00361a3,
		0x96177a9c,
		0xb410ff61,
		0xf20015ad
};

uint32_t abcdbcd_original_digests_224[8] = {
		0x8250e65d,
		0x367cd507,
		0x3070dd17,
		0xf70e5939,
		0x10c8b7b0,
		0x68581511,
		0x64f98fa7,
		0xbefa4fa4
};

const uint32_t abcdbcd_buffer_224[8] = {
		0x3cd78fe1,
		0x3e1ca2f1,
		0x35f4bf1c,
		0xba1a8a1b,
		0x86795a7d,
		0x2ce11258
};

const uint32_t abcdbcd_all_expected_digests_224[8] = {
		0x8250e65d,
		0xbcf62f84,
		0x66659c33,
		0x33e5e91a,
		0x10c8b7b0,
		0x95392769,
		0x1f1419c2,
		0xfd16f295
};

uint32_t abcdbcd_original_digests_256[8] = {
		0x85e655d6,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x76e09589,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
};

const uint32_t abcdbcd_buffer_256[8] = {
		0xbcfce922,
		0x962d8621,
		0xf6f443f8,
		0xacc75916,
		0x86126910,
		0x2fc08f85
};

const uint32_t abcdbcd_all_expected_digests_256[8] = {
		0x85e655d6,
		0x417a1795,
		0x3363376a,
		0x624cde5c,
		0x76e09589,
		0xcac5f811,
		0xcc4b32c1,
		0xf20e533a
};

uint32_t kzvuijx_original_digests_224[8] = {
		0xacfa6946,
		0x367cd507,
		0x3070dd17,
		0xf70e5939,
		0x3ec7231f,
		0x68581511,
		0x64f98fa7,
		0xbefa4fa4
};

const uint32_t kzvuijx_buffer_224[8] = {
		0xe4b82497,
		0x1ded8910,
		0x543af394,
		0x12e1b6b8,
		0x4ece72a0,
		0x9e08aa8f
};

const uint32_t kzvuijx_all_expected_digests_224[8] = {
		0xacfa6946,
		0x854b47a7,
		0x84abd0ab,
		0xdbc67dd0,
		0x3ec7231f,
		0x660bfa0,
		0x77db465f,
		0xdce7d8b4
};

uint32_t kzvuijx_original_digests_256[8] = {
		0xafeaa1ae,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x3570eed8,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
};

const uint32_t kzvuijx_buffer_256[8] = {
		0xcd720f86,
		0x07399ee1,
		0x35b1de18,
		0xfc5d9029,
		0xee626b25,
		0x00cad1bd
};

const uint32_t kzvuijx_all_expected_digests_256[8] = {
		0xafeaa1ae,
		0xa9ca19aa,
		0x7220d18a,
		0x72c204c0,
		0x3570eed8,
		0x9bd03a49,
		0x1be169d4,
		0x631a6bfa
};

void test_modify_final_vals(char* desc, uint32_t* original_digests,
		const uint32_t* shift_buffer, const uint32_t* _all_expected_digests) {
	printf("\nTEST: %s\n", desc);

	modify_final_vals(
			&original_digests[1],
			&original_digests[2],
			&original_digests[3],
			&original_digests[5],
			&original_digests[6],
			&original_digests[7],
			shift_buffer
	);

	printf("Actual digest values:   %08x %08x %08x %08x %08x %08x %08x %08x\n",
			original_digests[0],
			original_digests[1],
			original_digests[2],
			original_digests[3],
			original_digests[4],
			original_digests[5],
			original_digests[6],
			original_digests[7]
	);
	printf("Expected digest values: %08x %08x %08x %08x %08x %08x %08x %08x\n",
			_all_expected_digests[0],
			_all_expected_digests[1],
			_all_expected_digests[2],
			_all_expected_digests[3],
			_all_expected_digests[4],
			_all_expected_digests[5],
			_all_expected_digests[6],
			_all_expected_digests[7]
	);
}

int main_modify_final_vals() {
	printf("\n"
			"===============================================================\n"
			"SHA-224\n"
			"===============================================================\n");
	test_modify_final_vals("buffer 1 (abc)",
			abc_original_digests_224,
			abc_buffer_224, abc_all_expected_digests_224
	);
	test_modify_final_vals("buffer 2 "
			"(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
			abcdbcd_original_digests_224,
			abcdbcd_buffer_224, abcdbcd_all_expected_digests_224
	);
	test_modify_final_vals("buffer 3 "
			"(kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan)",
			kzvuijx_original_digests_224,
			kzvuijx_buffer_224, kzvuijx_all_expected_digests_224
	);

	printf("\n"
			"===============================================================\n"
			"SHA-256\n"
			"===============================================================\n");
	test_modify_final_vals("buffer 1 (abc)",
			abc_original_digests_256,
			abc_buffer_256, abc_all_expected_digests_256
	);
	test_modify_final_vals("buffer 2 "
			"(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)",
			abcdbcd_original_digests_256,
			abcdbcd_buffer_256, abcdbcd_all_expected_digests_256
	);
	test_modify_final_vals("buffer 3 "
			"(kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan)",
			kzvuijx_original_digests_256,
			kzvuijx_buffer_256, kzvuijx_all_expected_digests_256
	);

	return 0;
}
