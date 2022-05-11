#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

void sha_choice(bool sha_256, uint32_t* h0, uint32_t* h1, uint32_t* h2,
		uint32_t* h3, uint32_t* h4, uint32_t* h5, uint32_t* h6, uint32_t* h7);

const uint32_t expected_init_hash_224[8] = {
		0xc1059ed8,
		0x367cd507,
		0x3070dd17,
		0xf70e5939,
		0xffc00b31,
		0x68581511,
		0x64f98fa7, 
		0xbefa4fa4
};

const uint32_t expected_init_hash_256[8] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
};


int main_sha_choice() {
	printf("\n"
			"===============================================================\n"
			"SHA-224\n"
			"===============================================================\n");
	uint32_t init_hash_224[8];

	sha_choice(false, &init_hash_224[0], &init_hash_224[1], &init_hash_224[2],
			&init_hash_224[3], &init_hash_224[4], &init_hash_224[5],
			&init_hash_224[6], &init_hash_224[7]);
	printf("Actual values:   %08x %08x %08x %08x %08x %08x %08x %08x\n",
			init_hash_224[0], init_hash_224[1],
			init_hash_224[2], init_hash_224[3],
			init_hash_224[4], init_hash_224[5],
			init_hash_224[6], init_hash_224[7]
	);
	printf("Expected values: %08x %08x %08x %08x %08x %08x %08x %08x\n",
			expected_init_hash_224[0], expected_init_hash_224[1],
			expected_init_hash_224[2], expected_init_hash_224[3],
			expected_init_hash_224[4], expected_init_hash_224[5],
			expected_init_hash_224[6], expected_init_hash_224[7]
	);

	printf("\n"
			"===============================================================\n"
			"SHA-256\n"
			"===============================================================\n");
	uint32_t init_hash_256[8];
	sha_choice(true, &init_hash_256[0], &init_hash_256[1], &init_hash_256[2],
			&init_hash_256[3], &init_hash_256[4], &init_hash_256[5],
			&init_hash_256[6], &init_hash_256[7]);
	printf("Actual values:   %08x %08x %08x %08x %08x %08x %08x %08x\n",
			init_hash_256[0], init_hash_256[1],
			init_hash_256[2], init_hash_256[3],
			init_hash_256[4], init_hash_256[5],
			init_hash_256[6], init_hash_256[7]
	);
	printf("Expected values: %08x %08x %08x %08x %08x %08x %08x %08x\n",
			expected_init_hash_256[0], expected_init_hash_256[1],
			expected_init_hash_256[2], expected_init_hash_256[3],
			expected_init_hash_256[4], expected_init_hash_256[5],
			expected_init_hash_256[6], expected_init_hash_256[7]
	);
	return 0;
}
