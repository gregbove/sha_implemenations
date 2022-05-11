#include <stdio.h>
#include <stdint.h>

uint64_t strlength(const char *str);
void create_message_schedule(char *input, uint32_t *out);
void print_hex(char *str, uint64_t chars);

typedef struct preprocessed_msg_t {
	char overflow[64 * 2];
	uint64_t regular_blocks;
	uint64_t overflow_blocks;
} preprocessed_msg_t;

void preprocess(const char *message, const uint64_t msg_bytes,
		preprocessed_msg_t *out);

const uint32_t abc_expected_msg_schedule[64] = { 0x61626380, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000018, 0x61626380, 0x000f0000, 0x7da86405, 0x600003c6,
		0x3e9d7b78, 0x0183fc00, 0x12dcbfdb, 0xe2e2c38e, 0xc8215c1a, 0xb73679a2,
		0xe5bc3909, 0x32663c5b, 0x9d209d67, 0xec8726cb, 0x702138a4, 0xd3b7973b,
		0x93f5997f, 0x3b68ba73, 0xaff4ffc1, 0xf10a5c62, 0x0a8b3996, 0x72af830a,
		0x9409e33e, 0x24641522, 0x9f47bf94, 0xf0a64f5a, 0x3e246a79, 0x27333ba3,
		0x0c4763f2, 0x840abf27, 0x7a290d5d, 0x065c43da, 0xfb3e89cb, 0xcc7617db,
		0xb9e66c34, 0xa9993667, 0x84badedd, 0xc21462bc, 0x1487472c, 0xb20f7a99,
		0xef57b9cd, 0xebe6b238, 0x9fe3095e, 0x78bc8d4b, 0xa43fcf15, 0x668b2ff8,
		0xeeaba2cc, 0x12b1edeb };

const uint32_t abcdbcd_expected_msg_schedule[64] = { 0x61626364, 0x62636465,
		0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696a, 0x68696a6b,
		0x696a6b6c, 0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d6e6f70, 0x6e6f7071,
		0x80000000, 0x00000000, 0xeb8012ad, 0xa7c3ae92, 0x76e93ba2, 0xba42e743,
		0x92a92204, 0xd847e75e, 0x9e160036, 0xb280a7cb, 0xddeb1516, 0xf36586f4,
		0x969cd048, 0xe959d99d, 0x6accc0ec, 0xf54cb098, 0x2af1b2da, 0xee59c4c9,
		0xa835e16a, 0x1dff4429, 0xd6e15959, 0xc397cd6e, 0x6f1801ca, 0x21574205,
		0x35ff7a84, 0x9743ee78, 0xe44183e7, 0x0d09f00d, 0x9c89af54, 0x042d5bef,
		0x71f134d0, 0x0f94f463, 0x7e49dc63, 0x6f65c997, 0x0b706583, 0x179312ca,
		0x503054e9, 0xba125c39, 0x7e9392c9, 0xd5cbaa1e, 0x78e0585d, 0xf6e7611c,
		0x8ac830ce, 0x8b47a303, 0xfd6e627f, 0x8c6e2c6a, 0x4001adf1, 0x1a3dd097,
		0xa9df6f62, 0x6aa60a39 };

const uint32_t kzvuijx_expected_msg_schedule[64] = { 0x6b7a7675, 0x696a7878,
		0x63726d64, 0x6b73756b, 0x6d6b6c66, 0x6c687570, 0x7a756a7a, 0x61667964,
		0x65717177, 0x6a6f6f72, 0x646d6e6e, 0x76706774, 0x73786970, 0x6b7a7278,
		0x6e616467, 0x626b616e, 0xd8702a31, 0x0a4c0030, 0xf12df2af, 0x79769658,
		0x102df20b, 0x15e8210d, 0x7ed8c8de, 0x0cb20b66, 0x1f6e61d7, 0x2c593b78,
		0xdabaae44, 0x364c408a, 0xed648393, 0x2cb64031, 0x55666480, 0xdc21f4b0,
		0x64dff9c4, 0xe76c4658, 0x4587ddfd, 0x7b60efe3, 0x630a2ed9, 0x5672c7b0,
		0xfd00c353, 0xe2749992, 0x3be5074e, 0x8b17e001, 0x7be35ef9, 0xc00b42a0,
		0x0058a548, 0x86119358, 0x84f85e97, 0x8e112da8, 0xd1655055, 0x1bd71d37,
		0xfa092f62, 0x1e0639c5, 0x770e0b24, 0x3fd7ba40, 0x6fec2a7b, 0xb91abc04,
		0xd299f68b, 0xb9038ffe, 0xe8b31cf3, 0xa6a1befb, 0xf32635d9, 0x06bbe80f,
		0x26324d7f, 0xcf4e0696 };

void print_int_in_hex(const uint32_t *str) {
	for (int i = 0; i < 64; i++) { //up to the 64th index in w
		printf("%08x ", str[i]);
	}
}

int test_creation(const char *testing, char *message,
		const uint32_t *expected) {
	uint32_t result[64];

	preprocessed_msg_t preproc = { .overflow = { 0 } };
	preprocess(message, strlength(message), &preproc);

	printf("\nTEST: %s\n", testing);
	uint64_t msg_length = strlength(message);
	printf("Hex before: ");
	print_hex(message + msg_length - msg_length % 64, msg_length % 64);
	printf("\n");
	printf("Actual:     ");

	char* preproc_msg_buf;
	if (preproc.regular_blocks > 0) {
		preproc_msg_buf = message;
	} else {
		preproc_msg_buf = preproc.overflow;
	}

	create_message_schedule(preproc_msg_buf, result);
	print_int_in_hex(result);
	printf("\n");
	printf("Expected:   ");
	print_int_in_hex(expected);
	printf("\n");
	return 0;
}

int main_ms() {
	test_creation("short message", "abc",
			abc_expected_msg_schedule);
	test_creation("longer message shorter than block",
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			 abcdbcd_expected_msg_schedule);
	test_creation(
			"message same as block size",
			"kzvuijxxcrmdksukmklflhupzujzafydeqqwjoordmnnvpgtsxipkzrxnadgbkan",
			kzvuijx_expected_msg_schedule);
	return 0;
}
