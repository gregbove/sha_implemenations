#include <stdio.h>
#include <stdint.h>

typedef struct preprocessed_msg_t {
	char overflow[64 * 2];
	uint64_t regular_blocks;
	uint64_t overflow_blocks;
} preprocessed_msg_t;

// Edited to take msg_length as a parameter
void preprocess(const char* message, uint64_t msg_length, preprocessed_msg_t* out);

void print_hex(char* str, uint64_t chars) {
	for (uint64_t i = 0; i < chars; i++) {
		printf("%02x", str[i] & 0xff);
	}
}

// int test_message(char* desc, char* message) {
int test_message(char* desc, char* message, uint64_t msg_length) {
	printf("\nTEST: %s\n", desc);
	preprocessed_msg_t preproc = { .overflow = {0} };
	// preprocess(message, &preproc);
	preprocess(message, msg_length, &preproc);

	printf("Regular blocks:  %lld\n", preproc.regular_blocks);
	printf("Overflow blocks: %lld\n", preproc.overflow_blocks);
	printf("Message End:   ");
	// uint64_t msg_length = strlength(message); // NO LONGER NEEDED 
	print_hex(message + msg_length - msg_length % 64, msg_length % 64);
	printf("\n");
	printf("Overflow Buf:  ");
	print_hex(preproc.overflow, 64);
	printf("\n");
	printf("Overflow2 Buf: ");
	print_hex(preproc.overflow + 64, 64);
	printf("\n");
	printf("Message Length (Bytes): %lld\n", msg_length);
	printf("Message Length (Bits):  0x%llx\n", msg_length * 8);

	return 0;
}


int main_preproc() {
	test_message("message does not fill block", "hello world", 11);
	test_message("message is multiple of block size",
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678",
			512);
	test_message("message isn't multiple of block size + not enough room for all of length",
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"123456781234567812345678123456781234567812345678123456781234567",
			511);
	test_message("message isn't multiple of block size + not enough room for part of length",
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"12345678123456781234567812345678123456781234567812345678123456",
			510);
	test_message("message isn't multiple of block size + room for length",
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567812345678"
			"1234567812345678123456781234567812345678123456781234567",
			503);
	return 0;
}
