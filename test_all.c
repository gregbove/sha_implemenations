#include <stdio.h>

void print_fxn_label(char* label) {
	printf("\n\n"
			"###############################################################\n"
			"%s\n"
			"###############################################################"
			"\n", label);
}

int main() {
	print_fxn_label("Final Hash");
	main_final_hash();

	print_fxn_label("Preprocessing");
	main_preproc();

	print_fxn_label("Initialize Hash Values");
	main_sha_choice();

	print_fxn_label("Message Schedule");
	main_ms();

	print_fxn_label("Compression");
	main_compression();

	print_fxn_label("Modify Final Vals");
	main_modify_final_vals();

	print_fxn_label("Concatenate Final Vals");
	main_concat();

	return 0;
}
