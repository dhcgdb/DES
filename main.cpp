#include "main.h"

int main(int argc, char** argv) {
	src_file.open("C:\\Users\\Norton\\Desktop\\k.dat", ios::binary | ios::in);
	des_file.open("C:\\Users\\Norton\\Desktop\\k.dat.encrypt", ios::binary | ios::out);

	char flag, i, j;
	char seg_p[8];
	char seg_out[8];
	char round_key[16][8] = { 0 };
	uint32_t* seg_p_l, * seg_p_r, seg_tmp;
	char* seg_p_r_ptr;

	key_gen(round_key);
	while (input_replace(seg_p)) {
		seg_p_l = (uint32_t*)seg_p;
		seg_p_r = (uint32_t*)(seg_p + 4);
		seg_p_r_ptr = seg_p + 4;

		for (int i = 0; i < 16; i++) {
			seg_tmp = *seg_p_r;
			round_func(seg_p_r_ptr, round_key[i]);
			*seg_p_r = (*seg_p_r) ^ (*seg_p_l);
			*seg_p_l = seg_tmp;
		}
		seg_tmp = *seg_p_r;
		*seg_p_r = *seg_p_l;
		*seg_p_l = seg_tmp;

		flag = 0;
		memset(seg_out, 0, 8);
		for (i = 0; i < 8; i++) {
			for (j = 0; j < 8; j++) {
				if ((seg_p[rev_IP[flag] / 8] & b[rev_IP[flag] % 8]) != 0)
					seg_out[i] = seg_out[i] | b[j];
				flag++;
			}
		}
		des_file.write(seg_out, 8);
	}
	des_file.close();
	return 0;
}

//key generate
void key_gen(char(*round_key)[8]) {
	char key_p1_0[4] = { 0 };
	char key_p1_1[4] = { 0 };
	char flag = 0;
	char i, j, k;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 8; j++) {
			if ((key[(PC1[flag]) / 8] & b[(PC1[flag]) % 8]) != 0)
				key_p1_0[i] = key_p1_0[i] | b[j];
			flag++;
			if (flag == 28)
				break;
		}
	}
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 8; j++) {
			if ((key[(PC1[flag]) / 8] & b[(PC1[flag]) % 8]) != 0)
				key_p1_1[i] = key_p1_1[i] | b[j];
			flag++;
			if (flag == 56)
				break;
		}
	}
	char temp;
	swap_e(key_p1_0[0], key_p1_0[3], temp);
	swap_e(key_p1_0[1], key_p1_0[2], temp);
	swap_e(key_p1_1[0], key_p1_1[3], temp);
	swap_e(key_p1_1[1], key_p1_1[2], temp);

	uint32_t* kp0_ptr, * kp1_ptr;
	uint32_t x;
	kp0_ptr = (uint32_t*)key_p1_0;
	kp1_ptr = (uint32_t*)key_p1_1;
	for (i = 0; i < 16; i++) {
		if (i == 0 || i == 1 || i == 8 || i == 15) {
			if ((*kp0_ptr & 0x80000000) != 0)
				*kp0_ptr = (*kp0_ptr << 1) | 0x00000010;
			else
				*kp0_ptr = *kp0_ptr << 1;
			if ((*kp1_ptr & 0x80000000) != 0)
				*kp1_ptr = (*kp1_ptr << 1) | 0x00000010;
			else
				*kp1_ptr = *kp1_ptr << 1;

		}
		else {
			x = *kp0_ptr & 0xc0000000;
			x = x >> 26;
			*kp0_ptr = (*kp0_ptr << 2) | x;
			x = *kp1_ptr & 0xc0000000;
			x = x >> 26;
			*kp1_ptr = (*kp1_ptr << 2) | x;
		}
		flag = 0;
		for (j = 0; j < 8; j++) {
			for (k = 2; k < 8; k++) {
				if (PC2[flag] < 28) {
					if ((key_p1_0[3 - (PC2[flag] / 8)] & b[(PC2[flag]) % 8]) != 0)
						round_key[i][j] |= b[k];
				}
				else {
					if ((key_p1_1[3 - ((PC2[flag] - 28) / 8)] & b[(PC2[flag] - 28) % 8]) != 0)
						round_key[i][j] |= b[k];
				}
				flag++;
			}
		}
	}
}

//half_seg	4 byte long, use all bit
//key		8 byte long, store 48 bit, each byte use low 6 bit
void round_func(char* half_seg, char* key) {
	char half_seg_e[8] = { 0 };
	char half_seg_s[4] = { 0 };
	char flag, i, j;
	//Extended replace
	flag = 0;
	for (i = 0; i < 8; i++) {
		for (j = 2; j < 8; j++) {
			if ((half_seg[E[flag] / 8] & b[E[flag] % 8]) != 0)
				half_seg_e[i] = half_seg_e[i] | b[j];
			flag++;
		}
	}
	//XOR key
	for (i = 0; i < 8; i++)
		half_seg_e[i] ^= key[i];
	//S-box replace
	char col, row, temp;
	flag = 0;
	for (i = 0; i < 4; i++) {
		row = col = temp = 0;
		for (j = 0; j < 2; j++) {
			temp = S_box[i + i][row][col];
			row = col = 0;
			if ((half_seg_e[flag] & b6) != 0)
				row |= b2;
			if ((half_seg_e[flag] & b1) != 0)
				row |= b1;
			col = ((half_seg_e[flag] & 0x1e) >> 1) & 0x0f;
			flag++;
		}
		half_seg_s[i] = (temp << 4 & 0xf0) | (0x0f & S_box[i + i + 1][row][col]);
	}
	//P replace
	flag = 0;
	memset(half_seg, 0, 4);
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 8; j++) {
			if ((half_seg_s[P[flag] / 8] & b[P[flag] % 8]) != 0)
				half_seg[i] = half_seg[i] | b[j];
			flag++;
		}
	}
}

//seg_p 8 byte long, use all bit
bool input_replace(char* seg_p) {
	char seg[8], flag;
	memset(seg, 0, 8);
	memset(seg_p, 0, 8);
	src_file.read(seg, 8);
	if (src_file.gcount() != 0) {
		flag = 0;
		for (char i = 0; i < 8; i++)
			for (char j = 0; j < 8; j++) {
				if ((seg[IP[flag] / 8] & b[IP[flag] % 8]) != 0)
					seg_p[i] = seg_p[i] | b[j];
				flag++;
			}
	}
	else {
		src_file.close();
		cout << "DES Finished" << endl;
		return false;
	}
	return true;
}