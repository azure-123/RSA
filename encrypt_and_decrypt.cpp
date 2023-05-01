#include <iostream>
#include<string>
#include<bitset>
#include<fstream>
#include<cmath>
#include<time.h>
#include<NTL/ZZ.h>
#include<NTL/vector.h>
#define inf 65534
using namespace std;
using namespace NTL;


ifstream infile("a.txt", ios::in);
ZZ circular_left_shift(ZZ input, int bit_sum, int shift_num)
{
	ZZ temp(0);
	ZZ output(0);
	temp = input >> (bit_sum - shift_num);
	input <<= shift_num;
	output = temp | input;
	return output;
}

ZZ IP_permutation(ZZ input_64)//IP置换
{
	ZZ temp;
	temp = 0;
	int	permutation_list[65] = { 0, 58,50,42,34,26,18,10,2,
									60,52,44,36,28,20,12,4,
									62,54,46,38,30,22,14,6,
									64,56,48,40,32,24,16,8,
									57,49,41,33,25,17,9,1,
									59,51,43,35,27,19,11,3,
									61,53,45,37,29,21,13,5,
									63,55,47,39,31,23,15,7 };
	for (int i = 1; i <= 64; i++)
	{
		if (bit(input_64, 64 - permutation_list[i]) == 1)
			SetBit(temp, 64 - i);
	}
	return temp;
}

ZZ IP_permutation_inverse(ZZ input_64)//IP逆置换
{
	ZZ temp(0);
	int	permutation_list[65] = { 0,40,8,48,16,56,24,64,32,
								   39,7,47,15,55,23,63,31,
								   38,6,46,14,54,22,62,30,
								   37,5,45,13,53,21,61,29,
								   36,4,44,12,52,20,60,28,
								   35,4,43,11,51,19,59,27,
								   34,2,42,10,50,18,58,26,
								   33,1,41,9,49,17,57,25 };
	for (int i = 1; i <= 64; i++)
	{
		if (bit(input_64, 64 - permutation_list[i]) == 1)
			SetBit(temp, 64 - i);
	}
	return temp;
}

ZZ PC1_permutation(ZZ input_64)
{
	ZZ output_56(0);
	int PC1_list[57] = { 0,57,49,41,33,25,17,9,
						1,58,50,42,34,26,18,
						10,2,59,51,43,35,27,
						19,11,3,60,52,44,36,
						63,55,47,39,31,23,15,
						7,62,54,46,38,30,22,
						14,6,61,53,45,37,29,
						21,13,5,28,20,12,4 };
	for (int i = 1; i <= 56; i++)
	{
		if (bit(input_64, 64 - PC1_list[i]) == 1)
			SetBit(output_56, 56 - i);
	}
	return output_56;
}

ZZ PC2_permutation(ZZ input_56)
{
	ZZ output_48(0);
	int PC2_list[49] = { 0,14,17,11,24,1,5,
						3,28,15,6,21,10,
						23,19,12,4,26,8,
						16,7,27,20,13,2,
						41,52,31,37,47,55,
						30,40,51,45,33,48,
						44,49,39,56,34,53,
						46,42,50,36,29,32 };
	for (int i = 1; i <= 48; i++)
	{
		if (bit(input_56, 56 - PC2_list[i]) == 1)
			SetBit(output_48, 48 - i);
	}
	return output_48;
}

ZZ DES_key_schedule(ZZ input_key_64, int choice)
{
	ZZ output_key_48(0);
	ZZ shift_in;
	ZZ temp_high(0);
	ZZ temp_low(0);
	ZZ shift_out(0);
	int shift_list[16] = { 0 };//对需要做的移位进行处理
	shift_list[0] = 1;
	for (int i = 1; i < 16; i++)
	{
		if (i == 1 || i == 8 || i == 15)
			shift_list[i] = shift_list[i - 1] + 1;
		else
			shift_list[i] = shift_list[i - 1] + 2;
	}//为不同组密钥的移位进行赋值

	shift_in = PC1_permutation(input_key_64);//先进行置换PC-1，删掉8个校验位后进行置换

	temp_low = shift_in & 0xfffffff;//取低位28位
	temp_high = (shift_in - temp_low) >> 28;//取高位28位
	temp_low = circular_left_shift(temp_low, 28, shift_list[choice]);
	temp_high = circular_left_shift(temp_high, 28, shift_list[choice]);
	shift_out = temp_high * pow(2, 28) + temp_low;//将两个28比特数拼接起来

	output_key_48 = PC2_permutation(shift_out);//进行置换PC-2，压缩为48比特的子密钥

	return output_key_48;
}

ZZ E_expansion(ZZ input_32)//E扩展
{
	ZZ output_48;
	output_48 = 0;
	int expansion_list[49] = { 0,32,1,2,3,4,5,
								4,5,6,7,8,9,
								8,9,10,11,12,13,
								12,13,14,15,16,17,
								16,17,18,19,20,21,
								20,21,22,23,24,25,
								24,25,26,27,28,29,
								28,29,30,31,32,1
	};
	for (int i = 1; i <= 48; i++)
	{
		if (bit(input_32, 32 - expansion_list[i]) == 1)
			SetBit(output_48, 48 - i);
	}
	return output_48;
}

ZZ S_boxes_replacement(ZZ input_6, int choice)
{

	ZZ output_4;
	int row, col;
	row = bit(input_6, 0) + bit(input_6, 5) * 2;
	col = bit(input_6, 1) + bit(input_6, 2) * 2 + bit(input_6, 3) * 4 + bit(input_6, 4) * 8;

	int S_boxes[8][4][16] = {
		{
			14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
			0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
			4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
			15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
		},
		{
			15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
			3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
			0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
			13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
		},
		{
			10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
			13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
			13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
			1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
		},
		{
			7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
			13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
			10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
			3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
		},
		{
			2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
			14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
			4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
			11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
		},
		{
			12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
			10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
			9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
			4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
		},
		{
			4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
			13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
			1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
			6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
		},
		{
			13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
			1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
			7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
			2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
		}
	};
	output_4 = ZZ(S_boxes[choice][row][col]);
	return output_4;
}

ZZ P_box_permutation(ZZ input_32)
{
	ZZ output_32;
	output_32 = 0;
	int P_box[33] = { 0,16,7,20,21,
					29,12,28,17,
					1,15,23,26,
					5,18,31,10,
					2,8,24,14,
					32,27,3,9,
					19,13,30,6,
					22,11,4,25 };
	for (int i = 1; i <= 32; i++)
	{
		if (bit(input_32, 32 - P_box[i]) == 1)
			SetBit(output_32, 32 - i);
	}
	return output_32;
}

ZZ F_function(ZZ input_32, ZZ key_48)//F函数
{
	ZZ expanded_48 = E_expansion(input_32);
	ZZ output_32;
	output_32 = 0;//初始化为0，在后期需要对其直接进行加操作
	expanded_48 ^= key_48;
	ZZ S_box_in[8];//大整数数组，放8个六位数
	for (int i = 0; i < 8; i++)
		S_box_in[i] = 0;//全部初始化为0
	for (int i = 0; i < 8; i++)
	{
		for (int j = i * 6; j < (i + 1) * 6; j++)
		{
			if (bit(expanded_48, 47 - j) == 1)
				SetBit(S_box_in[i], 5 - j % 6);
		}
	}//给大整数数组中整数置位
	ZZ S_box_out[8];
	for (int i = 0; i < 8; i++)
		S_box_out[i] = 0;//全部初始化为0
	for (int i = 0; i < 8; i++)
		S_box_out[i] = S_boxes_replacement(S_box_in[i], i);//每个S盒输出一个四位的大整数
	for (int i = 0; i < 8; i++)
		output_32 += S_box_out[i] * ZZ(pow(16, 7 - i));
	output_32 = P_box_permutation(output_32);
	return output_32;
}

ZZ DES_encrypt(ZZ input_64, ZZ input_key_64)
{
	ZZ ip_temp;
	ip_temp = IP_permutation(input_64);
	ZZ temp_right, temp_left;
	temp_right = ip_temp & 0xffffffff;//取初始置换IP后的左半部分
	temp_left = (ip_temp - temp_right) >> 32;//取初始置换IP后的右半部分
	for (int i = 0; i < 16; i++)
	{
		temp_left ^= F_function(temp_right, DES_key_schedule(input_key_64, i));
		ZZ temp;
		temp = temp_left;
		temp_left = temp_right;
		temp_right = temp;
	}
	ZZ rounded;//经过16轮运算以后拼接起来的结果
	temp_left <<= 32;//将左半部分进行左移
	rounded = temp_right + temp_left;//相加进行拼接
	rounded = IP_permutation_inverse(rounded);
	return rounded;
}

ZZ DES_decrypt(ZZ input_64, ZZ input_key_64)
{
	ZZ ip_temp;
	ip_temp = IP_permutation(input_64);
	ZZ temp_right, temp_left;
	temp_right = ip_temp & 0xffffffff;//取初始置换IP后的左半部分
	temp_left = (ip_temp - temp_right) >> 32;//取初始置换IP后的右半部分
	for (int i = 15; i >= 0; i--)
	{
		temp_left ^= F_function(temp_right, DES_key_schedule(input_key_64, i));
		ZZ temp;
		temp = temp_left;
		temp_left = temp_right;
		temp_right = temp;
	}
	ZZ rounded;//经过16轮运算以后拼接起来的结果
	temp_left <<= 32;//将左半部分进行左移
	rounded = temp_right + temp_left;//相加进行拼接
	rounded = IP_permutation_inverse(rounded);
	return rounded;
}

void hex_cout(ZZ n, int num)
{
	ZZ temp4(0);
	if (num == 0)
		return;
	else
	{
		temp4 = n & 0xf;
		hex_cout(n >> 4, num - 1);
		if (temp4 == 0)
			cout << "0";
		else if (temp4 == 1)
			cout << "1";
		else if (temp4 == 2)
			cout << "2";
		else if (temp4 == 3)
			cout << "3";
		else if (temp4 == 4)
			cout << "4";
		else if (temp4 == 5)
			cout << "5";
		else if (temp4 == 6)
			cout << "6";
		else if (temp4 == 7)
			cout << "7";
		else if (temp4 == 8)
			cout << "8";
		else if (temp4 == 9)
			cout << "9";
		else if (temp4 == 10)
			cout << "a";
		else if (temp4 == 11)
			cout << "b";
		else if (temp4 == 12)
			cout << "c";
		else if (temp4 == 13)
			cout << "d";
		else if (temp4 == 14)
			cout << "e";
		else if (temp4 == 15)
			cout << "f";
		else
			;
		n >>= 4;
	}
}

ZZ random_generate_mediate(ZZ input_D, ZZ key1, ZZ key2)
{
	ZZ output_I;
	input_D = DES_encrypt(input_D, key1);
	input_D = DES_decrypt(input_D, key2);
	output_I = DES_encrypt(input_D, key1);
	return output_I;
}

//AES
void ZZ_to_matrix(ZZ input128, int mat[][4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
			mat[i][j] = 0;
	}
	for (int i = 15; i >= 0; i--)
	{
		ZZ temp(0);
		temp = (input128 >> (i * 8)) & 0xff;
		for (int j = 0; j < 8; j++)
		{
			mat[(15 - i) % 4][(15 - i) / 4] += bit(temp, j) << j;
		}
	}
	return;
}

ZZ matrix_to_ZZ(int mat[][4])
{
	ZZ state128(0);
	for (int j = 0; j < 4; j++)
	{
		for (int i = 0; i < 4; i++)
		{
			state128 <<= 8;
			state128 += ZZ(mat[i][j]);
		}
	}
	return state128;
}


ZZ AddRoundKey(ZZ State128, ZZ RoundKey128)//和密钥的异或操作
{
	ZZ output128;
	output128 = State128 ^ RoundKey128;
	return output128;
}

ZZ SubBytes(ZZ input128)
{
	ZZ State128(0);
	int AES_S_Box[16][16] = {
	{0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
	{0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
	{0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
	{0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
	{0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
	{0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
	{0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
	{0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
	{0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
	{0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
	{0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
	{0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
	{0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
	{0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
	{0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
	{0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}
	};

	for (int i = 15; i >= 0; i--)
	{
		ZZ temp;
		temp = (input128 >> i * 8) & 0xff;
		int row = 0, col = 0;
		for (int j = 0; j < 4; j++)
		{
			col += int(bit(temp, j) << j);
		}
		for (int j = 4; j < 8; j++)
		{
			row += int(bit(temp, j) << (j - 4));
		}
		State128 += ZZ(AES_S_Box[row][col]) << (i * 8);
	}
	return State128;
}

void ShiftRows(int mat[][4])
{
	//第二行向左循环左移1位
	int temp = mat[1][0];
	for (int i = 0; i < 3; i++)
	{
		mat[1][i] = mat[1][i + 1];
	}
	mat[1][3] = temp;
	//第三行向左循环左移2位
	for (int cnt = 0; cnt < 2; cnt++)
	{
		temp = mat[2][0];
		for (int i = 0; i < 3; i++)
		{
			mat[2][i] = mat[2][i + 1];
		}
		mat[2][3] = temp;
	}
	//第四行向左循环左移3位
	for (int cnt = 0; cnt < 3; cnt++)
	{
		temp = mat[3][0];
		for (int i = 0; i < 3; i++)
		{
			mat[3][i] = mat[3][i + 1];
		}
		mat[3][3] = temp;
	}
}

void ShiftRows_inv(int mat[][4])
{
	//第二行向右循环右移1位
	int temp = mat[1][3];
	for (int i = 3; i >= 1; i--)
	{
		mat[1][i] = mat[1][i - 1];
	}
	mat[1][0] = temp;
	//第三行向右循环移2位
	for (int cnt = 0; cnt < 2; cnt++)
	{
		temp = mat[2][3];
		for (int i = 3; i >= 1; i--)
		{
			mat[2][i] = mat[2][i - 1];
		}
		mat[2][0] = temp;
	}
	//第四行向右循环右移3位
	for (int cnt = 0; cnt < 3; cnt++)
	{
		temp = mat[3][3];
		for (int i = 3; i >= 1; i--)
		{
			mat[3][i] = mat[3][i - 1];
		}
		mat[3][0] = temp;
	}
}

ZZ SubBytes_inv(ZZ input128)
{
	ZZ State128(0);
	int AES_S_Box[16][16] = {
		{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
		{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
		{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
		{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
		{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
		{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
		{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
		{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
		{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
		{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
		{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
		{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
		{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
		{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
		{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
		{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
	};

	for (int i = 15; i >= 0; i--)
	{
		ZZ temp;
		temp = (input128 >> i * 8) & 0xff;
		int row = 0, col = 0;
		for (int j = 0; j < 4; j++)
		{
			col += int(bit(temp, j) << j);
		}
		for (int j = 4; j < 8; j++)
		{
			row += int(bit(temp, j) << (j - 4));
		}
		State128 += ZZ(AES_S_Box[row][col]) << (i * 8);
	}
	return State128;
}

void MixColumns_inv(int mat[][4])
{
	int mult[4][4] =
	{
		0x0e,0x0b,0x0d,0x09,
		0x09,0x0e,0x0b,0x0d,
		0x0d,0x09,0x0e,0x0b,
		0x0b,0x0d,0x09,0x0e
	};
	int temp_mat[4][4] = { 0 };
	for (int j = 0; j < 4; j++)//j表示输入矩阵的列数
	{
		for (int i = 0; i < 4; i++)//i表示输入矩阵的行数
		{
			for (int k = 0; k < 4; k++)//j表示相乘矩阵的列数
			{
				if (mult[i][k] == 0x09)
				{
					int temp = mat[k][j];
					int temp_b_2 = 0;
					int temp_b_4 = 0;
					int temp_b_8 = 0;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_2 = temp;
					//b*2

					temp = temp_b_2;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_4 = temp;//b*2*2
					//int mult2 = temp_mat[i][j];//*2

					temp = temp_b_4;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_8 = temp;//b*2*2*2
					//三次*2
					temp_mat[i][j] ^= mat[k][j];
					temp_mat[i][j] ^= temp_b_8;
					//temp_mat[i][j] ^= mult2;
				}
				else if (mult[i][k] == 0x0b)
				{
					int temp = mat[k][j];
					int temp_b_2 = 0;
					int temp_b_4 = 0;
					int temp_b_8 = 0;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					//b*2
					temp_b_2 = temp;//将b*2记录下来

					temp = temp_b_2;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_4 = temp;//b*2*2
					//int mult2 = temp_mat[i][j];//*2

					temp = temp_b_4;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_8 = temp;//b*2*2*2
					//三次*2
					temp_mat[i][j] ^= mat[k][j];//+b*1
					temp_mat[i][j] ^= temp_b_2;//+b*2
					temp_mat[i][j] ^= temp_b_8;//+b*8
				}
				else if (mult[i][k] == 0x0d)
				{
					int temp = mat[k][j];
					int temp_b_2 = 0;
					int temp_b_4 = 0;
					int temp_b_8 = 0;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_2 = temp;//b*2

					temp = temp_b_2;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_4 = temp;//b*2*2


					temp = temp_b_4;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_8 = temp;//b*2*2*2
					//三次*2
					temp_mat[i][j] ^= mat[k][j];//+b*1
					temp_mat[i][j] ^= temp_b_4;//+b*4
					temp_mat[i][j] ^= temp_b_8;//+b*4
				}
				else if (mult[i][k] == 0x0e)
				{
					int temp = mat[k][j];
					int temp_b_2 = 0;
					int temp_b_4 = 0;
					int temp_b_8 = 0;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_2 = temp;//b*2

					temp = temp_b_2;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_4 = temp;//b*2*2

					temp = temp_b_4;
					temp <<= 1;
					if (temp / 0xff)
					{
						temp ^= 0x1b;
						temp &= 0xff;
					}
					temp_b_8 = temp;//b*2*2*2
					//三次*2
					temp_mat[i][j] ^= temp_b_2;//+b*2
					temp_mat[i][j] ^= temp_b_4;//+b*4
					temp_mat[i][j] ^= temp_b_8;//+b*8
				}
			}
		}
	}
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			mat[i][j] = temp_mat[i][j] & 0xff;
		}
	}
}


void MixColumns(int mat[][4])
{
	int mult[4][4] =
	{
		2,3,1,1,
		1,2,3,1,
		1,1,2,3,
		3,1,1,2
	};
	int temp_mat[4][4] = { 0 };
	for (int j = 0; j < 4; j++)//j表示输入矩阵的列数
	{
		for (int i = 0; i < 4; i++)//i表示输入矩阵的行数
		{
			for (int k = 0; k < 4; k++)//j表示相乘矩阵的列数
			{
				if (mult[i][k] == 1)
				{
					temp_mat[i][j] ^= mat[k][j] * mult[i][k];
				}
				else if (mult[i][k] == 2)
				{
					int temp = mat[k][j];
					temp <<= 1;
					if (temp / 0xff)
						temp ^= 0x1b;
					temp_mat[i][j] ^= temp;

				}
				else
				{
					int temp = mat[k][j];
					temp <<= 1;
					if (temp / 0xff)
						temp ^= 0x1b;
					temp_mat[i][j] ^= temp;
					temp_mat[i][j] ^= mat[k][j];
				}
			}
		}
	}
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			mat[i][j] = temp_mat[i][j] & 0xff;
		}
	}
}

ZZ keys[11];
void AES_key_schedule(ZZ cipher_key)
{
	int Rcon_table[4][10] =
	{
		0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	int AES_S_Box[16][16] = {
	{0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
	{0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
	{0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
	{0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
	{0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
	{0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
	{0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
	{0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
	{0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
	{0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
	{0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
	{0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
	{0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
	{0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
	{0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
	{0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}
	};

	int round_keys[11][4][4] = { 0 };//轮密钥组
	int cipher_key_mat[4][4] = { 0 };//随机密钥k转化的矩阵
	int temp[4] = { 0 };//临时抽出的一列，与第一列、rcon异或
	ZZ_to_matrix(cipher_key, cipher_key_mat);//将随机密钥k转化成矩阵的形式
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
			round_keys[0][i][j] = cipher_key_mat[i][j];//将密钥先复制到轮密钥组中
	}
	for (int i = 1; i <= 10; i++)//不同轮的密钥计数
	{
		for (int j = 0; j < 4; j++)//一列的行数
		{
			temp[(j + 3) % 4] = round_keys[i - 1][j][3];//循环上移
		}
		for (int j = 0; j < 4; j++)
		{
			int row = (temp[j] >> 4) & 0xf;//取subBytes行
			int col = temp[j] & 0xf;//取subBytes列
			temp[j] = AES_S_Box[row][col];
		}
		for (int j = 0; j < 4; j++)
		{
			round_keys[i][j][0] = round_keys[i - 1][j][0] ^ temp[j] ^ Rcon_table[j][i - 1];//第一列的异或操作
		}
		for (int j = 1; j < 4; j++)
		{
			for (int k = 0; k < 4; k++)
			{
				round_keys[i][k][j] = round_keys[i - 1][k][j] ^ round_keys[i][k][j - 1];//后三列的异或操作
			}
		}
	}
	for (int i = 0; i <= 10; i++)
	{
		keys[i] = matrix_to_ZZ(round_keys[i]);
	}
}

ZZ ANSI(int bits)
{
	srand(unsigned(time(NULL)));
	ZZ key1(123);
	ZZ key2(321);
	ZZ input_D;
	ZZ res(0);
	ZZ ans(1);
	int m = 8;

	for (int i = 0; i < bits; i++)
	{
		ans *= 2;
	}
	//cout << ans << endl;
	res = 0;
	for (int i = 0; i < (bits / 64); i++)
	{
		input_D = ZZ(rand());
		res += random_generate_mediate(input_D, key1, key2);//max=9223372036854775807
		if (i != (bits / 64 - 1))
		{
			for (int j = 0; j < 64; j++)
				res *= 2;
		}
	}
	return res;
}


ZZ generate_cipher_key()
{
	return ANSI(128);
}


ZZ AES_encrypt(ZZ key, ZZ state)
{
	AES_key_schedule(key);
	state = AddRoundKey(state, key);
	for (int i = 1; i <= 10; i++)
	{
		int mat[4][4] = { 0 };
		state = SubBytes(state);
		ZZ_to_matrix(state, mat);
		ShiftRows(mat);
		if (i != 10)
			MixColumns(mat);
		state = matrix_to_ZZ(mat);
		state = AddRoundKey(state, keys[i]);
	}
	return state;
}

ZZ AES_decrypt(ZZ state)
{
	state = AddRoundKey(state, keys[10]);//无问题
	int mat[4][4] = { 0 };
	for (int i = 9; i >= 1; i--)
	{
		ZZ_to_matrix(state, mat);//将state转化为矩阵
		ShiftRows_inv(mat);//无问题
		state = matrix_to_ZZ(mat);//将矩阵转化为ZZ
		state = SubBytes_inv(state);
		state = AddRoundKey(state, keys[i]);//无问题
		ZZ_to_matrix(state, mat);//将state转化为矩阵
		MixColumns_inv(mat);
		state = matrix_to_ZZ(mat);
	}
	ZZ_to_matrix(state, mat);
	ShiftRows_inv(mat);

	state = matrix_to_ZZ(mat);
	state = SubBytes_inv(state);
	state = AddRoundKey(state, keys[0]);

	return state;
}

ifstream in_plaintext("plaintext.txt", ios::in | ios::binary);
ZZ read_digit_text()
{
	ZZ plain_group(0);

	if (!in_plaintext.is_open())
		cout << "明文文件打开失败！" << endl;
	for (int i = 0; i < 16; i++)
	{
		char ch;
		int dch;
		ch = in_plaintext.get();
		dch = int(ch) & 0xff;
		if (!in_plaintext.eof())
			plain_group += ZZ(dch);
		if (i != 15)
		{
			plain_group <<= 8;
		}
	}
	return plain_group;
}

void write_digit_text(ZZ ciphertext, int num)
{
	char output_text[17];
	if (!num)
	{
		ofstream out_ciphertext("ciphertext.txt", ios::out | ios::binary);
		for (int i = 0; i < 16; i++)
		{
			int temp = 0;
			ZZ temp_ZZ(0);
			temp_ZZ = (ciphertext >> (15 - i) * 8) & 0xff;
			for (int i = 0; i < 8; i++)
			{
				temp <<= 1;
				temp += bit(temp_ZZ, 7 - i);
			}
			//out_ciphertext << char(temp);
			output_text[i] = char(temp);
		}
		out_ciphertext << output_text;
	}
	else
	{
		ofstream out_ciphertext("ciphertext.txt", ios::out | ios::binary | ios::app);
		for (int i = 0; i < 16; i++)
		{
			int temp = 0;
			ZZ temp_ZZ(0);
			temp_ZZ = (ciphertext >> (15 - i) * 8) & 0xff;
			for (int i = 0; i < 8; i++)
			{
				temp <<= 1;
				temp += bit(temp_ZZ, 7 - i);
			}
			//out_ciphertext << char(temp);
			output_text[i] = char(temp);
		}
		out_ciphertext << output_text;
	}
}

void write_digit_cracked(ZZ ciphertext, int num)
{
	char output_text[18] = "";
	if (!num)
	{
		ofstream out_ciphertext("cracked.txt", ios::out | ios::binary);
		for (int i = 0; i < 16; i++)
		{
			int temp = 0;
			ZZ temp_ZZ(0);
			temp_ZZ = (ciphertext >> (15 - i) * 8) & 0xff;
			for (int i = 0; i < 8; i++)
			{
				temp <<= 1;
				temp += bit(temp_ZZ, 7 - i);
			}
			output_text[i] = char(temp);
		}
		out_ciphertext << output_text;
	}
	else
	{
		ofstream out_ciphertext("cracked.txt", ios::out | ios::binary | ios::app);
		for (int i = 0; i < 16; i++)
		{
			int temp = 0;
			ZZ temp_ZZ(0);
			temp_ZZ = (ciphertext >> (15 - i) * 8) & 0xff;
			for (int i = 0; i < 8; i++)
			{
				temp <<= 1;
				temp += bit(temp_ZZ, 7 - i);
			}
			output_text[i] = char(temp);
		}
		out_ciphertext << output_text;
	}
}

//生成随机素数
ZZ generate_prime(int bits)
{
	ZZ prime(0);
	while (true)
	{
		prime = ANSI(bits);
		if (ProbPrime(prime, 10))
			break;
	}
	return prime;
}

ZZ find_b(ZZ p, ZZ q)
{
	ZZ n(0);
	ZZ b(0);
	ZZ phi_n(0);
	n = p * q;
	phi_n = (p - 1)*(q - 1);
	while (true)
	{
		b = ANSI(64);
		if (GCD(b, phi_n) == 1)
			break;
	}
	return b;
}

ZZ exgcd(ZZ a, ZZ b, ZZ &x, ZZ &y)
{ 
	ZZ num, term;
	if (b == 0) 
	{
		x = 1;
		y = 0;
		return a;
	}
	num = exgcd(b, a % b, x, y);
	term = x;
	x = y;
	y = term - a / b * (y);
	return num;
}

ZZ find_a(ZZ a, ZZ p, ZZ q)
{
	ZZ phi_n(0);
	phi_n = (p - 1)*(q - 1);
	ZZ b;
	b = phi_n;
	ZZ x, y;
	exgcd(a, b, x, y);
	x = x % b;
	if (x <= 0)
		x = x + b;
	return x;
}


ZZ pow_mod(ZZ a, ZZ b, ZZ mod)
{
	ZZ result(1);
	while (b != 0)
	{
		if ((b & 1) != 0)
		{
			result = (result*a) % mod;
		}
		a = (a*a) % mod;
		b >>= 1;
	}
	return result;
}

int main()
{

	ZZ key(0);
	ZZ ciphertext;
	ZZ plaintext;
	ZZ RSA_plaintext;
	ZZ RSA_ciphertext;
	ZZ RSA_crackedtext;
	ZZ cracked;
	ZZ p(0);
	ZZ q(0);
	ZZ b(0);
	ZZ a(0);
	ZZ n(0);
	int num = 0;
	cout << "欢迎来到Alice和Bob的奇妙世界！(/≧▽≦)/" << endl;
	cout << "请输入素数的位数吧！<(￣︶￣)>这里→";
	cin >> num;
	key = generate_cipher_key();
	cout << "生成密钥:" << endl;
	hex_cout(key, 32);
	cout << endl;
	//RSA
	cout << "正在进行RSA加密和解密，※=○☆(＿＿*)Ｚｚｚ" << endl;
	cout << "寻找素数p中";
	p = generate_prime(num);
	cout << endl << "素数p:" << endl;
	hex_cout(p, num / 4);
	cout << endl;
	cout << "寻找素数q中";
	while (true)
	{
		q = generate_prime(num);
		if (p != q)
			break;
	}
	cout << endl << "素数q:" << endl;
	hex_cout(q, num / 4);
	cout << endl;
	cout << "生成b中";
	b = find_b(p, q);
	cout << endl << "b:" ;
	hex_cout(b, 64 / 4 + 1);
	cout << endl;
	cout << "生成a中";
	a = find_a(b, p, q);
	cout << endl << "a:";
	hex_cout(a, 64 / 4 + 1);
	cout << endl;


	n = p * q;
	RSA_ciphertext = pow_mod(key, b, n);
	cout << "加密后的密钥:" << endl;
	hex_cout(RSA_ciphertext, 128);
	cout << endl;
	RSA_crackedtext = pow_mod(RSA_ciphertext, a, n);
	cout << "解密后的密钥:" << endl;
	hex_cout(RSA_crackedtext, 32);
	cout << endl;


	//AES
	cout << "正在用该密钥进行AES加密和解密，请稍后ZZzz…(。-ω-)" << endl;
	for (int i = 0; i < inf; i++)
	{
		plaintext = read_digit_text();
		if (plaintext == 0)
			break;
		ciphertext = AES_encrypt(key, plaintext);
		write_digit_text(ciphertext, i);
		cracked = AES_decrypt(ciphertext);
		write_digit_cracked(cracked, i);
		key ^= cracked;//CBC模式
	}
	cout << endl << "AES加解密成功！o(〃'▽'〃)o" << endl
		<< "可前往ciphertext.txt和cracked.txt查看密文和解密后的明文哟(/ω＼*)……… (/ω·＼*)" << endl;


	return 0;
}
/*
  cypher key:
  0x2b7e151628aed2a6abf7158809cf4f3c
  key1:
  0xa0fafe1788542cb123a339392a6c7605
  key2:
  0xf2c295f27a96b9435935807a7359f67f
  key3:
  0x3d80477d4716fe3e1e237e446d7a883b
  key4:
  0xef44a541a8525b7fb671253bdb0bad00
  key5:
  0xd4d1c6f87c839d87caf2b8bc11f915bc
  key6:
  0x6d88a37a110b3efddbf98641ca0093fd
  key7:
  0x4e54f70e5f5fc9f384a64fb24ea6dc4f
  key8:
  0xead27321b58dbad2312bf5607f8d292f
  key9:
  0xac7766f319fadc2128d12941575c006e
  key10:
  0xd014f9a8c9ee2589e13f0cc8b6630ca6
  初始state:
  0x3243f6a8885a308d313198a2e0370734
  经过异或操作后state:
  0x193de3bea0f4e22b9ac68d2ae9f84808
  */
