// Most of this is based on the nist-standard specified in the following report:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

#include <vector>
#include <iostream>
#include <unistd.h>

const int ROUNDS = 10;
const int KEY_SIZE = 16;

int sbox[16][16] = {
     {0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76},
     {0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0},
     {0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15},
     {0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75},
     {0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84},
     {0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf},
     {0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8},
     {0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2},
     {0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73},
     {0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb},
     {0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79},
     {0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08},
     {0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a},
     {0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e},
     {0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf},
     {0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16}
};

int rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

// from: https://codereview.stackexchange.com/a/78539
std::string bytes_to_hexstr(char *data, int len) {
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}

void print_state(unsigned char state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            std::cout << std::hex << state[i][j] << " ";
        }
        std::cout << "\n";
    }
}

void sub_bytes(unsigned char state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            unsigned char entry = state[j][i];
            int row = entry / 16;
            int col = entry % 16;

            state[i][j] = sbox[row][col];
        }
    }
}

void shift_row(unsigned char state[4][4], int row, int steps) {
    if (steps % 4 == 0) {
        return;
    }

    for (int i = 0; i < steps; ++i) {
        unsigned char first = state[row][0];
        for (int j = 0; j < 3; ++j) {
            state[row][j] = state[row][j + 1];
        }
        state[row][3] = first;
    }
}

void shift_rows(unsigned char state[4][4]) {
    shift_row(state, 1, 1);
    shift_row(state, 2, 2);
    shift_row(state, 3, 3);
}

// heavily based on: https://en.wikipedia.org/wiki/Rijndael_MixColumns
void mix_columns(unsigned char state[4][4]) {
    for (int col = 0; col < 4; ++col) {
        unsigned char a[4];
        unsigned char b[4];
        unsigned char h;

        for (int row = 0; row < 4; ++row) {
            a[row] = state[row][col];

            h = (unsigned char)((signed char)state[row][col] >> 7);
            b[row] = state[row][col] << 1;
            b[row] ^= 0x1B & h;
        }

        state[0][col] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        state[1][col] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        state[2][col] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        state[3][col] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }
}

void add_round_key(unsigned char state[4][4], unsigned char key[], int start) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = state[i][j] ^ key[start + i + 4*j];
        }
    }
}

void rot_word(unsigned char arr[4]) {
    unsigned char first = arr[0];
    arr[0] = arr[1];
    arr[1] = arr[2];
    arr[2] = arr[3];
    arr[3] = first;
}

void sub_word(unsigned char arr[4]) {
    for (int i = 0; i < 4; ++i) {
        arr[i] = sbox[arr[i] / 16][arr[i] % 16];
    }
}

void key_expansion2(char* key, unsigned char w[]) {
    unsigned char temp[4];

    // copy user supplied key as first subkey
    int i = 0;
    while (i < 16) {
        w[i] = key[i];
        i++;
    }

    int c = 16;
    i = 1;

    // while there are still bytes to be generated
    while (c < 16 * (ROUNDS+1)) {
        // copy temp variable from last 4-byte block
        for (int a = 0; a < 4; ++a) {
            temp[a] = w[a + c - 4];
        }

        // every four blocks (of four bytes)
        if (c % 16 == 0) {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= rcon[i];
            //temp[0] ^= rcon2(i);
            i++;
        }

        for (int a = 0; a < 4; ++a) {
            w[c] = w[c - 16] ^ temp[a];
            c++;
        }
    }
}

char* encrypt(char* block, char* key) {
    unsigned char state[4][4];

    unsigned char w[16 * (ROUNDS+1)];

    // Set key to test value
    for (int i = 0; i < 16; ++i)
        key[i] = 0;

    key_expansion2(key, w);
    std::cout << "Printing keys:\n";
    for (int i = 0; i < (ROUNDS+1); ++i) {
        std::cout << i << ":\t";

        for (int j = 0; j < 16; ++j) {
            std::cout << hexmap[(w[16*i + j] & 0xF0) >> 4];
            std::cout << hexmap[w[j] & 0x0F] << " ";
        }

        std::cout << "\n";
    }

    // copy block into state matrix
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = block[i + 4*j];
        }
    }

    // initial round key addition
    add_round_key(state, w, 0);

    for (int round = 0; round < ROUNDS-1; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, w, 16 * (round+1));
    }

    // last round
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, w, 16 * ROUNDS);

    // copy output to block
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            block[i + 4*j] = state[i][j];
        }
    }

    return block;
}

int main() {
    char key[16];
    std::cin.read(key, 16);

    std::string hex_key = bytes_to_hexstr(key, 16);
    //std::cout << "key:\t" << hex_key << "\n";

    int i = 0;
    while (!std::cin.eof()) {
        char block[16];
        std::cin.read(block, 16);

        std::string hex_block = bytes_to_hexstr(block, 16);
        char* encrypted = encrypt(block, key);

        /*
        std::cout << "block" << i << ":\t";
        std::cout << hex_block << " " << "\n";
        std::string hex_encrypted = bytes_to_hexstr(encrypted, 16);
        std::cout << "encr:\t" <<  hex_encrypted << " " << "\n";
        */

        for (int j = 0; j < 16; ++j) {
            std::cout << encrypted[j];
        }
        std::cout << "\n";

        i++;
    }

    return 0;
}
