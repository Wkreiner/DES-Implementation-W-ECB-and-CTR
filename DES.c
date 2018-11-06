#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/*
 * des takes two arguments on the command line:
 *    des -enc -ecb      -- encrypt in ECB mode
 *    des -enc -ctr      -- encrypt in CTR mode
 *    des -dec -ecb      -- decrypt in ECB mode
 *    des -dec -ctr      -- decrypt in CTR mode
 * des also reads some hardcoded files:
 *    message.txt            -- the ASCII text message to be encrypted,
 *                              read by "des -enc"
 *    encrypted_msg.bin      -- the encrypted message, a binary file,
 *                              written by "des -enc"
 *    decrypted_message.txt  -- the decrypted ASCII text message
 *    key.txt                -- just contains the key, on a line by itself, as an ASCII
 *                              hex number, such as: 0x34FA879B
 */

/////////////////////////////////////////////////////////////////////////////
// Type definitions
/////////////////////////////////////////////////////////////////////////////
typedef uint64_t KEYTYPE;
typedef uint32_t SUBKEYTYPE;
typedef uint64_t BLOCKTYPE;

struct BLOCK {
    BLOCKTYPE block;        // the block read
    int size;               // number of "real" bytes in the block, should be 8, unless it's the last block
    struct BLOCK *next;     // pointer to the next block
};
typedef struct BLOCK* BLOCKLIST;

struct BLOCK *head = NULL;
BLOCKTYPE des_enc(BLOCKTYPE v);

/////////////////////////////////////////////////////////////////////////////
// Initial and final permutation
/////////////////////////////////////////////////////////////////////////////
uint64_t init_perm[] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};

int final_perm[] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9, 49,17,57,25
};

/////////////////////////////////////////////////////////////////////////////
// Subkey generation
/////////////////////////////////////////////////////////////////////////////
uint64_t subkeys[16];

// Each subkey is 48 bits. To simplify the assignment, we're providing a very
// simple subkey generation routine (generateSubKeys).
uint64_t getSubKey(int i) {
    return subkeys[i];
}

// For extra credit, write the correct DES key expansion routine.
// The provided key expansion routine is a simple rotate left by n bits, but
// should be good enough to get you started.
void generateSubKeys(KEYTYPE key) {
    int i;
    for(i = 0; i < 16; i++) {
        //key >>> (64 - i) before
        subkeys[i] = ((key << i) | (key >> (64 - i))) & 0xFFFFFFFFFFFF;
    }
}

/////////////////////////////////////////////////////////////////////////////
// P-boxes
/////////////////////////////////////////////////////////////////////////////
uint64_t expand_box[] = {
    32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
};

uint32_t Pbox[] =
{
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25,
};

/////////////////////////////////////////////////////////////////////////////
// S-boxes
/////////////////////////////////////////////////////////////////////////////
uint64_t sbox_1[4][16] = {
    {14,  4, 13,  1,  2, 15, 11,  8,  3, 10 , 6, 12,  5,  9,  0,  7},
    { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
    { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
    {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}};

uint64_t sbox_2[4][16] = {
    {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5 ,10},
    { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
    { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
    {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}};

uint64_t sbox_3[4][16] = {
    {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
    {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
    {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
    { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}};


uint64_t sbox_4[4][16] = {
    { 7, 13, 14,  3,  0 , 6,  9, 10,  1 , 2 , 8,  5, 11, 12,  4 ,15},
    {13,  8, 11,  5,  6, 15,  0,  3,  4 , 7 , 2, 12,  1, 10, 14,  9},
    {10,  6,  9 , 0, 12, 11,  7, 13 ,15 , 1 , 3, 14 , 5 , 2,  8,  4},
    { 3, 15,  0,  6, 10,  1, 13,  8,  9 , 4 , 5, 11 ,12 , 7,  2, 14}};


uint64_t sbox_5[4][16] = {
    { 2, 12,  4,  1 , 7 ,10, 11,  6 , 8 , 5 , 3, 15, 13,  0, 14,  9},
    {14, 11 , 2 ,12 , 4,  7, 13 , 1 , 5 , 0, 15, 10,  3,  9,  8,  6},
    { 4,  2 , 1, 11, 10, 13,  7 , 8 ,15 , 9, 12,  5,  6 , 3,  0, 14},
    {11,  8 ,12 , 7 , 1, 14 , 2 ,13 , 6 ,15,  0,  9, 10 , 4,  5,  3}};


uint64_t sbox_6[4][16] = {
    {12,  1, 10, 15 , 9 , 2 , 6 , 8 , 0, 13 , 3 , 4 ,14 , 7  ,5 ,11},
    {10, 15,  4,  2,  7, 12 , 9 , 5 , 6,  1 ,13 ,14 , 0 ,11 , 3 , 8},
    { 9, 14 ,15,  5,  2,  8 ,12 , 3 , 7 , 0,  4 ,10  ,1 ,13 ,11 , 6},
    { 4,  3,  2, 12 , 9,  5 ,15 ,10, 11 ,14,  1 , 7  ,6 , 0 , 8 ,13}};


uint64_t sbox_7[4][16] = {
    { 4, 11,  2, 14, 15,  0 , 8, 13, 3,  12 , 9 , 7,  6 ,10 , 6 , 1},
    {13,  0, 11,  7,  4 , 9,  1, 10, 14 , 3 , 5, 12,  2, 15 , 8 , 6},
    { 1 , 4, 11, 13, 12,  3,  7, 14, 10, 15 , 6,  8,  0,  5 , 9 , 2},
    { 6, 11, 13 , 8,  1 , 4, 10,  7,  9 , 5 , 0, 15, 14,  2 , 3 ,12}};

uint64_t sbox_8[4][16] = {
    {13,  2,  8,  4,  6 ,15 ,11,  1, 10,  9 , 3, 14,  5,  0, 12,  7},
    { 1, 15, 13,  8 ,10 , 3  ,7 , 4, 12 , 5,  6 ,11,  0 ,14 , 9 , 2},
    { 7, 11,  4,  1,  9, 12, 14 , 2,  0  ,6, 10 ,13 ,15 , 3  ,5  ,8},
    { 2,  1, 14 , 7 , 4, 10,  8, 13, 15, 12,  9,  0 , 3,  5 , 6 ,11}};

void convertToBinaryy(uint64_t n, int j)
{
    
    uint64_t k, m;
    int i;
    for (i = j; i >= 0; i--)
    {
        m = 1 << i;
        k = n & m;
        if (k == 0)
            printf("0");
        else
            printf("1");
    }
}

void decToBinary(uint64_t n) {
    int binaryNum[64];
    int i = 0;
    while( n > 0) {
        binaryNum[i] = n%2;
        n = n/2;
        i++;
    }
    int j;
    for(j = i -1; j >= 0; j--) {
        printf("%d", binaryNum[j]);
    }
    printf("\n");
}

/////////////////////////////////////////////////////////////////////////////
// I/O
/////////////////////////////////////////////////////////////////////////////

// Pad the list of blocks, so that every block is 64 bits, even if the
// file isn't a perfect multiple of 8 bytes long. In the input list of blocks,
// the last block may have "size" < 8. In this case, it needs to be padded. See
// the slides for how to do this (the last byte of the last block
// should contain the number if real bytes in the block, add an extra block if
// the file is an exact multiple of 8 bytes long.) The returned
// list of blocks will always have the "size"-field=8.
// Example:
//    1) The last block is 5 bytes long: [10,20,30,40,50]. We pad it with 2 bytes,
//       and set the length to 5: [10,20,30,40,50,0,0,5]. This means that the
//       first 5 bytes of the block are "real", the last 3 should be discarded.
//    2) The last block is 8 bytes long: [10,20,30,40,50,60,70,80]. We keep this
//       block as is, and add a new final block: [0,0,0,0,0,0,0,0]. When we decrypt,
//       the entire last block will be discarded since the last byte is 0
BLOCKLIST pad_last_block(BLOCKLIST blocks) {
    // TODO
    if(blocks->size == 8) {
        BLOCKLIST temp = malloc(sizeof(BLOCKLIST));
        if(temp == NULL) {
            printf("ERROR: NO MEMORY");
            exit(0);
        }
        
        temp->block = '\0';
        temp->next = head;
        temp->size = 0;
        head = temp;
        return head;
    }
    
    //printf("SIZE: %d\n", strlen(blocks->block));
    uint64_t temp = blocks->size;
    convertToBinaryy(blocks->block, 63);
    printf("\n");
    printf("size2: %8.8x\n", temp);
    
    //printf("OG str: %s\n", blocks->block);
    uint64_t mask = 0xf;
    int i;
    for(i = 0; i < temp*4; i++)
    {
        mask = (mask << 4) + 0xf;
    }
    mask = mask << 8;
    printf("%16.8x\n", mask);
    uint64_t snum = blocks->block << (64-(temp+1)*8);
    decToBinary(snum);
    printf("shifted num\n");
    decToBinary(blocks->block);
    blocks->block = (blocks->block & mask);
    decToBinary(blocks->block);
    printf("\n");
    blocks->block = snum | (temp);
    decToBinary(blocks->block);
    printf("\n");
    printf("newstr %x\n", blocks->block);
    return blocks;
}



// Reads the message to be encrypted, an ASCII text file, and returns a linked list
// of BLOCKs, each representing a 64 bit block. In other words, read the first 8 characters
// from the input file, and convert them (just a C cast) to 64 bits; this is your first block.
// Continue to the end of the file.
BLOCKLIST read_cleartext_message(FILE *msg_fp) {
    // TODO
    // call pad_last_block() here to pad the last block!
    char line[9];
    int len;
    int i;
    //make all 8 byte blocks... add null terminator
    while((len = fread(line, 1, 8, msg_fp)) && len == 8)
    {
        BLOCKLIST iteration = malloc(sizeof(BLOCKLIST));
        if (iteration == NULL) {
            return NULL;
        }
        line[8] = '\0';
        
        uint64_t try = 0;
        try = line[0];
        for(i = 1; i < 8; i++) {
            try = try << 8;
            try = try | line[i];
            decToBinary(try);
            printf(" - 8 bit shift\n");
        }
        decToBinary(try);
        printf(" - FINAL SHIFT VALUE\n");
        printf("A: %s\n", line);
        printf("B: %x\n", (uint64_t)line);
        iteration->block = try;
        if(head == NULL)
        {
            iteration->next = NULL;
            iteration->size = 8;
            head = iteration;
        }
        else {
            iteration->next = head;
            iteration->size = 8;
            head = iteration;
        }
    }
    
    //last line null terminator and block creation
    line[len-1] = '\0';
    printf("LASTLINE: %s\n", line);
    BLOCKLIST temp = malloc(sizeof(BLOCKLIST));
    if (temp == NULL) {
        return NULL;
    }
    uint64_t try2 = 0;
    try2 = line[0];
    for(i = 1; i < len; i++) {
        try2 = try2 << 8;
        try2 = try2 | line[i];
        decToBinary(try2);
        printf(" - 8 bit shift\n");
    }
    decToBinary(try2);
    temp->block = try2;
    if(head == NULL)
    {
        temp->next = NULL;
        temp->size = len-1;
        head = temp;
    }
    else {
        temp->next = head;
        temp->size = len-1;
        head = temp;
    }
    printf("C: %x\n", head->block);
    
    head = pad_last_block(head);
    
    exit(0);
    printf("D: %s\n", head->next->block);
    printf("E: %s\n", head->next->next->block);
    exit(0);
    
    return head;
}

// Reads the encrypted message, and returns a linked list of blocks, each 64 bits.
// Note that, because of the padding that was done by the encryption, the length of
// this file should always be a multiople of 8 bytes. The output is a linked list of
// 64-bit blocks.
BLOCKLIST read_encrypted_file(FILE *msg_fp) {
    // TODO
    return NULL;
}

// Reads 56-bit key into a 64 bit unsigned int. We will ignore the most significant byte,
// i.e. we'll assume that the top 8 bits are all 0. In real DES, these are used to check
// that the key hasn't been corrupted in transit. The key file is ASCII, consisting of
// exactly one line. That line has a single hex number on it, the key, such as 0x08AB674D9.
KEYTYPE read_key(FILE *key_fp) {
    // TODO
    //load key.txt file
    char *line = NULL;
    unsigned int key;
    //Read key into unsigned integer.
    fscanf(key_fp, "%x", &key);
    //Convert to 64 bit integer.
    key = key | 0x00000000;
    KEYTYPE toReturn = (KEYTYPE) key;
    return toReturn;
}

// Write the encrypted blocks to file. The encrypted file is in binary, i.e., you can
// just write each 64-bit block directly to the file, without any conversion.
void write_encrypted_message(FILE *msg_fp, BLOCKLIST msg) {
    while(msg != NULL) {
        fprintf(msg_fp, "%d", msg->block);
        msg = msg->next;
    }
}

// Write the encrypted blocks to file. This is called by the decryption routine.
// The output file is a plain ASCII file, containing the decrypted text message.
void write_decrypted_message(FILE *msg_fp, BLOCKLIST msg) {
    while(msg != NULL) {
        fprintf(msg_fp, "%d", msg->block);
        msg = msg->next;
    }
}

/////////////////////////////////////////////////////////////////////////////
// Encryption
/////////////////////////////////////////////////////////////////////////////

// Encrypt one block. This is where the main computation takes place. It takes
// one 64-bit block as input, and returns the encrypted 64-bit block. The
// subkeys needed by the Feistel Network is given by the function getSubKey(i).
BLOCKTYPE des_enc(BLOCKTYPE v){
    //initial permutation
    int i = 0;
    uint64_t newnum = 0;
    convertToBinaryy(v, 63);
    printf(" - initial pre perm\n");
    for(i = 0; i < 64; i++) {
        int pos = init_perm[i];
        
        //get bit in position
        uint64_t newpos = (1 << pos) & v;
        uint64_t oldpos = (1 << i) & v;
        //convertToBinaryy(newpos, 63);
        //printf(" - newpos \n");
        //convertToBinaryy(oldpos, 63);
        //printf(" - oldpos \n");
        newnum = (newnum | ((1 << i) & newpos));
        newnum = (newnum | ((1 << pos) & oldpos));
        //printf("newnum=%d\n\n", newnum);
    }
    convertToBinaryy(newnum, 63);
    printf(" - post perm\n");
    return 0;
}

// Encrypt the blocks in ECB mode. The blocks have already been padded
// by the input routine. The output is an encrypted list of blocks.
BLOCKLIST des_enc_ECB(BLOCKLIST msg) {
    // TODO
    // Should call des_enc in here repeatedly
    return NULL;
}

// Same as des_enc_ECB, but encrypt the blocks in Counter mode.
// SEE: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
// Start the counter at 0.
BLOCKLIST des_enc_CTR(BLOCKLIST msg) {
    // TODO
    // Should call des_enc in here repeatedly
    return NULL;
}

/////////////////////////////////////////////////////////////////////////////
// Decryption
/////////////////////////////////////////////////////////////////////////////
// Decrypt one block.
BLOCKTYPE des_dec(BLOCKTYPE v){
    // TODO
    return 0;
}

// Decrypt the blocks in ECB mode. The input is a list of encrypted blocks,
// the output a list of plaintext blocks.
BLOCKLIST des_dec_ECB(BLOCKLIST msg) {
    // TODO
    // Should call des_dec in here repeatedly
    return NULL;
}

// Decrypt the blocks in Counter mode
BLOCKLIST des_dec_CTR(BLOCKLIST msg) {
    // TODO
    // Should call des_enc in here repeatedly
    return NULL;
}

/////////////////////////////////////////////////////////////////////////////
// Main routine
/////////////////////////////////////////////////////////////////////////////

void encrypt (int argc, char **argv) {
    FILE *msg_fp = fopen("message.txt", "r");
    BLOCKLIST msg = read_cleartext_message(msg_fp);
    printf("A: %x %s", msg->next->block, msg->next->block);
    fclose(msg_fp);
    
    BLOCKLIST encrypted_message;
    if (!strcmp(argv[2], "-ecb")) {
        encrypted_message = des_enc_ECB(msg);
    } else if (!strcmp(argv[2], "-ctr")) {
        encrypted_message = des_enc_CTR(msg);
    } else {
        printf("No such mode.\n");
    };
    FILE *encrypted_msg_fp = fopen("encrypted_msg.bin", "wb");
    write_encrypted_message(encrypted_msg_fp, encrypted_message);
    fclose(encrypted_msg_fp);
}

void decrypt (int argc, char **argv) {
    FILE *encrypted_msg_fp = fopen("encrypted_msg.bin", "r");
    BLOCKLIST encrypted_message = read_encrypted_file(encrypted_msg_fp);
    fclose(encrypted_msg_fp);
    
    BLOCKLIST decrypted_message;
    if (!strcmp(argv[2], "-ecb")) {
        decrypted_message = des_dec_ECB(encrypted_message);
    } else if (!strcmp(argv[2], "-ctr")) {
        encrypted_message = des_dec_CTR(encrypted_message);
    } else {
        printf("No such mode.\n");
    };
    
    FILE *decrypted_msg_fp = fopen("decrypted_message.txt", "wb");
    write_decrypted_message(decrypted_msg_fp, decrypted_message);
    fclose(decrypted_msg_fp);
}

int main(int argc, char **argv){
    FILE *key_fp = fopen("key.txt","r");
    KEYTYPE key = read_key(key_fp);
    generateSubKeys(key);              // This does nothing right now.
    fclose(key_fp);
    
    if (!strcmp(argv[1], "-enc")) {
        encrypt(argc, argv);
    } else if (!strcmp(argv[1], "-dec")) {
        decrypt(argc, argv);
    } else {
        printf("First argument should be -enc or -dec\n");
    }
    return 0;
}
