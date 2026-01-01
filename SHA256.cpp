#include "SHA256.hpp"
#include <cstring>
#include <algorithm>
#include <cstdio>

#define ROTR(x,n) ((x >> n) | (x << (32-n)))
#define CH(x,y,z) ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10))

SHA256::SHA256() {
    sha256_init();
}

SHA256::~SHA256() {
    std::fill(std::begin(state_), std::end(state_), 0);
    std::fill(std::begin(buffer_), std::end(buffer_), 0);
    bitlen_ = 0;
    buflen_ = 0;
}

void SHA256::sha256_init() {
    state_[0] = 0x6a09e667;
    state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372;
    state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f;
    state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab;
    state_[7] = 0x5be0cd19;
    bitlen_ = 0;
    buflen_ = 0;
}

void SHA256::compress(const uint8_t block[BLOCK_SIZE]) {
    uint32_t W[64];
    for(int i=0;i<16;i++){
        W[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
    for(int i=16;i<64;i++){
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    uint32_t a=state_[0], b=state_[1], c=state_[2], d=state_[3];
    uint32_t e=state_[4], f=state_[5], g=state_[6], h=state_[7];

    for(int i=0;i<64;i++){
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + K[i] + W[i];
        uint32_t t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
    state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
}

void SHA256::sha256_update(const uint8_t* data, size_t len) {
    for(size_t i=0;i<len;i++){
        buffer_[buflen_++] = data[i];
        if(buflen_==BLOCK_SIZE){
            compress(buffer_);
            bitlen_ += 512;
            buflen_ = 0;
        }
    }
}

void SHA256::padAndFinalize(uint8_t out[HASH_SIZE]) {
    bitlen_ += buflen_ * 8;
    buffer_[buflen_++] = 0x80;
    if(buflen_ > 56){
        while(buflen_ < 64) buffer_[buflen_++] = 0;
        compress(buffer_);
        buflen_ = 0;
    }
    while(buflen_ < 56) buffer_[buflen_++] = 0;
    for(int i=7;i>=0;i--){
        buffer_[buflen_++] = (bitlen_ >> (i*8)) & 0xff;
    }
    compress(buffer_);
    for(int i=0;i<8;i++){
        out[i*4] = (state_[i] >> 24) & 0xff;
        out[i*4+1] = (state_[i] >> 16) & 0xff;
        out[i*4+2] = (state_[i] >> 8) & 0xff;
        out[i*4+3] = state_[i] & 0xff;
    }
    // очистка буфера
    std::fill(std::begin(buffer_), std::end(buffer_), 0);
}

void SHA256::sha256_final(uint8_t out[HASH_SIZE]){
    padAndFinalize(out);
}

void SHA256::sha256_compute(const uint8_t* data, size_t len, uint8_t out[HASH_SIZE]){
    SHA256 sha;
    sha.sha256_init();
    sha.sha256_update(data,len);
    sha.sha256_final(out);
}

int SHA256::sha256_hmac(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t out[HASH_SIZE])
{
    uint8_t key_block[BLOCK_SIZE]{0};
    if(key_len>BLOCK_SIZE){
        sha256_compute(key,key_len,key_block);
    }else{
        std::copy(key,key+key_len,key_block);
    }
    uint8_t o_key_pad[BLOCK_SIZE], i_key_pad[BLOCK_SIZE];
    for(size_t i=0;i<BLOCK_SIZE;i++){
        o_key_pad[i]=key_block[i]^0x5c;
        i_key_pad[i]=key_block[i]^0x36;
    }

    SHA256 sha_inner;
    sha_inner.sha256_init();
    sha_inner.sha256_update(i_key_pad,BLOCK_SIZE);
    sha_inner.sha256_update(data,data_len);
    uint8_t inner_hash[HASH_SIZE];
    sha_inner.sha256_final(inner_hash);

    SHA256 sha_outer;
    sha_outer.sha256_init();
    sha_outer.sha256_update(o_key_pad,BLOCK_SIZE);
    sha_outer.sha256_update(inner_hash,HASH_SIZE);
    sha_outer.sha256_final(out);

    // очистка
    std::fill(std::begin(key_block),std::end(key_block),0);
    std::fill(std::begin(o_key_pad),std::end(o_key_pad),0);
    std::fill(std::begin(i_key_pad),std::end(i_key_pad),0);
    std::fill(std::begin(inner_hash),std::end(inner_hash),0);

    return 0;
}

int SHA256::hashToHex(const uint8_t hash[HASH_SIZE],
                      char* out_hex, size_t out_hex_len)
{
    if(out_hex_len < HASH_SIZE*2+1) return -1;
    for(size_t i=0;i<HASH_SIZE;i++){
        snprintf(out_hex+i*2,3,"%02x",hash[i]);
    }
    out_hex[HASH_SIZE*2]=0;
    return 0;
}

bool SHA256::libraryReady(){ return true; }
