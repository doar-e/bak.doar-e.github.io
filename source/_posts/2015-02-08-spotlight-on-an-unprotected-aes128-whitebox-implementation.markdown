---
layout: post
title: "Spotlight on an unprotected AES128 white-box implementation"
date: 2015-02-08 22:59
comments: true
categories: [obfuscation, white-box, practical cryptography, aes128, encryption]
author: Axel "0vercl0k" Souchet
published: true
toc: true
---
# Introduction
I think it all began when I've worked on the [NSC2013](https://github.com/0vercl0k/stuffz/tree/master/NoSuchCon2013) crackme made by [@elvanderb](https://twitter.com/elvanderb), long story short you had an AES128 heavily obfuscated white-box implementation to break. The thing was you could actually solve the challenge in different ways: 

 1. the first one was the easiest one: you didn't need to know anything about white-box, crypto or even AES ; you could just see the function as a black-box & try to find "design flaws" in its inner-workings
 2. the elite way: this one involved to understand & recover the entire design of the white-box, then to identify design weaknesses that allows the challenger to directly attack & recover the encryption key. A really nice write-up has been recently written by [@doegox](https://twitter.com/doegox), check it out, really :): [Oppida/NoSuchCon challenge](http://wiki.yobi.be/wiki/NSC_Writeups).

The annoying thing is that you don't have a lot of understandable available C codes on the web that implement such things, nevertheless you do have quite some nice academic references ; they are a really good resource to build your own.

This post aims to present briefly, in a simple way what an AES white-box looks like ; and to show how its design is important if you want to not have your encryption key extracted :). The implementation I'm going to talk about today is not my creation at all, I just followed the first part (might do another post talking about the second part? Who knows) of a really [nice paper](https://github.com/0vercl0k/stuffz/raw/master/wbaes_attack/docs/a_tutorial_on_whitebox_aes.pdf) (even for non-mathematical / crypto guys like me!) written by James A. Muir.

The idea is simple: we will start from a clean AES128 encryption function in plain C, we will modify it & transform it into a white-box implementation in several steps.
As usual, all the codes are available on my github account; you are encourage to break & hack them!

Of course, we will use this post to briefly present what is the white-box cryptography, what are the goals & why it's kind of cool.

Before diving deep, here is the table of contents:

<div class='entry-content-toc'></div>

<!--more-->

# AES128

## Introduction
All right, here we are: this part is just a reminder of how AES (with a 128 bits key) roughly works. If you know that already, feel free to go to the next level. Basically in here I just want us to build our first function: a simple block encryption. The signature of the function will be something, as you expect, like this:

```c aes128_enc_base signature
void aes128_enc_base(unsigned char in[16], unsigned char out[16], unsigned char key[16])
```

The encryption works in eleven rounds, the first one & the last one are slightly different than the nine others ; but they all rely on four different operations. Those operations are called: AddRoundKey, SubBytes, ShiftRows, MixColumns. Each round modifies a 128 bits state with a 128 bits round-key. Those round-keys are generated from the encryption key after a key expansion (called key schedule) function. Note that the first round-key is actually the encryption key.

The first part of an AES encryption is to execute the key schedule in order to get our round-keys ; once we have them all it's just a matter of using the four different operations we saw to generate the encrypted plain-text.

I know that I quite like to see how crypto algorithms work in a visual way, if this is also your case check this SWF animation (no exploit in here, don't worry :)): [Rijndael_Animation_v4_eng.swf](http://www.formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng.swf) ; else you can also read the [FIPS-197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf) document.

## Key schedule
The key schedule is like the most important part of the algorithm. As I said a bit earlier, this function is a derivation one: it takes the encryption key as input and will generate the round-keys the encryption process will use as output.

I don't really feel like explaining in detail how it works (as it is a bit tricky to explain that with words), I would rather advise you to read the FIPS document or to follow the flash animation. Here is what my key schedule looks like:

```c aes key schedule
const unsigned char S_box[] = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };
#define DW(x) (*(unsigned int*)(x))
{
    unsigned int d;
    unsigned char round_keys[11][16] = { 0 };
    const unsigned char rcon[] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D };

    /// Key schedule -- Generate one subkey for each round
    /// http://www.formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng.swf

    // First round-key is the actual key
    memcpy(&round_keys[0][0], key, 16);
    d = DW(&round_keys[0][12]);
    for (size_t i = 1; i < 11; ++i)
    {
        // Rotate `d` 8 bits to the right
        d = ROT(d);

        // Takes every bytes of `d` & substitute them using `S_box`
        unsigned char a1, a2, a3, a4;
        // Do not forget to xor this byte with `rcon[i]`
        a1 = S_box[(d >> 0) & 0xff] ^ rcon[i]; // a1 is the LSB
        a2 = S_box[(d >> 8) & 0xff];
        a3 = S_box[(d >> 16) & 0xff];
        a4 = S_box[(d >> 24) & 0xff];

        d = (a1 << 0) | (a2 << 8) | (a3 << 16) | (a4 << 24);

        // Now we can generate the current roundkey using the previous one
        for (size_t j = 0; j < 4; j++)
        {
            d ^= DW(&(round_keys[i - 1][j * 4]));
            *(unsigned int*)(&(round_keys[i][j * 4])) = d;
        }
    }
}
```

Sweet, feel free to dump the round keys and to compare them with an official test vector to convince you that this thing works. Once we have that function, we need to build the different primitives that the core encryption algorithm will use & reuse to generate the encrypted block. Some of them are like 1 line of C, really simple ; some others are a bit more twisted, but whatever.

## Encryption process
### Transformations
#### AddRoundKey
This one is a really simple one: it takes a round key (according to which round you are currently in), the state & you xor every single byte of the state with the round-key.

```c AddRoundKey
void AddRoundKey(unsigned char roundkey[16], unsigned char out[16])
{
    for (size_t i = 0; i < 16; ++i)
        out[i] ^= roundkey[i];
}
```

#### SubBytes
Another simple one: it takes the state as input & will substitute every byte using the forward substitution box `S_box`.

```c SubBytes
void SubBytes(unsigned char out[16])
{
    for (size_t i = 0; i < 16; ++i)
        out[i] = S_box[out[i]];
}
```

If you are interested in how the values of the `S_box` are computed, you should read the following blogpost [AES SBox and ParisGP](http://kutioo.blogspot.fr/2013/11/aes-sbox-and-parigp.html) written by my mate [@kutioo](https://twitter.com/kutioo).

#### ShiftRows
This operation is a bit less tricky, but still is fairly straightforward. Imagine that the state is a 4x4 matrix, you just have to left rotate the second line by 1 byte, the third one by 2 bytes & finally the last one by 3 bytes. This can be done in C like this:

```c ShiftRows
__forceinline void ShiftRows(unsigned char out[16])
{
    // +----+----+----+----+
    // | 00 | 04 | 08 | 12 |
    // +----+----+----+----+
    // | 01 | 05 | 09 | 13 |
    // +----+----+----+----+
    // | 02 | 06 | 10 | 14 |
    // +----+----+----+----+
    // | 03 | 07 | 11 | 15 |
    // +----+----+----+----+
    unsigned char tmp1, tmp2;

    tmp1 = out[1];
    out[1] = out[5];
    out[5] = out[9];
    out[9] = out[13];
    out[13] = tmp1;

    tmp1 = out[2];
    tmp2 = out[6];
    out[2] = out[10];
    out[6] = out[14];
    out[10] = tmp1;
    out[14] = tmp2;

    tmp1 = out[3];
    out[3] = out[15];
    out[15] = out[11];
    out[11] = out[7];
    out[7] = tmp1;
}
```

#### MixColumns
I guess this one is the less trivial one to implement & understand. But basically it is a "matrix multiplication" (in GF(2^8) though hence the double-quotes) between 4 bytes of the state (row matrix) against a fixed 4x4 matrix. That gives you 4 new state bytes, so you do that for every double-words of your state.

Now, I kind of cheated for my implementation: instead of implementing the "weird" multiplication, I figured I could use a pre-computed table instead to avoid all the hassle. Because the fixed matrix has only 3 different values (1, 2 & 3) the final table has a really small memory footprint: 3*0x100 bytes basically (if I'm being honest I even stole this table from [@elvanderb](https://twitter.com/elvanderb)'s [crazy white-box generator](http://pastebin.com/MvXpGZts)).

```c gmul
const unsigned char gmul[3][0x100] = {
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF },
    { 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E, 0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE, 0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE, 0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE, 0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05, 0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25, 0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45, 0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65, 0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85, 0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5, 0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5, 0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5 },
    { 0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x18, 0x1B, 0x1E, 0x1D, 0x14, 0x17, 0x12, 0x11, 0x30, 0x33, 0x36, 0x35, 0x3C, 0x3F, 0x3A, 0x39, 0x28, 0x2B, 0x2E, 0x2D, 0x24, 0x27, 0x22, 0x21, 0x60, 0x63, 0x66, 0x65, 0x6C, 0x6F, 0x6A, 0x69, 0x78, 0x7B, 0x7E, 0x7D, 0x74, 0x77, 0x72, 0x71, 0x50, 0x53, 0x56, 0x55, 0x5C, 0x5F, 0x5A, 0x59, 0x48, 0x4B, 0x4E, 0x4D, 0x44, 0x47, 0x42, 0x41, 0xC0, 0xC3, 0xC6, 0xC5, 0xCC, 0xCF, 0xCA, 0xC9, 0xD8, 0xDB, 0xDE, 0xDD, 0xD4, 0xD7, 0xD2, 0xD1, 0xF0, 0xF3, 0xF6, 0xF5, 0xFC, 0xFF, 0xFA, 0xF9, 0xE8, 0xEB, 0xEE, 0xED, 0xE4, 0xE7, 0xE2, 0xE1, 0xA0, 0xA3, 0xA6, 0xA5, 0xAC, 0xAF, 0xAA, 0xA9, 0xB8, 0xBB, 0xBE, 0xBD, 0xB4, 0xB7, 0xB2, 0xB1, 0x90, 0x93, 0x96, 0x95, 0x9C, 0x9F, 0x9A, 0x99, 0x88, 0x8B, 0x8E, 0x8D, 0x84, 0x87, 0x82, 0x81, 0x9B, 0x98, 0x9D, 0x9E, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8F, 0x8C, 0x89, 0x8A, 0xAB, 0xA8, 0xAD, 0xAE, 0xA7, 0xA4, 0xA1, 0xA2, 0xB3, 0xB0, 0xB5, 0xB6, 0xBF, 0xBC, 0xB9, 0xBA, 0xFB, 0xF8, 0xFD, 0xFE, 0xF7, 0xF4, 0xF1, 0xF2, 0xE3, 0xE0, 0xE5, 0xE6, 0xEF, 0xEC, 0xE9, 0xEA, 0xCB, 0xC8, 0xCD, 0xCE, 0xC7, 0xC4, 0xC1, 0xC2, 0xD3, 0xD0, 0xD5, 0xD6, 0xDF, 0xDC, 0xD9, 0xDA, 0x5B, 0x58, 0x5D, 0x5E, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4F, 0x4C, 0x49, 0x4A, 0x6B, 0x68, 0x6D, 0x6E, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7F, 0x7C, 0x79, 0x7A, 0x3B, 0x38, 0x3D, 0x3E, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2F, 0x2C, 0x29, 0x2A, 0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1F, 0x1C, 0x19, 0x1A }
    };
```

Once you have this magic table, the multiplication gets really easy. Let's take an example:

{%img center /images/spotlight_on_an_unprotected_aes128_white-box_implementation/mixcolumn_example.png %}

As I said, the four bytes at the left are from your state & the 4x4 matrix is the fixed one (filled only with 3 different values). To have the result of this multiplication you just have to execute this:

```python mult
reduce(operator.xor, [gmul[1][0xd4], gmul[2][0xbf], gmul[0][0x5d], gmul[0][0x30]])
```

The first indexes in the table are the actual values taken from the 4x4 matrix minus one (because our array is going to be addressed from index 0). So then you can declare your own 4x4 matrix with proper indexes & do the multiplication four times:

```c MixColumns
void MixColumns(unsigned char out[16])
{
    const unsigned char matrix[16] = {
        1, 2, 0, 0,
        0, 1, 2, 0,
        0, 0, 1, 2,
        2, 0, 0, 1
    },
    
    /// In[19]: reduce(operator.xor, [gmul[1][0xd4], gmul[2][0xbf], gmul[0][0x5d], gmul[0][0x30]])
    /// Out[19] : 4
    /// In [20]: reduce(operator.xor, [gmul[0][0xd4], gmul[1][0xbf], gmul[2][0x5d], gmul[0][0x30]])
    /// Out[20]: 102
    
    gmul[3][0x100] = {
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF },
        { 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E, 0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE, 0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE, 0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE, 0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05, 0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25, 0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45, 0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65, 0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85, 0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5, 0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5, 0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5 },
        { 0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x18, 0x1B, 0x1E, 0x1D, 0x14, 0x17, 0x12, 0x11, 0x30, 0x33, 0x36, 0x35, 0x3C, 0x3F, 0x3A, 0x39, 0x28, 0x2B, 0x2E, 0x2D, 0x24, 0x27, 0x22, 0x21, 0x60, 0x63, 0x66, 0x65, 0x6C, 0x6F, 0x6A, 0x69, 0x78, 0x7B, 0x7E, 0x7D, 0x74, 0x77, 0x72, 0x71, 0x50, 0x53, 0x56, 0x55, 0x5C, 0x5F, 0x5A, 0x59, 0x48, 0x4B, 0x4E, 0x4D, 0x44, 0x47, 0x42, 0x41, 0xC0, 0xC3, 0xC6, 0xC5, 0xCC, 0xCF, 0xCA, 0xC9, 0xD8, 0xDB, 0xDE, 0xDD, 0xD4, 0xD7, 0xD2, 0xD1, 0xF0, 0xF3, 0xF6, 0xF5, 0xFC, 0xFF, 0xFA, 0xF9, 0xE8, 0xEB, 0xEE, 0xED, 0xE4, 0xE7, 0xE2, 0xE1, 0xA0, 0xA3, 0xA6, 0xA5, 0xAC, 0xAF, 0xAA, 0xA9, 0xB8, 0xBB, 0xBE, 0xBD, 0xB4, 0xB7, 0xB2, 0xB1, 0x90, 0x93, 0x96, 0x95, 0x9C, 0x9F, 0x9A, 0x99, 0x88, 0x8B, 0x8E, 0x8D, 0x84, 0x87, 0x82, 0x81, 0x9B, 0x98, 0x9D, 0x9E, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8F, 0x8C, 0x89, 0x8A, 0xAB, 0xA8, 0xAD, 0xAE, 0xA7, 0xA4, 0xA1, 0xA2, 0xB3, 0xB0, 0xB5, 0xB6, 0xBF, 0xBC, 0xB9, 0xBA, 0xFB, 0xF8, 0xFD, 0xFE, 0xF7, 0xF4, 0xF1, 0xF2, 0xE3, 0xE0, 0xE5, 0xE6, 0xEF, 0xEC, 0xE9, 0xEA, 0xCB, 0xC8, 0xCD, 0xCE, 0xC7, 0xC4, 0xC1, 0xC2, 0xD3, 0xD0, 0xD5, 0xD6, 0xDF, 0xDC, 0xD9, 0xDA, 0x5B, 0x58, 0x5D, 0x5E, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4F, 0x4C, 0x49, 0x4A, 0x6B, 0x68, 0x6D, 0x6E, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7F, 0x7C, 0x79, 0x7A, 0x3B, 0x38, 0x3D, 0x3E, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2F, 0x2C, 0x29, 0x2A, 0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1F, 0x1C, 0x19, 0x1A }
    };

    for (size_t i = 0; i < 4; ++i)
    {
        unsigned char a = out[i * 4 + 0];
        unsigned char b = out[i * 4 + 1];
        unsigned char c = out[i * 4 + 2];
        unsigned char d = out[i * 4 + 3];

        out[i * 4 + 0] = gmul[matrix[0]][a] ^ gmul[matrix[1]][b] ^ gmul[matrix[2]][c] ^ gmul[matrix[3]][d];
        out[i * 4 + 1] = gmul[matrix[4]][a] ^ gmul[matrix[5]][b] ^ gmul[matrix[6]][c] ^ gmul[matrix[7]][d];
        out[i * 4 + 2] = gmul[matrix[8]][a] ^ gmul[matrix[9]][b] ^ gmul[matrix[10]][c] ^ gmul[matrix[11]][d];
        out[i * 4 + 3] = gmul[matrix[12]][a] ^ gmul[matrix[13]][b] ^ gmul[matrix[14]][c] ^ gmul[matrix[15]][d];
    }
}
```

### Combine them together
Now we have everything we need, it is going to be easy peasy ; really:

 1. The initial state is populated with the encryption key
 2. Generate the round-keys thanks to the key schedule ; remember 11 keys, the first one being the plain encryption key
 3. The first different round is a simple `AddRoundKey` operation
 4. Then we enter in the main loop which does 9 rounds:
    1. `SubBytes`
    2. `ShiftRows`
    3. `MixColumns`
    4. `AddRoundKey`
 5. Last round which is also a bit different:
    1. `SubBytes`
    2. `ShiftRows`
    3. `AddRoundKey`
 6. The state is now your encrypted block, yay!

Here we are, we finally have our AES128 encryption function that we will use as a reference:

```c aes128_enc_base
void aes128_enc_base(unsigned char in[16], unsigned char out[16], unsigned char key[16])
{
    unsigned int d;
    unsigned char round_keys[11][16] = { 0 };
    const unsigned char rcon[] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D };

    /// Key schedule -- Generate one subkey for each round
    /// http://www.formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng.swf

    // First round-key is the actual key
    memcpy(&round_keys[0][0], key, 16);
    d = DW(&round_keys[0][12]);
    for (size_t i = 1; i < 11; ++i)
    {
        // Rotate `d` 8 bits to the right
        d = ROT(d);

        // Takes every bytes of `d` & substitute them using `S_box`
        unsigned char a1, a2, a3, a4;
        // Do not forget to xor this byte with `rcon[i]`
        a1 = S_box[(d >> 0) & 0xff] ^ rcon[i]; // a1 is the LSB
        a2 = S_box[(d >> 8) & 0xff];
        a3 = S_box[(d >> 16) & 0xff];
        a4 = S_box[(d >> 24) & 0xff];

        d = (a1 << 0) | (a2 << 8) | (a3 << 16) | (a4 << 24);

        // Now we can generate the current roundkey using the previous one
        for (size_t j = 0; j < 4; j++)
        {
            d ^= DW(&(round_keys[i - 1][j * 4]));
            *(unsigned int*)(&(round_keys[i][j * 4])) = d;
        }
    }

    /// Dig in now
    /// The initial round is just AddRoundKey with the first one (being the encryption key)
    memcpy(out, in, 16);
    AddRoundKey(round_keys[0], out);

    /// Let's start the encryption process now
    for (size_t i = 1; i < 10; ++i)
    {
        SubBytes(out);
        ShiftRows(out);
        MixColumns(out);
        AddRoundKey(round_keys[i], out);
    }

    /// Last round which is a bit different
    SubBytes(out);
    ShiftRows(out);
    AddRoundKey(round_keys[10], out);
}
```

Not that bad right? And we can even prepare a function that tests if the encrypted block is valid or not (this is really going to be useful as soon as we start to tweak the implementation):

```c tests
unsigned char tests()
{
    /// AES128ENC
    {
        unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
        unsigned char out[16] = { 0 };
        unsigned char plain[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
        unsigned char expected[16] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
        printf("> aes128_enc_base ..");
        aes128_enc_base(plain, out, key);
        if (memcmp(out, expected, 16) != 0)
        {
            printf("FAIL\n");
            return 0;
        }
        printf("OK\n");
    }

    return 1;
}
```

Brilliant.

# White-boxing AES128 in ~7 steps
## Introduction
I'm no crypto-expert whatsoever but I'll still try to explain what "white-boxing" AES means for us. Currently, we have a block encryption primitive with the following signature `void aes128_enc_base(unsigned char in[16], unsigned char out[16], unsigned char key[16])`. One of the purpose of the white-boxing process is going to "remove", or I should say "hide" instead, the key. Your primitive will work without any input key parameter, but the key won't be hard-coded either in the body of the function. You'll be able to encrypt things without any apparent key.

A perfectly secure but unpractical version of a white-box AES would be to have a big hash-table: the keys would be every single possible plain-texts and the values would be their encrypted version with the key you want. That should give you a really clear idea of what a white-box is. But obviously storing that kind of table in memory is another problem by itself :-).

Instead of using that "naive" idea, researchers came up with way to pre-compute "things" that involve the round-keys in order to hide everything. The other goal of a real white-box is to be resistant to reverse-engineering & dynamic/static analysis. Even if you are able to read whatever memory you want, you still should not be able to extract the key. The [NoSuchCon2013](https://github.com/0vercl0k/stuffz/tree/master/NoSuchCon2013) crackme is again a really good example of that: we had to wait for 2 years before [@doegox](https://twitter.com/doegox) actually works his magic to extract the key.

The design of the implementation is really really important in order to make that key extraction process the most difficult.

In this part, we are using James A. Muir's [paper](https://github.com/0vercl0k/stuffz/raw/master/wbaes_attack/docs/a_tutorial_on_whitebox_aes.pdf) to rewrite step by step our implementation in order to make it possible to combine several operations between them & make pre-computed table out of them. At the end of this part we should have a working AES128 encryption primitive that doesn't require an hard-coded key. But we will also build in parallel a tool used to generate the different tables our implementation is going to need: obviously, this tool is going to need both the key schedule & the encryption key to be able to generate the look-up tables.
Long story short: the first steps are basically going to reorder / rewrite the logic of the encryption, & the last ones will really transform the implementation in a white-box.

Anyway, let's go folks!

## Step 1: bring the first `AddRoundKey` in the loop & kick out the last one out of it
This one is really easy: basically we just have to change our loop to start at `i=0` until `i=8` (inclusive), move the first `AddRoundKey` in the loop, and move the last one outside of it.

The encryption loop should look like this now:

```c aes128_enc_reorg_step1
void aes128_enc_reorg_step1(unsigned char in[16], unsigned char out[16], unsigned char key[16])
{
[...]
    /// Key schedule -- Generate one subkey for each round
[...]
    memcpy(out, in, 16);

    for (size_t i = 0; i < 9; ++i)
    {
        AddRoundKey(round_keys[i], out);
        SubBytes(out);
        ShiftRows(out);
        MixColumns(out);
    }

    AddRoundKey(round_keys[9], out);
    SubBytes(out);
    ShiftRows(out);
    AddRoundKey(round_keys[10], out);
}
```

## Step 2: `SubBytes` then `ShiftRows` equals `ShiftRows` then `SubBytes`
Yet another easy one: because `SubBytes` is just replacing a byte by its substitution (stored in `S_box`), you can apply `ShiftRows` before `SubBytes` or `SubBytes` before `ShiftRows` ; you will get the same result. So let's exchange them:

```c aes128_enc_reorg_step2
void aes128_enc_reorg_step2(unsigned char in[16], unsigned char out[16], unsigned char key[16])
{
[...]
    /// Key schedule -- Generate one subkey for each round
[...]
    memcpy(out, in, 16);

    /// Let's start the encryption process now
    for (size_t i = 0; i < 9; ++i)
    {
        AddRoundKey(round_keys[i], out);
        ShiftRows(out);
        SubBytes(out);
        MixColumns(out);
    }

    /// Last round which is a bit different
    AddRoundKey(round_keys[9], out);
    ShiftRows(out);
    SubBytes(out);
    AddRoundKey(round_keys[10], out);
}
```

## Step 3: `ShiftRows` first, but needs to `ShiftRows` the round-key
This one is a bit more tricky, but again it's more about reordering, rewriting the encryption loop than really replacing computation by look-up tables so far. Basically, the idea of this step is to start the encryption loop with a `ShiftRows` operation. Because of the way this operation is defined, if you put it first you also need to apply `ShiftRows` to the current round key in order to get the same result than `AddRoundKey`/`ShiftRows`.

```c aes128_enc_reorg_step3
void aes128_enc_reorg_step3(unsigned char in[16], unsigned char out[16], unsigned char key[16])
{
[...]
    /// Key schedule -- Generate one subkey for each round
[...]
    /// Let's start the encryption process now
    for (size_t i = 0; i < 9; ++i)
    {
        ShiftRows(out);
        ShiftRows(round_keys[i]);
        AddRoundKey(round_keys[i], out);
        SubBytes(out);
        MixColumns(out);
    }

    /// Last round which is a bit different
    ShiftRows(out);
    ShiftRows(round_keys[9]);
    AddRoundKey(round_keys[9], out);
    SubBytes(out);
    AddRoundKey(round_keys[10], out);
}
```

## Step 4: White-boxing it like it's hot, White-boxing it like it's hot
This step is a really important one for us, it's actually the first one where we are going to be able to both remove the key & start the tables generator project. The tables generator project basically generates everything we need to have our white-box AES encryption working.

Now we don't need the key schedule anymore in the AES encryption function (but obviously we will need it on the table generator side), and we can keep only the encryption loop.

The transformation introduced in this step is to create a look-up table that will replace `ShiftRows(round_keys[i])`/`AddRoundKey`/`SubBytes`. We can clearly see now how our round keys are going to be "diffused" & combined with different operations to make them "not trivially" (in fact they are, but let's say they are not right now) extractable. In order to have such a table, we need quite some space though: basically we need this table `Tboxes[10][16][0x100]`. We have 10 operations `ShiftRows(round_keys[i])`/`AddRoundKey`/`SubBytes`, 16 bytes of round keys in each one of them and the 0x100 for the bytes (`[0x00-0xFF]`) than can be encrypted.

The computation is not really hard:

 1. We compute the key schedule for a specific encryption key
 2. We populate the table this way:
     1. For each round key:
       1. For every byte possible:
         1. You compute `S_box[byte ^ ShiftRows(roundkey)[i]]`

The `S_box` part is for the `SubBytes` operation, the xor with one byte of the round key is for `AddRoundKey` & the rest is for `ShiftRows(round_keys[i])`. There is a special case for the 9th round key, where you have to include `AddRoundKey` of the latest round key. It's like we don't have 11 rounds anymore, but 10 now. As the 9th contains information about the round key 9th & 10th.

If you are confused about that bit, don't be ; it's just I suck at explaining things, but just have a look at the following code (especially at lines 47, 48):

```c wbaes128_unprotected_tables_generator.c:Tboxes generation
int main()
{
    unsigned char key[16] = "0vercl0k@doare-e";
    unsigned char plain_block[16] = "whatdup folks???";
    unsigned char round_keys[11][16] = { 0 };

    /// 10 -> we have 10 rounds
    /// 16 -> we have 16 bytes of round keys
    /// 0x100 -> we have to be able to encrypt every plain-text input byte [0-0xff]
    unsigned char Tboxes[10][16][0x100] = { 0 };

    key_schedule(key, round_keys);

    /// Remember we have 10 rounds & we want to combine AddRoundKey & SubBytes
    /// which is really simple.
    /// These so-called T-boxes are defined as follows:
    /// Tri(x) = S[x ^ ShiftRows(rk)[i]] ; r being the round number ([0-8]), x being the byte of plaintext, rk the roundkey & i the index ([0-15])
    printf("#pragma once\n");
    printf("// Table for key='%.16s'\n", key);
    printf("const unsigned char Tboxes[10][16][0x100] = \n{\n");
    for (size_t r = 0; r < 10; ++r)
    {
        printf("  {\n");
 
        ShiftRows(round_keys[r]);

        for (size_t i = 0; i < 16; ++i)
        {
            printf("    {\n      ");
            for (size_t x = 0; x < 0x100; ++x)
            {
                if (x != 0 && (x % 16) == 0)
                    printf("\n      ");

                Tboxes[r][i][x] = S_box[x ^ round_keys[r][i]];
                /// We need to include the bytes from the roundkey 10 to replace that:
                ///  ShiftRows(out);
                ///  ShiftRows(round_keys[9]);
                ///  AddRoundKey(round_keys[9], out);
                ///  SubBytes(out);
                ///  AddRoundKey(round_keys[10], out);
                ///
                /// By
                /// ShiftRows(out);
                /// for (size_t j = 0; j < 16; ++j)
                ///     out[j] = Tboxes[9][j][out[j]];
                if (r == 9)
                    Tboxes[r][i][x] ^= round_keys[10][i];

                printf("0x%.2x", Tboxes[r][i][x]);
                if ((x + 1) < 0x100)
                    printf(", ");
            }
            printf("\n    }");
            if ((i + 1) < 16)
                printf(",");

            printf("\n");
        }
        printf("  }");
        if ((r + 1) < 10)
            printf(",");
        printf("\n");
    }
    printf("};\n\n");
}
```

Now that we have this table created, we just need to actually use it in our encryption. Thanks to this table, the encryption loop is way more simple and pretty, check it out:

```c aes128_enc_wb_step1
void aes128_enc_wb_step1(unsigned char in[16], unsigned char out[16])
{
    memcpy(out, in, 16);

    for (size_t i = 0; i < 9; ++i)
    {
        ShiftRows(out);

        for (size_t j = 0; j < 16; ++j)
        {
            unsigned char x = Tboxes[i][j][out[j]];
            out[j] = x;
        }

        MixColumns(out);
    }

    ShiftRows(out);

    for (size_t j = 0; j < 16; ++j)
    {
        unsigned char x = Tboxes[9][j][out[j]];
        out[j] = x;
    }
}
```

## Step 5: Transforming `MixColumns` in a look-up table
OK, so this is maybe the "most difficult" part of the game: we have to transform our ugly `MixColumn` function in four look-up tables. Basically, we want to transform this:

```c before
out[i * 4 + 0] = gmul[matrix[0]][a] ^ gmul[matrix[1]][b] ^ gmul[matrix[2]][c] ^ gmul[matrix[3]][d];
out[i * 4 + 1] = gmul[matrix[4]][a] ^ gmul[matrix[5]][b] ^ gmul[matrix[6]][c] ^ gmul[matrix[7]][d];
out[i * 4 + 2] = gmul[matrix[8]][a] ^ gmul[matrix[9]][b] ^ gmul[matrix[10]][c] ^ gmul[matrix[11]][d];
out[i * 4 + 3] = gmul[matrix[12]][a] ^ gmul[matrix[13]][b] ^ gmul[matrix[14]][c] ^ gmul[matrix[15]][d];
```

by this (where `Ty[0-4]` are the look-up tables I mentioned just above):

```c after
DW(&out[j * 4]) = Ty[0][a] ^ Ty[1][b] ^ Ty[2][c] ^ Ty[3][d];
```

We know that `gmul[X]` gives you 1 byte, and we can see those four lines use `gmul[X][a]` where `X` is constant. You can also see that basically those four lines take 4 bytes as input `a`, `b`, `c` & `d` and will generate 4 bytes as output.

The idea is to combine `gmul[matrix[0]][a]`, `gmul[matrix[4]][a]`, `gmul[matrix[8]][a]` & `gmul[matrix[12]][a]` inside a single double-word. We do the same for `b`, `c` & `d` so that we can directly apply the `xor` operation between double-words now ; the result will also be a double-word so we have our 4 output bytes. We just re-factorized 4 individual computations (1 byte as input, 1 byte as output) into a single one (4 bytes as input, 4 bytes as output).

With that in mind, the tables generation function writes nearly by itself:

```c wbaes128_unprotected_tables_generator.c:Ty tables generation
int main()
{
[...]
    typedef union
    {
        unsigned char b[4];
        unsigned int i;
    } magic_int;

    /// 4 -> four rows MC
    /// 0x100 -> for every char
    unsigned int Ty[4][0x100] = { 0 };
    printf("const unsigned int Ty[4][16][0x100] =\n{\n");
    for (size_t i = 0; i < 4; ++i)
    {
        printf("  {\n    ");
        for (size_t j = 0; j < 0x100; ++j)
        {
            if (j != 0 && (j % 16) == 0)
                printf("\n    ");

            magic_int mi;

            mi.b[0] = gmul[matrix[i + 0]][j];
            mi.b[1] = gmul[matrix[i + 4]][j];
            mi.b[2] = gmul[matrix[i + 8]][j];
            mi.b[3] = gmul[matrix[i + 12]][j];

            Ty[i][j] = mi.i;

            printf("0x%.8x", Ty[i][j]);
            if ((j + 1) < 0x100)
                printf(", ");
        }

        printf("\n  }");
        if ((i + 1) < 4)
            printf(",");
        printf("\n");
    }
    printf("};\n");
}
```

Glad to replace that `MixColumn` call now:

```c aes128_enc_wb_step2
void aes128_enc_wb_step2(unsigned char in[16], unsigned char out[16])
{
    memcpy(out, in, 16);

    /// Let's start the encryption process now
    for (size_t i = 0; i < 9; ++i)
    {
        ShiftRows(out);

        for (size_t j = 0; j < 16; ++j)
        {
            unsigned char x = Tboxes[i][j][out[j]];
            out[j] = x;
        }
        
        for (size_t j = 0; j < 4; ++j)
        {
            unsigned char a = out[j * 4 + 0];
            unsigned char b = out[j * 4 + 1];
            unsigned char c = out[j * 4 + 2];
            unsigned char d = out[j * 4 + 3];

            DW(&out[j * 4]) = Ty[0][a] ^ Ty[1][b] ^ Ty[2][c] ^ Ty[3][d];
        }
    }

    /// Last round which is a bit different
    ShiftRows(out);

    for (size_t j = 0; j < 16; ++j)
    {
        unsigned char x = Tboxes[9][j][out[j]];
        out[j] = x;
    }
}
```

You can even make it cleaner by merging the two inner-loops & make them both handle 4 bytes of data by 4 bytes of data:

```c aes128_enc_wb_step3
// Unified the loops by treating the state 4 bytes by 4 bytes
void aes128_enc_wb_step3(unsigned char in[16], unsigned char out[16])
{
    memcpy(out, in, 16);

    /// Let's start the encryption process now
    for (size_t i = 0; i < 9; ++i)
    {
        ShiftRows(out);

        for (size_t j = 0; j < 4; ++j)
        {
            unsigned char a = out[j * 4 + 0];
            unsigned char b = out[j * 4 + 1];
            unsigned char c = out[j * 4 + 2];
            unsigned char d = out[j * 4 + 3];

            a = out[j * 4 + 0] = Tboxes[i][j * 4 + 0][a];
            b = out[j * 4 + 1] = Tboxes[i][j * 4 + 1][b];
            c = out[j * 4 + 2] = Tboxes[i][j * 4 + 2][c];
            d = out[j * 4 + 3] = Tboxes[i][j * 4 + 3][d];

            DW(&out[j * 4]) = Ty[0][a] ^ Ty[1][b] ^ Ty[2][c] ^ Ty[3][d];
        }
    }

    /// Last round which is a bit different
    ShiftRows(out);

    for (size_t j = 0; j < 16; ++j)
    {
        unsigned char x = Tboxes[9][j][out[j]];
        out[j] = x;
    }
}
```

## Step 6: Adding a little *xor* table

This step is a really simple one (& kind of useless) ; we just want to transform the *xor* operation between 2 double-words by a look-up table that does that between 2 nibbles (4 bits). Basically, you combine 8 nibbles to get a full double-word with *or* operations & some binary shifts. Easy peasy:

```c wbaes128_unprotected_tables_generator.c:Xor table generation
int main()
{
[...]
    /// Xor Tables
    /// Basically takes two nibbles in input & generate a nibble in output (x^y)
    unsigned char Xor[0x10][0x10] = { 0 };
    printf("const unsigned char Xor[0x10][0x10] =\n{\n");
    for (size_t i = 0; i < 0x10; ++i)
    {
        printf("  {\n    ");

        for (size_t j = 0; j < 0x10; ++j)
        {
            if (j != 0 && (j % 8) == 0)
                printf("\n    ");

            Xor[i][j] = i ^ j;
            printf("0x%.1x", Xor[i][j]);
            if ((j + 1) < 0x10)
                printf(", ");
        }

        printf("\n  }");
        if ((i + 1) < 0x10)
            printf(",");
        printf("\n");
    }
    printf("};\n");
    return EXIT_SUCCESS;
}
```

Which is directly used by our implementation:

```c aes128_enc_wb_step4
void aes128_enc_wb_step4(unsigned char in[16], unsigned char out[16])
{
    memcpy(out, in, 16);

    /// Let's start the encryption process now
    for (size_t i = 0; i < 9; ++i)
    {
        ShiftRows(out);

        for (size_t j = 0; j < 4; ++j)
        {
            unsigned char a = out[j * 4 + 0];
            unsigned char b = out[j * 4 + 1];
            unsigned char c = out[j * 4 + 2];
            unsigned char d = out[j * 4 + 3];

            a = out[j * 4 + 0] = Tboxes[i][j * 4 + 0][a];
            b = out[j * 4 + 1] = Tboxes[i][j * 4 + 1][b];
            c = out[j * 4 + 2] = Tboxes[i][j * 4 + 2][c];
            d = out[j * 4 + 3] = Tboxes[i][j * 4 + 3][d];

            unsigned int aa = Ty[0][a];
            unsigned int bb = Ty[1][b];
            unsigned int cc = Ty[2][c];
            unsigned int dd = Ty[3][d];

            out[j * 4 + 0] = (Txor[Txor[(aa >>  0) & 0xf][(bb >>  0) & 0xf]][Txor[(cc >>  0) & 0xf][(dd >>  0) & 0xf]])  | ((Txor[Txor[(aa >>  4) & 0xf][(bb >>  4) & 0xf]][Txor[(cc >>  4) & 0xf][(dd >>  4) & 0xf]]) << 4);
            out[j * 4 + 1] = (Txor[Txor[(aa >>  8) & 0xf][(bb >>  8) & 0xf]][Txor[(cc >>  8) & 0xf][(dd >>  8) & 0xf]])  | ((Txor[Txor[(aa >> 12) & 0xf][(bb >> 12) & 0xf]][Txor[(cc >> 12) & 0xf][(dd >> 12) & 0xf]]) << 4);
            out[j * 4 + 2] = (Txor[Txor[(aa >> 16) & 0xf][(bb >> 16) & 0xf]][Txor[(cc >> 16) & 0xf][(dd >> 16) & 0xf]])  | ((Txor[Txor[(aa >> 20) & 0xf][(bb >> 20) & 0xf]][Txor[(cc >> 20) & 0xf][(dd >> 20) & 0xf]]) << 4);
            out[j * 4 + 3] = (Txor[Txor[(aa >> 24) & 0xf][(bb >> 24) & 0xf]][Txor[(cc >> 24) & 0xf][(dd >> 24) & 0xf]])  | ((Txor[Txor[(aa >> 28) & 0xf][(bb >> 28) & 0xf]][Txor[(cc >> 28) & 0xf][(dd >> 28) & 0xf]]) << 4);
        }
    }

    /// Last round which is a bit different
    ShiftRows(out);

    for (size_t j = 0; j < 16; ++j)
    {
        unsigned char x = Tboxes[9][j][out[j]];
        out[j] = x;
    }
}
```

## Step 7: Combining TBoxes & Ty tables
The last step aims to combine the `Tboxes` with `Ty` tables and if you look at the code it doesn't seem really hard. We basically want the table to work this way: 1 byte as input (`a` for example in the previous code) & generate 4 bytes of outputs.

To compute such a table, you need to compute the `Tboxes` (or not, you can compute everything without relying on the `Tboxes` ; it's actually what I'm doing), & then you compute `Ty[Y][Tboxes[i][j][X]]` ; this is it, roughly. `X`, `i` and `j` are the unknown variables here, which means we will end-up with a table like that:

```c Tyboxes
const unsigned int Tyboxes[9][16][0x100];
```

Makes sense right?

So here is the code that generates that big table:

```c wbaes128_unprotected_tables_generator.c:Tyboxes table generation
int main()
{
[...]
    /// Tyboxes
    /// It's basically Tybox(Tboxes(x))
    unsigned int Tyboxes[9][16][0x100] = { 0 };
    printf("const unsigned int Tyboxes[9][16][0x100] =\n{\n");
    for (size_t r = 0; r < 9; ++r)
    {
        printf("  {\n");

        // ShiftRows(round_keys[r]); <- don't forget we already executed that to compute the Tboxes

        for (size_t i = 0; i < 16; ++i)
        {
            printf("    {\n      ");
            for (size_t x = 0; x < 0x100; ++x)
            {
                if (x != 0 && (x % 16) == 0)
                    printf("\n      ");

                unsigned char c = S_box[x ^ round_keys[r][i]];
                Tyboxes[r][i][x] = Ty[i % 4][c];

                printf("0x%.8x", Tyboxes[r][i][x]);
                if ((x + 1) < 0x100)
                    printf(", ");
            }

            printf("\n    }");
            if ((i + 1) < 16)
                printf(",");

            printf("\n");
        }
        printf("  }");
        if ((r + 1) < 10)
            printf(",");
        printf("\n");
    }
    printf("};\n");

    printf("const unsigned char Tboxes_[16][0x100] = \n{\n");
    for (size_t i = 0; i < 16; ++i)
    {
        printf("  {\n    ");
        for (size_t x = 0; x < 0x100; ++x)
        {
            if (x != 0 && (x % 16) == 0)
                printf("\n    ");

            Tboxes[9][i][x] = S_box[x ^ round_keys[9][i]] ^ round_keys[10][i];
            printf("0x%.2x", Tboxes[9][i][x]);
            if ((x + 1) < 0x100)
                printf(", ");
        }
        printf("\n  }");
        if ((i + 1) < 16)
            printf(",");

        printf("\n");
    }

    printf("};\n\n");
    return EXIT_SUCCESS;
}
```

We just have to take care of the last round which is a bit different as we saw earlier, but no biggie.

## Final code

Yeah, finally, here we are ; the final code of our (not protected) AES128 white-box:

```c aes128_enc_wb_final
void aes128_enc_wb_final(unsigned char in[16], unsigned char out[16])
{
    memcpy(out, in, 16);

    /// Let's start the encryption process now
    for (size_t i = 0; i < 9; ++i)
    {
        ShiftRows(out);

        for (size_t j = 0; j < 4; ++j)
        {
            unsigned int aa = Tyboxes[i][j * 4 + 0][out[j * 4 + 0]];
            unsigned int bb = Tyboxes[i][j * 4 + 1][out[j * 4 + 1]];
            unsigned int cc = Tyboxes[i][j * 4 + 2][out[j * 4 + 2]];
            unsigned int dd = Tyboxes[i][j * 4 + 3][out[j * 4 + 3]];

            out[j * 4 + 0] = (Txor[Txor[(aa >>  0) & 0xf][(bb >>  0) & 0xf]][Txor[(cc >>  0) & 0xf][(dd >>  0) & 0xf]]) | ((Txor[Txor[(aa >>  4) & 0xf][(bb >>  4) & 0xf]][Txor[(cc >>  4) & 0xf][(dd >>  4) & 0xf]]) << 4);
            out[j * 4 + 1] = (Txor[Txor[(aa >>  8) & 0xf][(bb >>  8) & 0xf]][Txor[(cc >>  8) & 0xf][(dd >>  8) & 0xf]]) | ((Txor[Txor[(aa >> 12) & 0xf][(bb >> 12) & 0xf]][Txor[(cc >> 12) & 0xf][(dd >> 12) & 0xf]]) << 4);
            out[j * 4 + 2] = (Txor[Txor[(aa >> 16) & 0xf][(bb >> 16) & 0xf]][Txor[(cc >> 16) & 0xf][(dd >> 16) & 0xf]]) | ((Txor[Txor[(aa >> 20) & 0xf][(bb >> 20) & 0xf]][Txor[(cc >> 20) & 0xf][(dd >> 20) & 0xf]]) << 4);
            out[j * 4 + 3] = (Txor[Txor[(aa >> 24) & 0xf][(bb >> 24) & 0xf]][Txor[(cc >> 24) & 0xf][(dd >> 24) & 0xf]]) | ((Txor[Txor[(aa >> 28) & 0xf][(bb >> 28) & 0xf]][Txor[(cc >> 28) & 0xf][(dd >> 28) & 0xf]]) << 4);
        }
    }

    /// Last round which is a bit different
    ShiftRows(out);

    for (size_t j = 0; j < 16; ++j)
    {
        unsigned char x = Tboxes_[j][out[j]];
        out[j] = x;
    }
}
```

It's cute isn't it?

# Attacking the white-box: extract the key
As the title says, this white-box implementation is really insecure: which means that if you have access to an executable with that kind of white-box you just have to extract `Tyboxes[0]` & do a little magic to extract the key.

If it's not already obvious to you, you just have to remember how we actually compute the values inside that big tables ; look carefully at those two lines:

```c Tyboxes generation core
unsigned char c = S_box[x ^ round_keys[r][i]];
Tyboxes[r][i][x] = Ty[i % 4][c];
```

In our case, `r` is 0, `i` will be the byte index of the round key 0 (which is the AES key) & we can also set `x` to a constant value: let's say 0 or 1 for instance. `S_box` is known, `Ty` too as this transformation is always the same (it doesn't depend on the key). Basically we just need to brute-force `round_keys[r][i]` with every values a byte can take. If the computed value is equal to the one in the dumped `Tyboxes`, then we have extracted one byte of the round key & we can go find the next one.

Attentive readers noticed that we are not going to actually extract the encryption key per-se, but `ShiftRows(key)` instead (remember that we needed to apply this transformation to build our white-box). But again, `ShiftRows` being not key-dependent we can invert this operation easily to really have  the plain encryption key this time.

Here is the code that does what I just described:

```c wbaes128_attack_the_boxes.c:main
    unsigned char scrambled_key[16] = { 0 };
    for (size_t i = 0; i < 16; ++i)
    {
        // unsigned char c = S_box[0 ^ X0];
        // Tyboxes[0][0][0] = Ty[0][c];
        unsigned int value = Tyboxes_round0_dumped[i][1];
        // Now we generate the 0x100 possible values for the character 0 & wait to find a match
        for (size_t j = 0; j < 0x100; ++j)
        {
            unsigned char c = S_box[1 ^ j];
            unsigned int computed_value = Ty[i % 4][c];
            if (computed_value == value)
                scrambled_key[i] = j;
        }
    }

    {
        unsigned char tmp1, tmp2;
        // 8-bits right rotation of the second line
        tmp1 = scrambled_key[13];
        scrambled_key[13] = scrambled_key[9];
        scrambled_key[9] = scrambled_key[5];
        scrambled_key[1] = tmp1;

        // 16-bits right rotation of the third line
        tmp1 = scrambled_key[10];
        tmp2 = scrambled_key[14];
        scrambled_key[14] = scrambled_key[6];
        scrambled_key[10] = scrambled_key[2];
        scrambled_key[6] = tmp2;
        scrambled_key[2] = tmp1;

        // 24-bits right rotation of the last line
        tmp1 = scrambled_key[15];
        scrambled_key[15] = scrambled_key[3];
        scrambled_key[3] = scrambled_key[7];
        scrambled_key[7] = scrambled_key[11];
        scrambled_key[11] = tmp1;
    }

    printf("Key successfully extracted & UnShiftRow'd:\n");
    for (size_t i = 0; i < 16; ++i)
        printf("\\x%.2x", scrambled_key[i]);

```

# Obfuscating it?
This is basically the part where you have no limit, where you can exercise your creativity & have to develop stuffs. I'll just talk about ideas & obvious things, a lot of them are directly taken from [@elvanderb](https://twitter.com/elvanderb)'s challenge so I guess I owe him yet another beer.

The first things you can do for free are:

  * Unrolling the implementation to make room for craziness
  * Use public LLVM passes on the unrolled implementation to make it even more crazy
    * [Kryptonite](https://github.com/0vercl0k/stuffz/blob/master/llvm-funz/kryptonite/llvm-functionpass-kryptonite-obfuscater.cpp)
    * Quarklab's [ones](https://github.com/quarkslab/llvm-passes)
    * [Ollvm](https://github.com/obfuscator-llvm/obfuscator)
    * Build yours!

The other good idea is to try to make less obvious key elements in your implementation: basically the AES state, the tables & their structures. Those three things give away quite some important information about how your implementation works, so making a bit harder to figure those points out is good for us. Instead of storing the AES state inside a contiguous memory area of 16 bytes, why not use 16 non-contiguous variables of 1 byte? You can go even further by using different variables for every round to make it even more confusing. 

You can also apply that same idea to the different arrays our implementation uses: do not store them in a contiguous memory area, dispatch them all over the memory & transform them in one dimension arrays instead.

We could also imagine a generic array "obfuscation" where you add several "layers" before reaching the value you are interested in:

  * Imagine an array `[1,5,10,11]` ; we could shuffle this one into `[10, 5, 1, 11]` and build the associated index table which would be `[2, 1, 0, 3]`
  * And now instead of accessing directly the first array, you retrieve the correct index first in the index table, `shuffled[index[0]]`
    * Obviously you could have as many indirections you want

To make everything always more confusing, we could build the primitives we need on top of crazy CPU extensions like SSE or MMX; or completely build a virtual software-processor..!

Do also try to shuffle everything that is "shufflable" ; here is simple graph that shows data-dependencies between the lines of our unrolled C implementation (an arrow from A to B means that A needs to be executed prior to B):

{%img center /images/spotlight_on_an_unprotected_aes128_white-box_implementation/aes.svg %}

From here, you have everything you need to move the lines around & generate a "less normal" implementation (even that we can clearly see what I call synchronization points at the end of every round which is basically the calls to `ShiftRows(out)` ; but again we could get rid of those, and directly in-lining them etc):

```python generate_dependency_graph.py:generate_shuffled_implementation_via_dependency_graph
def generate_shuffled_implementation_via_dependency_graph(dependency_graph, out_filename):
    '''This function is basically leveraging the graph we produced in the previous function
    to generate an actual shuffled implementation of the AES white-box without breaking any
    constraints, keeping the result of this new shuffled function the same as the clean version.'''
    lines = open('aes_unrolled_code.raw.clean.unique_aabbccdd', 'r').readlines()
    print ' > Finding the bottom of the graph..'
    last_nodes = set()
    for i in range(len(lines)):
        _, degree_o = dependency_graph.degree_iter(i, indeg = False, outdeg = True).next()
        if degree_o == 0:
            last_nodes.add(dependency_graph.get_node(i))

    assert(len(last_nodes) != 0)
    print ' > Good, check it out: %r' % last_nodes
    shuffled_lines = []
    step_n = 0
    print ' > Lets go'
    while len(last_nodes) != 0:
        print '  %.2d> Shuffle %d nodes / lines..' % (step_n, len(last_nodes))
        random.shuffle(list(last_nodes), random = random.random)
        shuffled_lines.extend(lines[int(i.get_name())] for i in last_nodes)
        step_n += 1

        print '  %.2d> Finding parents / stepping back ..' % step_n
        tmp = set()
        for node in last_nodes:
            tmp.update(dependency_graph.in_neighbors(node))
        last_nodes = tmp
        step_n += 1

    shuffled_lines = reversed(shuffled_lines)
    with open(out_filename, 'w') as f:
        f.write('''void aes128_enc_wb_final_unrolled_shuffled_%d(unsigned char in[16], unsigned char out[16])
{
memcpy(out, in, 16);
''' % random.randint(0, 0xffffffff))
        f.writelines(shuffled_lines)
        f.write('}')
    return shuffled_lines
```

Anyway, I wish I had time to implement what we just talked about but I unfortunately don't; if you do feel free to shoot me an email & I'll update the post with links to your codes :-).

# Last words

I hope this little post gave you enough to understand how white-box cryptography kind of works, how important is the design of the implementation and what sort of problems you can encounter. If you did enjoy this subject, here is a list of cool articles you may want to check out:

 * [White-box cryptography: hiding keys in software](http://www.whiteboxcrypto.com/files/2012_misc.pdf)
 * [White-Box Cryptography - 30c3](https://www.youtube.com/watch?v=om5AVTqB5bA)
 * [Digital content protection: How to crack DRM and make them more resistant](http://esec-lab.sogeti.com/dotclear/public/publications/10-hitbkl-drm.pdf)
 * [A white-box DES (Chow et al)](https://github.com/mimoo/whiteboxDES)

Every sources produced for this post has been posted on my [github](https://github.com/0vercl0k) account right here: [wbaes128](https://github.com/0vercl0k/stuffz/blob/master/wbaes_attack/wbaes128).

Special thanks to my mate [@__x86](https://twitter.com/__x86) for proof-reading!