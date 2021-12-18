package ra.did;

/**
 * HashStrength: a number between 0 and 0xff that controls the number of times to iterate the password
 * hash before use. More iterations are useful against offline attacks, as it takes more
 * time to check each password. The actual number of iterations is rather complex, and also
 * depends on the hash function in use. Refer to Section 3.7.1.3 in rfc4880.txt.
 * Bigger numbers give you more iterations. As a rough rule of thumb, when using SHA256 as
 * the hashing function, 0x10 gives you about 64 iterations, 0x20 about 128, 0x30 about 256
 * and so on till 0xf0, or about 1 million iterations. The maximum you can go to is 0xff,
 * or about 2 million iterations.
 */
public class HashStrength {
    public static final int HASH_STRENGTH_64 = 0x10; // About 64 iterations for SHA-256
    public static final int HASH_STRENGTH_128 = 0x20; // About 128
    public static final int HASH_STRENGTH_256 = 0x30; // About 256
    public static final int HASH_STRENGTH_512 = 0x40; // About 512
    public static final int HASH_STRENGTH_1k = 0x50; // About 1k
    public static final int HASH_STRENGTH_2k = 0x60; // About 2k
    public static final int HASH_STRENGTH_4k = 0x70; // About 4k
    public static final int HASH_STRENGTH_8k = 0x80; // About 8k
    public static final int HASH_STRENGTH_16k = 0x90; // About16k
    public static final int HASH_STRENGTH_32k = 0xa0; // About 32k
    public static final int HASH_STRENGTH_64k = 0xb0; // About 64k
    public static final int HASH_STRENGTH_128k = 0xc0; // About 128k
    public static final int HASH_STRENGTH_256k = 0xd0; // About 256k
    public static final int HASH_STRENGTH_512k = 0xe0; // About 512k
    public static final int HASH_STRENGTH_1M = 0xf0; // About 1 million
    public static final int HASH_STRENGTH_2M = 0xff; // About 2 million
}
