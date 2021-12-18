package ra.did;

import ra.common.identity.PublicKey;

import static ra.did.HashStrength.HASH_STRENGTH_64;

public class GenerateKeyRingCollectionsRequest extends DIDRequest {
    public static int REQUEST_REQUIRED = 1;
    public static int KEY_RING_USERNAME_REQUIRED = 2;
    public static int KEY_RING_PASSPHRASE_REQUIRED = 3;
    public static int KEY_RING_USERNAME_TAKEN = 4;
    public static int KEY_RING_LOCATION_REQUIRED = 5;
    public static int KEY_RING_LOCATION_INACCESSIBLE = 6;

    // Required
    public String location;
    // Required
    public String keyRingUsername;
    // Required
    public String keyRingPassphrase;

    public int hashStrength = HASH_STRENGTH_64; // default

    // Response is publicKey associated with key ring username (default)
    public PublicKey identityPublicKey;
    public PublicKey encryptionPublicKey;

}
