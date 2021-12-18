package ra.did;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import ra.common.*;
import ra.common.content.JSON;
import ra.common.crypto.EncryptionAlgorithm;
import ra.common.crypto.Hash;
import ra.common.file.InfoVaultFileDB;
import ra.common.identity.DID;
import ra.common.identity.PublicKey;
import ra.common.messaging.MessageProducer;
import ra.common.messaging.TextMessage;
import ra.common.route.Route;
import ra.common.service.BaseService;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusObserver;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.logging.Logger;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static ra.did.HashRequest.UNKNOWN_HASH_ALGORITHM;
import static ra.did.HashStrength.HASH_STRENGTH_64;


/**
 * Decentralized IDentifier (DID) Service
 */
public class DIDService extends BaseService {

    private static final Logger LOG = Logger.getLogger(DIDService.class.getName());

    public static final String OPERATION_GENERATE_KEY_RINGS_COLLECTIONS = "GENERATE_KEY_RINGS_COLLECTIONS";
    public static final String OPERATION_GENERATE_KEY_RINGS = "GENERATE_KEY_RINGS";
    public static final String OPERATION_AUTHN_MASTER_RING = "AUTHN_MASTER_RING";
    public static final String OPERATION_ENCRYPT = "ENCRYPT";
    public static final String OPERATION_DECRYPT = "DECRYPT";
    public static final String OPERATION_ENCRYPT_SYMMETRIC = "ENCRYPT_SYMMETRIC";
    public static final String OPERATION_DECRYPT_SYMMETRIC = "DECRYPT_SYMMETRIC";
    public static final String OPERATION_SIGN = "SIGN";
    public static final String OPERATION_VERIFY_SIGNATURE = "VERIFY_SIGNATURE";
    public static final String OPERATION_VOUCH = "VOUCH";
    public static final String OPERATION_RELOAD = "RELOAD";

    public static final String OPERATION_GET_IDENTITIES = "GET_IDENTITIES";
    public static final String OPERATION_GET_IDENTITY = "GET_IDENTITY";
    public static final String OPERATION_VERIFY_IDENTITY = "VERIFY";
    public static final String OPERATION_SAVE_IDENTITY = "SAVE";
    public static final String OPERATION_DELETE_IDENTITY = "DELETE";

    public static final String OPERATION_AUTHENTICATE = "AUTHENTICATE";

    public static final String OPERATION_HASH = "HASH";
    public static final String OPERATION_VERIFY_HASH = "VERIFY_HASH";

    public static final String OPERATION_ADD_CONTACT = "ADD_CONTACT";
    public static final String OPERATION_GET_CONTACT = "GET_CONTACT";
    public static final String OPERATION_GET_CONTACTS = "GET_CONTACTS";
    public static final String OPERATION_DELETE_CONTACT = "DELETE_CONTACT";

    private static final int MAX_IDENTITIES = 10;
    private static final int MAX_CONTACTS = 10000;
    private static final int MAX_CONTACTS_LIST = 100;

    private Properties properties = new Properties();

    private Map<String, KeyRing> keyRings = new HashMap<>();

    // Identity DBs
    private InfoVaultFileDB identitiesDB; // Personal
    private InfoVaultFileDB nodesDB;
    private InfoVaultFileDB contactsDB;

    public DIDService() {}

    public DIDService(MessageProducer producer, ServiceStatusObserver serviceStatusObserver) {
        super(producer, serviceStatusObserver);
    }

    @Override
    public void handleDocument(Envelope e) {
        handleAll(e);
    }

    @Override
    public void handleEvent(Envelope e) {
        handleAll(e);
    }

    @Override
    public void handleHeaders(Envelope e) {
        handleAll(e);
    }

    private void handleAll(Envelope e) {
        Route route = e.getRoute();
        String operation = route.getOperation();
        KeyRing keyRing;
        switch(operation) {
            case OPERATION_GENERATE_KEY_RINGS_COLLECTIONS: {
                LOG.info("Generate Key Rings Collections request received.");
                GenerateKeyRingCollectionsRequest r = (GenerateKeyRingCollectionsRequest) e.getData(GenerateKeyRingCollectionsRequest.class);
                if(r == null) {
                    LOG.warning("GenerateKeyRingCollectionsRequest required.");
                    r = new GenerateKeyRingCollectionsRequest();
                    r.statusCode = GenerateKeyRingCollectionsRequest.REQUEST_REQUIRED;
                    e.addData(GenerateKeyRingCollectionsRequest.class, r);
                    break;
                }
                File f;
                if(r.location == null || r.location.isEmpty()) {
                    // default
                    f = getServiceDirectory();
                    r.location = f.getAbsolutePath();
                } else {
                    f = new File(r.location);
                }
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_LOCATION_INACCESSIBLE;
                    break;
                }
                if(r.keyRingUsername == null) {
                    LOG.warning("KeyRing username required.");
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_USERNAME_REQUIRED;
                    break;
                }
                if(r.keyRingPassphrase == null) {
                    LOG.warning("KeyRing passphrase required.");
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.hashStrength < HASH_STRENGTH_64) {
                    r.hashStrength = HASH_STRENGTH_64; // minimum
                }
                if(r.keyRingImplementation == null) {
                    r.keyRingImplementation = OpenPGPKeyRing.class.getName(); // Default
                }
                try {
                    keyRing = keyRings.get(r.keyRingImplementation);
                    if(keyRing == null) {
                        LOG.warning("KeyRing implementation unknown: "+r.keyRingImplementation);
                        r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                        return;
                    }
                    keyRing.generateKeyRingCollections(r);
                } catch (Exception ex) {
                    r.exception = ex;
                }
                break;
            }
            case OPERATION_AUTHN_MASTER_RING: {
                AuthNKeyRingRequest r = (AuthNKeyRingRequest)e.getData(AuthNKeyRingRequest.class);
                if(r==null) {
                    r = new AuthNKeyRingRequest();
                    r.statusCode = AuthNKeyRingRequest.REQUEST_REQUIRED;
                    e.addData(AuthNKeyRingRequest.class, r);
                    break;
                }
                File f;
                if(r.location == null || r.location.isEmpty()) {
                    // Set locally
                    f = getServiceDirectory();
                    r.location = f.getAbsolutePath();
                } else {
                    f = new File(r.location);
                }
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = AuthNKeyRingRequest.KEYRING_LOCATION_INACCESSIBLE;
                    break;
                }
                if(r.keyRingUsername == null) {
                    LOG.warning("KeyRing username required.");
                    r.statusCode = AuthNKeyRingRequest.KEY_RING_USERNAME_REQUIRED;
                    break;
                }
                if(r.keyRingPassphrase == null) {
                    LOG.warning("KeyRing passphrase required.");
                    r.statusCode = AuthNKeyRingRequest.KEY_RING_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.alias == null || r.alias.isEmpty()) {
                    r.statusCode = AuthNKeyRingRequest.ALIAS_REQUIRED;
                    break;
                }
                if(r.aliasPassphrase == null || r.aliasPassphrase.isEmpty()) {
                    r.statusCode = AuthNKeyRingRequest.ALIAS_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.keyRingImplementation == null) {
                    r.keyRingImplementation = OpenPGPKeyRing.class.getName(); // Default
                }
                try {
                    keyRing = keyRings.get(r.keyRingImplementation);
                    if(keyRing == null) {
                        LOG.warning("KeyRing implementation unknown: "+r.keyRingImplementation);
                        r.statusCode = AuthNKeyRingRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                        return;
                    }
                    PGPPublicKeyRingCollection c = null;
                    try {
                        c = keyRing.getPublicKeyRingCollection(r.location, r.keyRingUsername, r.keyRingPassphrase);
                    } catch (IOException e1) {
                        LOG.info("No key ring collection found.");
                        break;
                    } catch (PGPException e1) {
                        LOG.warning(e1.getLocalizedMessage());
                        break;
                    }

                    PGPPublicKey identityPublicKey = keyRing.getPublicKey(c, r.alias, true);
                    r.identityPublicKey = new PublicKey();
                    r.identityPublicKey.setAlias(r.alias);
                    r.identityPublicKey.setFingerprint(Base64.getEncoder().encodeToString(identityPublicKey.getFingerprint()));
                    r.identityPublicKey.setAddress(Base64.getEncoder().encodeToString(identityPublicKey.getEncoded()));
                    r.identityPublicKey.setBase64Encoded(true);
                    r.identityPublicKey.setType("RSA2048");
                    r.identityPublicKey.isEncryptionKey(identityPublicKey.isEncryptionKey());
                    r.identityPublicKey.isIdentityKey(identityPublicKey.isMasterKey());
                    LOG.info("Identity Public Key loaded: " + r.identityPublicKey);

                    PGPPublicKey encryptionPublicKey = keyRing.getPublicKey(c, r.alias, false);
                    r.encryptionPublicKey = new PublicKey();
                    r.encryptionPublicKey.setAlias(r.alias);
                    r.encryptionPublicKey.setFingerprint(Base64.getEncoder().encodeToString(encryptionPublicKey.getFingerprint()));
                    r.encryptionPublicKey.setAddress(Base64.getEncoder().encodeToString(encryptionPublicKey.getEncoded()));
                    r.encryptionPublicKey.setBase64Encoded(true);
                    r.encryptionPublicKey.setType("RSA2048");
                    r.encryptionPublicKey.isEncryptionKey(encryptionPublicKey.isEncryptionKey());
                    r.encryptionPublicKey.isIdentityKey(encryptionPublicKey.isMasterKey());
                    LOG.info("Encryption Public Key loaded: " + r.encryptionPublicKey);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_GENERATE_KEY_RINGS: {
                GenerateKeyRingRequest r = (GenerateKeyRingRequest)e.getData(GenerateKeyRingRequest.class);
                if(r == null) {
                    r = new GenerateKeyRingRequest();
                    r.statusCode = GenerateKeyRingRequest.REQUEST_REQUIRED;
                    break;
                }
                File f;
                if(r.location == null || r.location.isEmpty()) {
                    // Set locally
                    f = getServiceDirectory();
                    r.location = f.getAbsolutePath();
                } else {
                    f = new File(r.location);
                }
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = GenerateKeyRingRequest.KEYRING_LOCATION_INACCESSIBLE;
                    break;
                }
                if(r.keyRingUsername == null || r.keyRingUsername.isEmpty()) {
                    r.statusCode = GenerateKeyRingRequest.KEYRING_USERNAME_REQUIRED;
                    break;
                }
                if(r.keyRingPassphrase == null || r.keyRingPassphrase.isEmpty()) {
                    r.statusCode = GenerateKeyRingRequest.KEYRING_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.alias == null || r.alias.isEmpty()) {
                    r.statusCode = GenerateKeyRingRequest.ALIAS_REQUIRED;
                    break;
                }
                if(r.aliasPassphrase == null || r.aliasPassphrase.isEmpty()) {
                    r.statusCode = GenerateKeyRingRequest.ALIAS_PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.keyRingImplementation == null)
                    r.keyRingImplementation = OpenPGPKeyRing.class.getName(); // default
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.createKeyRings(r.location, r.keyRingUsername, r.keyRingPassphrase, r.alias, r.aliasPassphrase, r.hashStrength, r.keyRingImplementation);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_ENCRYPT: {
                EncryptRequest r = (EncryptRequest)e.getData(EncryptRequest.class);
                if(r == null) {
                    r = new EncryptRequest();
                    r.statusCode = EncryptRequest.REQUEST_REQUIRED;
                    e.addData(EncryptRequest.class, r);
                    break;
                }
                if(r.location == null) {
                    r.statusCode = EncryptRequest.LOCATION_REQUIRED;
                    break;
                }
                File f = new File(r.location);
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = EncryptRequest.LOCATION_INACCESSIBLE;
                    break;
                }
                if(r.content == null || r.content.getBody() == null || r.content.getBody().length == 0) {
                    r.statusCode = EncryptRequest.CONTENT_TO_ENCRYPT_REQUIRED;
                    break;
                }
                if(r.publicKeyAlias == null) {
                    r.statusCode = EncryptRequest.PUBLIC_KEY_ALIAS_REQUIRED;
                    break;
                }
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = EncryptRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.encrypt(r);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_DECRYPT: {
                DecryptRequest r = (DecryptRequest)e.getData(DecryptRequest.class);
                if(r == null) {
                    r = new DecryptRequest();
                    r.statusCode = DecryptRequest.REQUEST_REQUIRED;
                    e.addData(DecryptRequest.class, r);
                    break;
                }
                if(r.location == null) {
                    r.statusCode = DecryptRequest.LOCATION_REQUIRED;
                    break;
                }
                File f = new File(r.location);
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = DecryptRequest.LOCATION_INACCESSIBLE;
                    break;
                }
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.decrypt(r);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_SIGN: {
                SignRequest r = (SignRequest)e.getData(SignRequest.class);
                if(r == null) {
                    r = new SignRequest();
                    r.statusCode = SignRequest.REQUEST_REQUIRED;
                    e.addData(SignRequest.class, r);
                    break;
                }
                if(r.location == null) {
                    r.statusCode = SignRequest.LOCATION_REQUIRED;
                    break;
                }
                File f = new File(r.location);
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = SignRequest.LOCATION_INACCESSIBLE;
                    break;
                }
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.sign(r);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_VERIFY_SIGNATURE: {
                VerifySignatureRequest r = (VerifySignatureRequest)e.getData(VerifySignatureRequest.class);
                if(r == null) {
                    r = new VerifySignatureRequest();
                    r.statusCode = VerifySignatureRequest.REQUEST_REQUIRED;
                    e.addData(VerifySignatureRequest.class, r);
                    break;
                }
                if(r.location == null) {
                    r.statusCode = VerifySignatureRequest.LOCATION_REQUIRED;
                    break;
                }
                File f = new File(r.location);
                if(!f.exists() && !f.mkdir()) {
                    r.statusCode = VerifySignatureRequest.LOCATION_INACCESSIBLE;
                    break;
                }
                keyRing = keyRings.get(r.keyRingImplementation);
                if(keyRing == null) {
                    r.statusCode = GenerateKeyRingCollectionsRequest.KEY_RING_IMPLEMENTATION_UNKNOWN;
                    return;
                }
                try {
                    keyRing.verifySignature(r);
                } catch (Exception ex) {
                    r.exception = ex;
                    LOG.warning(ex.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_ENCRYPT_SYMMETRIC: {
                EncryptSymmetricRequest r = (EncryptSymmetricRequest)e.getData(EncryptSymmetricRequest.class);
                if(r==null) {
                    r = new EncryptSymmetricRequest();
                    r.statusCode = EncryptSymmetricRequest.REQUEST_REQUIRED;
                    e.addData(EncryptSymmetricRequest.class, r);
                    break;
                }
                if(r.content == null || r.content.getBody() == null || r.content.getBody().length == 0) {
                    r.statusCode = EncryptSymmetricRequest.CONTENT_TO_ENCRYPT_REQUIRED;
                    break;
                }
                if(r.content.getEncryptionPassphrase() == null || r.content.getEncryptionPassphrase().isEmpty()) {
                    r.statusCode = EncryptSymmetricRequest.PASSPHRASE_REQUIRED;
                    break;
                }
                try {
                    byte[] key = r.content.getEncryptionPassphrase().getBytes(StandardCharsets.UTF_8);
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key,16);
                    // Encrypt
                    SecretKey secretKey = new SecretKeySpec(key, "AES");
                    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    byte[] iv = new byte[16];
                    SecureRandom random = new SecureRandom();
                    random.nextBytes(iv);
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                    aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
                    r.content.setBody(aesCipher.doFinal(r.content.getBody()), false, false);
                    r.content.setBody(Base64.getEncoder().encodeToString(r.content.getBody()).getBytes(), false, false);
                    r.content.setBodyBase64Encoded(true);
                    r.content.setBase64EncodedIV(Base64.getEncoder().encodeToString(iv));
                    r.content.setEncrypted(true);
                    r.content.setEncryptionAlgorithm(EncryptionAlgorithm.AES256);
                } catch (NoSuchAlgorithmException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (NoSuchPaddingException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidKeyException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidAlgorithmParameterException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (IllegalBlockSizeException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (BadPaddingException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                }

                break;
            }
            case OPERATION_DECRYPT_SYMMETRIC: {
                DecryptSymmetricRequest r = (DecryptSymmetricRequest)e.getData(DecryptSymmetricRequest.class);
                if(r==null) {
                    r = new DecryptSymmetricRequest();
                    e.addData(DecryptSymmetricRequest.class, r);
                    r.statusCode = DecryptSymmetricRequest.REQUEST_REQUIRED;
                    break;
                }
                if(r.content == null || r.content.getBody() == null || r.content.getBody().length == 0) {
                    r.statusCode = DecryptSymmetricRequest.ENCRYPTED_CONTENT_REQUIRED;
                    break;
                }
                if(r.content.getEncryptionPassphrase()==null || r.content.getEncryptionPassphrase().isEmpty()) {
                    r.statusCode = DecryptSymmetricRequest.PASSPHRASE_REQUIRED;
                    break;
                }
                if(r.content.getBase64EncodedIV()==null || r.content.getBase64EncodedIV().isEmpty()) {
                    r.statusCode = DecryptSymmetricRequest.IV_REQUIRED;
                    break;
                }
                try {
                    byte[] key = r.content.getEncryptionPassphrase().getBytes(StandardCharsets.UTF_8);
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key,16);
                    // Encrypt
                    SecretKey secretKey = new SecretKeySpec(key, "AES");
                    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    if(r.content.getBodyBase64Encoded()) {
                        r.content.setBody(Base64.getDecoder().decode(r.content.getBody()), false, false);
                        r.content.setBodyBase64Encoded(false);
                    }
                    byte[] iv = Base64.getDecoder().decode(r.content.getBase64EncodedIV());
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                    aesCipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
                    r.content.setBody(aesCipher.doFinal(r.content.getBody()), false, false);
                    r.content.setEncrypted(false);
                    r.content.setBase64EncodedIV(null);
                    r.content.setEncryptionAlgorithm(null);
                } catch (NoSuchAlgorithmException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (NoSuchPaddingException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidKeyException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidAlgorithmParameterException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (IllegalBlockSizeException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (BadPaddingException e1) {
                    r.statusCode = DecryptSymmetricRequest.BAD_PASSPHRASE;
                    LOG.warning(e1.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_VOUCH: {
                VouchRequest r = (VouchRequest)e.getData(VouchRequest.class);
                if(r.signer==null) {
                    r.statusCode = VouchRequest.SIGNER_REQUIRED;
                    break;
                }
                if(r.signee==null){
                    r.statusCode = VouchRequest.SIGNEE_REQUIRED;
                    break;
                }
                if(r.attributesToSign==null) {
                    r.statusCode = VouchRequest.ATTRIBUTES_REQUIRED;
                    break;
                }
                // TODO: Verify attributes to sign are available attributes
                LOG.warning("VOUCH not yet implemented.");
            }
            case OPERATION_RELOAD: {
                loadKeyRingImplementations();
            }
            case OPERATION_GET_IDENTITIES: {
                LOG.info("Received get Identities request.");
                int start = 0;
                int identitiesNumber = 10; // default
                DID.Type type = DID.Type.IDENTITY;
                if(nonNull(e.getValue("identitiesStart"))) {
                    start = Integer.parseInt((String)e.getValue("identitiesStart"));
                }
                if(nonNull(e.getValue("identitiesNumber"))) {
                    identitiesNumber = Integer.parseInt((String)e.getValue("identitiesNumber"));
                    if(identitiesNumber > MAX_IDENTITIES) {
                        identitiesNumber = MAX_IDENTITIES;
                    }
                }
                if(nonNull(e.getValue("identityType"))) {
                    type = DID.Type.valueOf((String)e.getValue("identityType"));
                }
                List<DID> identities = loadRange(start, identitiesNumber, type);
                e.addNVP("identities", identities);
                break;
            }
            case OPERATION_GET_IDENTITY: {
                LOG.info("Received get Identity request.");
                String username = (String)e.getValue("username");
                DID.Type type = DID.Type.valueOf((String)e.getValue("identityType"));
                DID did = load(username, type);
                if(nonNull(did))
                    e.addData(DID.class, did);
                break;
            }
            case OPERATION_VERIFY_IDENTITY: {
                LOG.info("Received verify DID request.");
                String username = (String)e.getValue("username");
                DID.Type type = DID.Type.valueOf((String)e.getValue("identityType"));
                DID did = load(username, type);
                e.addNVP("verified", isNull(did));
                break;
            }
            case OPERATION_AUTHENTICATE: {
                LOG.info("Received authn request.");
                AuthenticateDIDRequest r = (AuthenticateDIDRequest)e.getData(AuthenticateDIDRequest.class);
                if(isNull(r)) {
                    r = new AuthenticateDIDRequest();
                    r.statusCode = AuthenticateDIDRequest.REQUEST_REQUIRED;
                    e.addNVP("authN",r);
                    break;
                }
                if(isNull(r.username)) {
                    r.statusCode = AuthenticateDIDRequest.USERNAME_REQUIRED;
                    break;
                }
                if(isNull(r.passphrase)) {
                    r.statusCode = AuthenticateDIDRequest.PASSPHRASE_REQUIRED;
                    break;
                }
                if(isNull(r.type)) {
                    r.type = DID.Type.IDENTITY;
                }
                DID did = load(r.username, r.type);
                try {
                    if(nonNull(did)
                            && nonNull(did.getPassphraseHash())
                            && HashUtil.verifyPasswordHash(r.passphrase, did.getPassphraseHash().getHash())) {
                        e.addData(DID.class, did);
                    } else {
                        e.addNVP("authN", false);
                    }
                } catch (NoSuchAlgorithmException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_SAVE_IDENTITY: {
                LOG.info("Received save DID request.");
                Map<String,Object> m = (Map<String,Object>)e.getData(DID.class);
                if(isNull(m)) {
                    e.addErrorMessage("No DID to Save.");
                    break;
                }
                DID.Type type = DID.Type.valueOf((String)e.getValue("identityType"));
                String location = null;
                if(nonNull(e.getValue("identityLocation")))
                    location = (String)e.getValue("identityLocation");
                DID did = new DID();
                did.fromMap(m);
                saveDID(did, type, location);
                break;
            }
            case OPERATION_DELETE_IDENTITY: {
                String username = (String)e.getValue("username");
                Boolean success = identitiesDB.delete(username);
                e.addNVP("delete-success",success.toString());
                break;
            }
            case OPERATION_ADD_CONTACT: {
                LOG.info("Received add Contact request.");
                e.addNVP("contact", saveDID((DID)e.getValue("contact"), DID.Type.CONTACT, null));
                break;
            }
            case OPERATION_GET_CONTACT: {
                LOG.info("Received get Contact request.");
                String username = ((TextMessage) e.getMessage()).getText();
                DID contact = load(username, DID.Type.CONTACT);
                e.addNVP("contact", contact);
                break;
            }
            case OPERATION_GET_CONTACTS: {
                LOG.info("Received get Contacts request.");
                int start = 0;
                int contactsNumber = 10; // default
                if(e.getValue("contactsStart")!=null) {
                    start = Integer.parseInt((String)e.getValue("contactsStart"));
                }
                if(DLC.getValue("contactsNumber", e)!=null) {
                    contactsNumber = Integer.parseInt((String)e.getValue("contactsNumber"));
                    if(contactsNumber > MAX_CONTACTS_LIST) {
                        contactsNumber = MAX_CONTACTS_LIST; // 1000 is max
                    }
                }
                List<InfoVault> infoVaults = new ArrayList<>();
                contactsDB.loadRange(start, contactsNumber, infoVaults);
                DID contact;
                List<DID> contacts = new ArrayList<>();
                for(InfoVault iv : infoVaults) {
                    contact = new DID();
                    contact.fromJSON(iv.content.toJSON());
                    contacts.add(contact);
                }
                e.addNVP("contacts", contacts);
                break;
            }
            case OPERATION_DELETE_CONTACT: {
                LOG.info("Received delete Contact request.");
                String fingerprint = (String)e.getValue("contactFingerprint");
                contactsDB.delete(fingerprint);
                break;
            }
            case OPERATION_HASH: {
                HashRequest r = (HashRequest)DLC.getData(HashRequest.class,e);
                try {
                    if(r.generateHash)
                        r.hash = new Hash(HashUtil.generateHash(r.contentToHash, r.hashAlgorithm.getName()), r.hashAlgorithm);
                    if(r.generateFingerprint && r.hash != null) {
                        r.fingerprint = new Hash(HashUtil.generateHash(r.hash.getHash(), r.hashAlgorithm.getName()), r.hashAlgorithm);
                    }
                } catch (NoSuchAlgorithmException e1) {
                    r.statusCode = UNKNOWN_HASH_ALGORITHM;
                }
                break;
            }
            case OPERATION_VERIFY_HASH:{
                VerifyHashRequest r = (VerifyHashRequest)e.getData(VerifyHashRequest.class);
                try {
                    r.isAMatch = HashUtil.verifyHash(r.content, r.hashToVerify.getHash(), r.hashToVerify.getAlgorithm().getName());
                } catch (NoSuchAlgorithmException e1) {
                    r.statusCode = UNKNOWN_HASH_ALGORITHM;
                }
                break;
            }
            default: deadLetter(e); // Operation not supported
        }
    }

    /**
     * Saves DID
     * @param did DID
     */
    private boolean saveDID(DID did, DID.Type type, String location) {
        LOG.info("Saving DID...");
        if(nonNull(did.getPassphrase())) {
            LOG.info("Hashing passphrase...");
            try {
                did.setPassphraseHash(new Hash(HashUtil.generatePasswordHash(did.getPassphrase()), Hash.Algorithm.PBKDF2WithHmacSHA1));
                // ensure passphrase is cleared
                did.setPassphrase(null);
            } catch (NoSuchAlgorithmException ex) {
                LOG.warning("Hashing Algorithm not supported while saving DID\n" + ex.getLocalizedMessage());
                return false;
            }
        }

        InfoVault iv = new InfoVault();
        iv.content = new JSON(did.toJSON().getBytes(), DID.class.getName(), did.getUsername(), false, false);
        if(isNull(location))
            iv.content.setLocation(getServiceDirectory()+type.name()+"/"+did.getUsername()+".json");
        else
            iv.content.setLocation(location + (location.endsWith("/") ? "" : "/") + type.name() + "/" + did.getUsername()+".json");
        switch (type) {
            case NODE: return nodesDB.save(iv);
            case CONTACT: return contactsDB.save(iv);
            case IDENTITY: return identitiesDB.save(iv);
            default: return false;
        }
    }

    private DID load(String username, DID.Type type) {
        DID loadedDID = new DID();
        InfoVault iv = null;
        switch (type) {
            case NODE: iv = nodesDB.load(username);break;
            case CONTACT: iv = contactsDB.load(username);break;
            case IDENTITY: iv = identitiesDB.load(username);break;
        }
        if(nonNull(iv)) {
            loadedDID.fromMap(iv.content.toMap());
            LOG.info("JSON loaded: " + iv.content.toJSON());
            LOG.info("DID Loaded from map.");
            return loadedDID;
        }
        return null;
    }

    private List<DID> loadRange(int begin, int numberEntries, DID.Type type) {
        List<DID> loadedDIDs = new ArrayList<>();
        List<InfoVault> infoVaults = new ArrayList<>();
        DID did;
        InfoVaultDB db;
        switch (type) {
            case CONTACT: db = contactsDB;break;
            case NODE: db = nodesDB;break;
            default: db = identitiesDB;
        }
        if(db.loadRange(begin, numberEntries, infoVaults)) {
            for (InfoVault iv : infoVaults) {
                did = new DID();
                did.fromMap(iv.content.toMap());
                loadedDIDs.add(did);
            }
        }
        return loadedDIDs;
    }

    private void loadKeyRingImplementations(){
        keyRings.clear();
        KeyRing keyRing;
        if(properties.getProperty("ra.keyring.KeyRings") == null) {
            keyRing = new OpenPGPKeyRing(); // Default
            if(keyRing.init(properties))
                keyRings.put(OpenPGPKeyRing.class.getName(), keyRing);
        } else {
            String[] keyRingStrings = properties.getProperty("ra.keyring.KeyRings").split(",");
            for (String keyRingString : keyRingStrings) {
                try {
                    keyRing = (KeyRing) Class.forName(keyRingString).getConstructor().newInstance();
                    if(keyRing.init(properties))
                        keyRings.put(keyRingString, keyRing);
                } catch (Exception e) {
                    LOG.warning(e.getLocalizedMessage());
                }
            }
        }
    }

    @Override
    public boolean start(Properties properties) {
        super.start(properties);
        LOG.info("Starting....");
        updateStatus(ServiceStatus.STARTING);
        this.properties = properties;
        // Android apps set SpongyCastle as the default provider
        if(!SystemVersion.isAndroid()) {
            Security.addProvider(new BouncyCastleProvider());
        }
        loadKeyRingImplementations();
        // TODO: Support external drives (InfoVault)
        nodesDB = new InfoVaultFileDB();
        nodesDB.setBaseURL(new File(getServiceDirectory(),DID.Type.NODE.name()).getAbsolutePath());
        identitiesDB = new InfoVaultFileDB();
        identitiesDB.setBaseURL(new File(getServiceDirectory(),DID.Type.IDENTITY.name()).getAbsolutePath());
        contactsDB = new InfoVaultFileDB();
        contactsDB.setBaseURL(new File(getServiceDirectory(),DID.Type.CONTACT.name()).getAbsolutePath());
        updateStatus(ServiceStatus.RUNNING);
        LOG.info("Started.");
        return true;
    }

    @Override
    public boolean shutdown() {
        super.shutdown();
        LOG.info("Shutting down....");
        updateStatus(ServiceStatus.SHUTTING_DOWN);

        updateStatus(ServiceStatus.SHUTDOWN);
        LOG.info("Shutdown.");
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        return shutdown();
    }

//    public static void main(String[] args) {
//        DIDService service = new DIDService();
//        DID did = new DID();
//        did.setAlias("Alice");
//        did.setPassphrase("1234");
//        service.create(did);
//    }

}
