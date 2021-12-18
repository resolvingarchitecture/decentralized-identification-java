package ra.did;

import org.junit.jupiter.api.*;
import ra.common.DLC;
import ra.common.Envelope;
import ra.common.content.Text;

import java.io.File;
import java.util.Date;
import java.util.Properties;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;
import static ra.did.HashStrength.HASH_STRENGTH_64;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DIDServiceTest {

    private static final Logger LOG = Logger.getLogger(DIDServiceTest.class.getName());

    private static MockProducer producer;
    private static DIDService service;
    private static Properties props;
    private static boolean serviceRunning = false;

    private static String keyRingUsername = "AnonMasterTest";
    private static String keyRingPassphrase = "1234";
    private static String alias = "AnonTest1";
    private static String aliasPassphrase = "5678";
    private static String keyRingImplementation = OpenPGPKeyRing.class.getName();
    private static String content = "Key Ring Service Test";

    @BeforeAll
    public static void init() {
        LOG.info("Init...");
        props = new Properties();
        producer = new MockProducer();
        service = new DIDService(producer, null);
        serviceRunning = service.start(props);
    }

    @AfterAll
    public static void tearDown() {
        LOG.info("Teardown...");
        service.gracefulShutdown();
    }

    @Test
    @Order(1)
    public void verifyInitializedTest() {
        assertTrue(serviceRunning);
    }

    @Test
    @Order(2)
    public void generateKeyRingsCollectionTest() {
        GenerateKeyRingCollectionsRequest req = new GenerateKeyRingCollectionsRequest();
        req.keyRingImplementation = keyRingImplementation;
        req.keyRingUsername = keyRingUsername;
        req.keyRingPassphrase = keyRingPassphrase;
        req.hashStrength = HASH_STRENGTH_64;
        Envelope e = Envelope.documentFactory();
        DLC.addData(GenerateKeyRingCollectionsRequest.class, req, e);
        DLC.addRoute(DIDService.class.getName(), DIDService.OPERATION_GENERATE_KEY_RINGS_COLLECTIONS, e);
        // Ratchet route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        File pkf = new File(service.getServiceDirectory(), req.keyRingUsername+".pkr");
        if(pkf.exists()) {
            assertTrue(pkf.delete());
        }
        File skf = new File(service.getServiceDirectory(), req.keyRingUsername+".skr");
        if(skf.exists()) {
            assertTrue(skf.delete());
        }
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        LOG.info("Key generation took: "+(end-start)+" ms.");
        assertTrue(pkf.exists());
        assertTrue(skf.exists());
        assertTrue((end-start) < 30000); // < 30 seconds
    }

    @Test
    @Order(3)
    public void generateKeyRingsTest() {
        GenerateKeyRingRequest req = new GenerateKeyRingRequest();
        req.keyRingImplementation = keyRingImplementation;
        req.keyRingUsername = keyRingUsername;
        req.keyRingPassphrase = keyRingPassphrase;
        req.alias = alias;
        req.aliasPassphrase = aliasPassphrase;
        Envelope e = Envelope.documentFactory();
        DLC.addData(GenerateKeyRingRequest.class, req, e);
        DLC.addRoute(DIDService.class.getName(), DIDService.OPERATION_GENERATE_KEY_RINGS, e);
        // Ratchet Route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        File pkf = new File(service.getServiceDirectory(), req.keyRingUsername+".pkr");
        if(pkf.exists()) {
            assertTrue(pkf.delete());
        }
        File skf = new File(service.getServiceDirectory(), req.keyRingUsername+".skr");
        if(skf.exists()) {
            assertTrue(skf.delete());
        }
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        LOG.info("Key generation took: "+(end-start)+" ms.");
        assertTrue(pkf.exists());
        assertTrue(skf.exists());
        assertTrue((end-start) < 30000); // < 30 seconds
    }

    @Test
    @Order(4)
    public void authenticationTest() {
        AuthNKeyRingRequest req = new AuthNKeyRingRequest();
        req.keyRingUsername = keyRingUsername;
        req.keyRingPassphrase = keyRingPassphrase;
        req.alias = alias;
        req.aliasPassphrase = aliasPassphrase;
        Envelope e = Envelope.documentFactory();
        DLC.addData(AuthNKeyRingRequest.class, req, e);
        DLC.addRoute(DIDService.class.getName(), DIDService.OPERATION_AUTHN_MASTER_RING, e);
        // Ratchet Route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        File pkf = new File(service.getServiceDirectory(), req.keyRingUsername+".pkr");
        if(pkf.exists()) {
            assertTrue(pkf.delete());
        }
        File skf = new File(service.getServiceDirectory(), req.keyRingUsername+".skr");
        if(skf.exists()) {
            assertTrue(skf.delete());
        }
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        LOG.info("Authentication took: "+(end-start)+" ms.");
        assertTrue(pkf.exists());
        assertTrue(skf.exists());
        assertTrue((end-start) < 30000); // < 30 seconds
        assertTrue(req.identityPublicKey!=null && req.identityPublicKey.isIdentityKey() && req.identityPublicKey.getAlias()!=null && req.identityPublicKey.getAddress()!=null);
    }

    @Test
    @Order(5)
    public void encryptionTest() {
        EncryptRequest encReq = new EncryptRequest();
        encReq.keyRingUsername = keyRingUsername;
        encReq.keyRingPassphrase = keyRingPassphrase;
        encReq.publicKeyAlias = alias;
        encReq.location = service.getServiceDirectory().getAbsolutePath();
        encReq.content = new Text();
        encReq.content.setBody(content.getBytes(), false, false);
        Envelope e = Envelope.documentFactory();
        DLC.addData(EncryptRequest.class, encReq, e);
        DLC.addRoute(DIDService.class.getName(), DIDService.OPERATION_ENCRYPT, e);
        // Ratchet Route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        LOG.info("Encryption took: "+(end-start)+" ms.");
        String encContent = new String(encReq.content.getBody());
        LOG.info("Content: "+content+"; Encrypted: \n"+encContent);
        assertNotEquals(encContent, content);
        assertTrue((end-start) < 30000); // < 30 seconds

        DecryptRequest decReq = new DecryptRequest();
        decReq.keyRingUsername = keyRingUsername;
        decReq.keyRingPassphrase = keyRingPassphrase;
        decReq.alias = alias;
        decReq.location = service.getServiceDirectory().getAbsolutePath();
        decReq.content = encReq.content;
        Envelope e2 = Envelope.documentFactory();
        DLC.addData(DecryptRequest.class, decReq, e2);
        DLC.addRoute(DIDService.class.getName(), DIDService.OPERATION_DECRYPT, e2);
        // Ratchet Route
        e2.setRoute(e2.getDynamicRoutingSlip().nextRoute());
        start = new Date().getTime();
        service.handleDocument(e2);
        end = new Date().getTime();
        LOG.info("Decryption took: "+(end-start)+" ms.");
        assertEquals(new String(decReq.content.getBody()), content);
        assertTrue((end-start) < 30000); // < 30 seconds
    }

    @Test
    @Order(6)
    public void yubiKeyFindTest() {
        Properties p = new Properties();
        YubiKeyRing ring = new YubiKeyRing();
        ring.init(p);

    }

}
