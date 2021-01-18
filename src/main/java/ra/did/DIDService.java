package ra.did;

import ra.common.DLC;
import ra.common.Envelope;
import ra.common.InfoVault;
import ra.common.content.JSON;
import ra.common.crypto.Hash;
import ra.common.file.InfoVaultFileDB;
import ra.common.identity.DID;
import ra.common.messaging.MessageProducer;
import ra.common.messaging.TextMessage;
import ra.common.route.Route;
import ra.common.service.BaseService;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusObserver;
import ra.keyring.AuthNRequest;
import ra.keyring.GenerateKeyRingCollectionsRequest;
import ra.util.HashUtil;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import static ra.did.HashRequest.UNKNOWN_HASH_ALGORITHM;


/**
 * Decentralized IDentifier (DID) Service
 *
 * TODO: Support External and make it the default choice
 */
public class DIDService extends BaseService {

    private static final Logger LOG = Logger.getLogger(DIDService.class.getName());

    public static final String OPERATION_GET_IDENTITIES = "GET_IDENTITIES";
    public static final String OPERATION_SET_ACTIVE_IDENTITY = "SET_ACTIVE_IDENTITY";
    public static final String OPERATION_GET_ACTIVE_IDENTITY = "GET_ACTIVE_IDENTITY";
    public static final String OPERATION_VERIFY_IDENTITY = "VERIFY"; // Read/Verify
    public static final String OPERATION_SAVE_IDENTITY = "SAVE"; // Create/Update
    public static final String OPERATION_DELETE_IDENTITY = "DELETE";

    public static final String OPERATION_AUTHENTICATE = "AUTHENTICATE";
    public static final String OPERATION_AUTHENTICATE_CREATE = "AUTHENTICATE_CREATE";

    public static final String OPERATION_HASH = "HASH";
    public static final String OPERATION_VERIFY_HASH = "VERIFY_HASH";

    public static final String OPERATION_ADD_CONTACT = "ADD_CONTACT";
    public static final String OPERATION_GET_CONTACT = "GET_CONTACT";
    public static final String OPERATION_GET_CONTACTS = "GET_CONTACTS";
    public static final String OPERATION_DELETE_CONTACT = "DELETE_CONTACT";

    private static final int MAX_IDENTITIES = 10;
    private static final int MAX_CONTACTS = 10000;
    private static final int MAX_CONTACTS_LIST = 100;

    private static final String CONTACT_DIR = "c";
    private static final String IDENTITY_DIR = "i";
    private static final String NODE_DIR = "n";

    // Internal
    private DID nodeDID;
    private DID activeIdentity;
    private InfoVaultFileDB identitiesDB;

    // External
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
        switch(operation) {
            case OPERATION_SET_ACTIVE_IDENTITY: {
                LOG.info("Received set active identity....");
                String fingerprint = (String) e.getValue("fingerprint");
                if(fingerprint ==null) {
                    e.addErrorMessage("No Fingerprint");
                    break;
                }
                activeIdentity = loadIdentity(fingerprint, false, false);
                e.addEntity(activeIdentity);
                break;
            }
            case OPERATION_GET_ACTIVE_IDENTITY: {
                LOG.info("Received get active identity....");
                if(activeIdentity !=null) {
                    e.addNVP("activeIdentity",activeIdentity);
                    break;
                }
                List<DID> identitiesLoaded = loadIdentities(1, MAX_IDENTITIES, false);
                for(DID d : identitiesLoaded) {
                    if(DID.Status.ACTIVE == d.getStatus()) {
                        activeIdentity = d;
                        e.addNVP("activeIdentity",activeIdentity);
                        break;
                    }
                }
                break;
            }
            case OPERATION_GET_IDENTITIES: {
                LOG.info("Received get Identities request.");
                int start = 0;
                int identitiesNumber = 10; // default
                if(DLC.getValue("identitiesStart", e)!=null) {
                    start = Integer.parseInt((String)e.getValue("identitiesStart"));
                }
                if(DLC.getValue("identitiesNumber", e)!=null) {
                    identitiesNumber = Integer.parseInt((String)e.getValue("identitiesNumber"));
                    if(identitiesNumber > MAX_IDENTITIES) {
                        identitiesNumber = MAX_IDENTITIES;
                    }
                }
                List<DID> identities = loadIdentities(start, identitiesNumber, false);
                e.addNVP("identities", identities);
                break;
            }
            case OPERATION_VERIFY_IDENTITY: {
                DID verified;
                DID did = e.getDID();
                LOG.info("Received verify DID request.");
                // Node DID needs to be verified first
                DID didLoaded = loadIdentity(did.getPublicKey().getFingerprint(), nodeDID==null, false);
                if(did.getPublicKey().getFingerprint() != null
                        && did.getPublicKey().getFingerprint().equals(didLoaded.getPublicKey().getFingerprint())) {
                    didLoaded.setVerified(true);
                    LOG.info("DID verification successful.");
                    verified = didLoaded;
                } else {
                    did.setVerified(false);
                    LOG.info("DID verification unsuccessful.");
                    verified = did;
                }
                e.setDID(verified);
                break;
            }
            case OPERATION_AUTHENTICATE: {
                LOG.info("Received authn DID request.");
                AuthenticateDIDRequest r = (AuthenticateDIDRequest)e.getData(AuthenticateDIDRequest.class);
                if(r == null) {
                    LOG.warning("Request required.");
                    r = new AuthenticateDIDRequest();
                    r.statusCode = AuthenticateDIDRequest.REQUEST_REQUIRED;
                    e.addNVP("authN",r);
                    break;
                }
                if(r.did == null) {
                    LOG.warning("DID required.");
                    r.statusCode = AuthenticateDIDRequest.DID_REQUIRED;
                    break;
                }
                if(r.did.getPublicKey().getFingerprint() == null) {
                    LOG.info("Fingerprint required.");
                    r.statusCode = AuthenticateDIDRequest.DID_FINGERPRINT_REQUIRED;
                    break;
                }
                if(r.did.getPassphrase() == null) {
                    LOG.info("Passphrase required.");
                    r.statusCode = AuthenticateDIDRequest.DID_PASSPHRASE_REQUIRED;
                    break;
                }
                AuthNRequest ar = (AuthNRequest)e.getData(AuthNRequest.class);
                GenerateKeyRingCollectionsRequest gkr = (GenerateKeyRingCollectionsRequest) e.getData(GenerateKeyRingCollectionsRequest.class);
                if(ar!=null && ar.identityPublicKey!=null)
                    r.did.setPublicKey(ar.identityPublicKey);
                else if(gkr!=null && gkr.identityPublicKey!=null)
                    r.did.setPublicKey(gkr.identityPublicKey);
                authenticateIdentity(r, nodeDID == null);
                if(r.did.getAuthenticated()) {
                    LOG.info("DID Authenticated, setting DID in header.");
                    if(nodeDID==null) {
                        // first authentication is the node itself
                        LOG.info("First authn is node.");
                        nodeDID = r.did;
                        nodeDID.setVerified(true);
                        nodeDID.setStatus(DID.Status.ACTIVE);
                        saveIdentity(r.did, true,false, false);
                        e.setDID(r.did);
                    } else {
                        if(activeIdentity!=null) {
                            activeIdentity.setStatus(DID.Status.INACTIVE);
                            saveIdentity(activeIdentity,  true,false, false);
                        }
                        activeIdentity = r.did;
                        activateIdentity(activeIdentity);
                        LOG.info("Active identity updated.");
                    }
                } else if(r.statusCode == AuthenticateDIDRequest.DID_USERNAME_UNKNOWN && r.autogenerate) {
                    LOG.info("Username unknown and autogenerate is true so save DID as authenticated...");
                    r.did.setAuthenticated(true); // true because we're going to create it
                    r.did.setVerified(true);
                    r.did.setStatus(DID.Status.ACTIVE);
                    e.setDID(r.did);
                    if(r.isNode) {
                        nodeDID = r.did;
                        saveIdentity(nodeDID, r.autogenerate, true, false);
                        LOG.info("Node identity saved.");
                    } else {
                        activeIdentity = r.did;
                        activateIdentity(activeIdentity);
                        LOG.info("Active identity saved.");
                    }
                }
                break;
            }
            case OPERATION_SAVE_IDENTITY: {
                LOG.info("Received save DID request.");
                DID did = (DID)e.getData(DID.class);
                if(did!=null) {
                    saveIdentity(did, true, false, false);
                }
                break;
            }
            case OPERATION_AUTHENTICATE_CREATE: {
                AuthenticateDIDRequest r = (AuthenticateDIDRequest)e.getData(AuthenticateDIDRequest.class);
                authenticateOrCreateIdentity(r);
                break;
            }
            case OPERATION_DELETE_IDENTITY: {
                String fingerprint = (String)e.getValue("fingerprint");
                Boolean success = identitiesDB.delete(fingerprint);
                e.addNVP("delete-success",success.toString());
                break;
            }
            case OPERATION_ADD_CONTACT: {
                LOG.info("Received add Contact request.");
                e.addNVP("contact", saveContact((DID)e.getValue("contact"), true, false));
                break;
            }
            case OPERATION_GET_CONTACT: {
                LOG.info("Received get Contact request.");
                String fingerprint = ((TextMessage) e.getMessage()).getText();
                DID contact = loadContact(fingerprint, false);
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

    private void activateIdentity(DID activeDID) {
        List<DID> dids = loadIdentities(1, MAX_IDENTITIES, false);
        for(DID did : dids) {
            if(did.getPublicKey().getFingerprint().equals(activeDID.getPublicKey().getFingerprint())) {
                activeDID.setStatus(DID.Status.ACTIVE);
                saveIdentity(activeDID, false, false, false);
            } else if(did.getStatus()==DID.Status.ACTIVE) {
                did.setStatus(DID.Status.INACTIVE);
                saveIdentity(did, false, false, false);
            }
        }
    }

    /**
     * Saves and returns Identity DID generating passphrase hash if none exists.
     * @param did DID
     */
    private DID saveIdentity(DID did, boolean autoCreate, boolean isNode, boolean toExternal) {
        LOG.info("Saving Identity DID...");
        if(did.getPassphraseHash() == null) {
            LOG.info("Hashing passphrase...");
            try {
                did.setPassphraseHash(new Hash(HashUtil.generatePasswordHash(did.getPassphrase()), Hash.Algorithm.PBKDF2WithHmacSHA1));
                // ensure passphrase is cleared
                did.setPassphrase(null);
            } catch (NoSuchAlgorithmException ex) {
                LOG.warning("Hashing Algorithm not supported while saving DID\n" + ex.getLocalizedMessage());
                return did;
            }
        }
            JSON json = new JSON(did.toJSON().getBytes(), DID.class.getName(), did.getPublicKey().getFingerprint(), false, false);
            json.setLocation(getServiceDirectory()+IDENTITY_DIR+did.getPublicKey().getFingerprint());
            InfoVault iv = new InfoVault();
            iv.content = json;
            iv.storeExternal = toExternal;
            iv.autoCreate = autoCreate;
            if(isNode) {
                nodesDB.save(iv);
                LOG.info("Node Identity DID saved.");
            } else {
                identitiesDB.save(iv);
                LOG.info("Identity DID saved.");
            }
        return did;
    }

    /**
     * Authenticates passphrase
     * @param r AuthenticateDIDRequest
     */
    private void authenticateIdentity(AuthenticateDIDRequest r, boolean isNode) {
        DID loadedDID = loadIdentity(r.did.getPublicKey().getFingerprint(), isNode, false);
        if(loadedDID==null) {
            r.did.setAuthenticated(false);
            r.statusCode = AuthenticateDIDRequest.DID_USERNAME_UNKNOWN;
            return;
        }
        if(loadedDID.getPassphraseHash()==null) {
            if(r.autogenerate) {
                r.did.setVerified(true);
                r.did.setAuthenticated(true);
                loadedDID = saveIdentity(r.did, true, isNode, false);
                LOG.info("Saved Identity DID: " + loadedDID);
            } else {
                LOG.warning("Unable to load DID and autogenerate=false. Authentication failed.");
                r.statusCode = AuthenticateDIDRequest.DID_USERNAME_UNKNOWN;
                return;
            }
        } else {
            LOG.info("Loaded Identity DID: "+loadedDID);
            Boolean authN = null;
            LOG.info("Verifying password hash...");
            try {
                authN = HashUtil.verifyPasswordHash(r.did.getPassphrase(), loadedDID.getPassphraseHash().getHash());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                LOG.warning(e.getLocalizedMessage());
            }
            LOG.info("AuthN: "+(authN != null && authN));
            r.did.setAuthenticated(authN != null && authN);
        }
        if(r.did.getAuthenticated()) {
            r.did = loadedDID;
            activeIdentity = loadedDID;
        }
    }

    private void authenticateOrCreateIdentity(AuthenticateDIDRequest r) {
        boolean isNode = nodeDID == null;
        DID result;
        LOG.info("Received verify DID request.");
        DID didLoaded = loadIdentity(r.did.getPublicKey().getFingerprint(), isNode, false);
        if(r.did.getPublicKey().getFingerprint() != null
                && r.did.getPublicKey().getFingerprint().equals(didLoaded.getPublicKey().getFingerprint())) {
            didLoaded.setVerified(true);
            LOG.info("DID verification successful.");
            result = didLoaded;
        } else {
            r.did.setVerified(false);
            LOG.info("DID verification unsuccessful.");
            result = r.did;
        }
        r.did = result;
        if(!r.did.getVerified()) {
            saveIdentity(r.did, true, isNode, false);
        } else {
            authenticateIdentity(r, isNode);
        }
        if(isNode) {
            nodeDID = r.did;
        }
    }

    private boolean isNewIdentity(String alias, boolean isNode, boolean fromExternal) {
        DID loadedDID = loadIdentity(alias, isNode, fromExternal);
        return loadedDID == null || loadedDID.getUsername() == null || loadedDID.getUsername().isEmpty();
    }

    private DID loadIdentity(String fingerprint, boolean isNode, boolean fromExternal) {
        InfoVault iv = isNode ? nodesDB.load(fingerprint) : identitiesDB.load(fingerprint);
        DID did = new DID();
        did.fromMap(iv.content.toMap());
        LOG.info("JSON loaded: "+iv.content.toJSON());
        LOG.info("Identity DID Loaded from map.");
        return did;
    }

    private List<DID> loadIdentities(int start, int numberIdentities, boolean fromExternal) {
        List<DID> dList = new ArrayList<>();
        List<InfoVault> infoVaults = new ArrayList<>();
        boolean success = identitiesDB.loadRange(start, numberIdentities, infoVaults);
        if(!success) {
            LOG.warning("Loading identities failed.");
            return dList;
        }
        DID did;
        for(InfoVault iv: infoVaults) {
            did = new DID();
            did.fromMap(iv.content.toMap());
            dList.add(did);
        }
        return dList;
    }

    /**
     * Saves and returns Contact DID.
     * @param did DID
     */
    private DID saveContact(DID did, boolean autoCreate, boolean storeExternal) {
        LOG.info("Saving Contact DID...");
        InfoVault iv = new InfoVault();
        iv.content = new JSON(did.toJSON().getBytes(), DID.class.getName(), did.getPublicKey().getFingerprint(), false, false);
        iv.content.setLocation(getServiceDirectory()+CONTACT_DIR+did.getPublicKey().getFingerprint());
        iv.autoCreate = autoCreate;
        iv.storeExternal = storeExternal;
        contactsDB.save(iv);
        LOG.info("Contact DID saved.");
        return did;
    }

    private DID loadContact(String fingerprint, boolean fromExternal) {
        DID loadedDID = new DID();
        InfoVault iv = contactsDB.load(fingerprint);
        loadedDID.fromMap(iv.content.toMap());
        LOG.info("JSON loaded: "+iv.content.toJSON());
        LOG.info("Contact DID Loaded from map.");
        return loadedDID;
    }

    private List<DID> loadContactRange(int begin, int numberEntries) {
        List<DID> loadedDIDs = new ArrayList<>();
        List<InfoVault> infoVaults = new ArrayList<>();
        DID did;
        if(contactsDB.loadRange(begin, numberEntries, infoVaults)) {
            for (InfoVault iv : infoVaults) {
                did = new DID();
                did.fromMap(iv.content.toMap());
                LOG.info("JSON loaded: " + iv.content.toJSON());
                loadedDIDs.add(did);
                LOG.info("Contact DID Loaded from map.");
            }
        }
        return loadedDIDs;
    }

    @Override
    public boolean start(Properties properties) {
        super.start(properties);
        LOG.info("Starting....");
        updateStatus(ServiceStatus.STARTING);
        // TODO: Support external drives (InfoVault)
        nodesDB = new InfoVaultFileDB();
        nodesDB.setBaseURL(new File(getServiceDirectory(),NODE_DIR).getAbsolutePath());
        identitiesDB = new InfoVaultFileDB();
        identitiesDB.setBaseURL(new File(getServiceDirectory(),IDENTITY_DIR).getAbsolutePath());
        contactsDB = new InfoVaultFileDB();
        contactsDB.setBaseURL(new File(getServiceDirectory(),CONTACT_DIR).getAbsolutePath());
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
