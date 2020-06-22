package ra.did;

import ra.common.*;
import ra.common.route.Route;

import java.io.FileNotFoundException;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;


/**
 * Decentralized IDentifier (DID) Service
 *
 * @author objectorange
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

    private static final int MAX_IDENTITIES = 100;
    private static final int MAX_CONTACTS = 10000;
    private static final int MAX_CONTACTS_LIST = 100;

    private DID nodeDID;

    private DID activeIdentity;

    private InfoVaultDB nodeDB;
    private InfoVaultDB identitiesDB;
    private InfoVaultDB contactsDB;

    public DIDService() {}

    public DIDService(MessageProducer producer, ServiceStatusListener serviceStatusListener) {
        super(producer, serviceStatusListener);
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
                String fingerprint = (String) DLC.getValue("fingerprint", e);
                if(fingerprint ==null) {
                    DLC.addErrorMessage("No Fingerprint", e);
                    break;
                }
                activeIdentity = loadIdentity(fingerprint, false);
                DLC.addEntity(activeIdentity, e);
                break;
            }
            case OPERATION_GET_ACTIVE_IDENTITY: {
                LOG.info("Received get active identity....");
                if(activeIdentity !=null) {
                    DLC.addEntity(activeIdentity, e);
                    break;
                }
                List<DID> identitiesLoaded = loadIdentities(1, MAX_IDENTITIES);
                for(DID d : identitiesLoaded) {
                    if(DID.Status.ACTIVE == d.getStatus()) {
                        activeIdentity = d;
                        DLC.addEntity(activeIdentity, e);
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
                    start = Integer.parseInt((String)DLC.getValue("identitiesStart", e));
                }
                if(DLC.getValue("identitiesNumber", e)!=null) {
                    identitiesNumber = Integer.parseInt((String)DLC.getValue("identitiesNumber", e));
                    if(identitiesNumber > MAX_IDENTITIES) {
                        identitiesNumber = MAX_IDENTITIES;
                    }
                }
                List<byte[]> contactsBytes = identitiesDB.loadRange(DID.class.getName(), start, identitiesNumber);
                DID identity;
                List<DID> identities = new ArrayList<>();
                for(byte[] i : contactsBytes) {
                    identity = new DID();
                    identity.fromJSON(new String(i));
                    identities.add(identity);
                }
                DLC.addNVP("identities", identities, e);
                break;
            }
            case OPERATION_VERIFY_IDENTITY: {
                DID verified;
                DID did = e.getDID();
                LOG.info("Received verify DID request.");
                DID didLoaded = loadIdentity(did.getPublicKey().getFingerprint(), nodeDID==null);
                if(didLoaded != null && did.getPublicKey().getFingerprint() != null && did.getPublicKey().getFingerprint().equals(didLoaded.getPublicKey().getFingerprint())) {
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
                AuthenticateDIDRequest r = (AuthenticateDIDRequest)DLC.getData(AuthenticateDIDRequest.class,e);
                if(r == null) {
                    LOG.warning("Request required.");
                    r = new AuthenticateDIDRequest();
                    r.statusCode = AuthenticateDIDRequest.REQUEST_REQUIRED;
                    DLC.addData(AuthenticateDIDRequest.class,r,e);
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
                AuthNRequest ar = (AuthNRequest)DLC.getData(AuthNRequest.class,e);
                GenerateKeyRingCollectionsRequest gkr = (GenerateKeyRingCollectionsRequest) DLC.getData(GenerateKeyRingCollectionsRequest.class,e);
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
                        saveIdentity(r.did, false, true);
                        e.setDID(r.did);
                    } else {
                        if(activeIdentity!=null) {
                            activeIdentity.setStatus(DID.Status.INACTIVE);
                            saveIdentity(activeIdentity, false, false);
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
                    if(nodeDID==null) {
                        // first authentication is the node itself
                        nodeDID = r.did;
                        saveIdentity(nodeDID, r.autogenerate, true);
                        LOG.info("First authn is node.");
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
                DID did = (DID)DLC.getData(DID.class,e);
                if(did!=null) {
                    e.setDID(saveIdentity(did, true, false));
                }
                break;
            }
            case OPERATION_AUTHENTICATE_CREATE: {
                AuthenticateDIDRequest r = (AuthenticateDIDRequest)DLC.getData(AuthenticateDIDRequest.class,e);
                authenticateOrCreateIdentity(r);
                break;
            }
            case OPERATION_DELETE_IDENTITY: {
                String fingerprint = (String)DLC.getValue("fingerprint", e);
                Boolean success = identitiesDB.delete(DID.class.getName(), fingerprint);
                DLC.addNVP("delete-success",success.toString(),e);
                break;
            }
            case OPERATION_ADD_CONTACT: {
                LOG.info("Received add Contact request.");
                DLC.addNVP("contact", saveContact((DID)DLC.getValue("contact",e), true), e);
                break;
            }
            case OPERATION_GET_CONTACT: {
                LOG.info("Received get Contact request.");
                String alias = ((TextMessage) e.getMessage()).getText();
                DID loadedDID = loadContact(alias);
                DLC.addNVP("contact", loadedDID, e);
                break;
            }
            case OPERATION_GET_CONTACTS: {
                LOG.info("Received get Contacts request.");
                int start = 0;
                int contactsNumber = 10; // default
                if(DLC.getValue("contactsStart", e)!=null) {
                    start = Integer.parseInt((String)DLC.getValue("contactsStart", e));
                }
                if(DLC.getValue("contactsNumber", e)!=null) {
                    contactsNumber = Integer.parseInt((String)DLC.getValue("contactsNumber", e));
                    if(contactsNumber > MAX_CONTACTS_LIST) {
                        contactsNumber = MAX_CONTACTS_LIST; // 1000 is max
                    }
                }
                List<byte[]> contactsBytes = contactsDB.loadRange(DID.class.getName(), start, contactsNumber);
                DID contact;
                List<DID> contacts = new ArrayList<>();
                for(byte[] c : contactsBytes) {
                    contact = new DID();
                    contact.fromJSON(new String(c));
                    contacts.add(contact);
                }
                DLC.addNVP("contacts", contacts, e);
                break;
            }
            case OPERATION_DELETE_CONTACT: {
                LOG.info("Received delete Contact request.");

                break;
            }
            case OPERATION_HASH: {
                HashRequest r = (HashRequest)DLC.getData(HashRequest.class,e);
                try {
                    if(r.generateHash)
                        r.hash = HashUtil.generateHash(r.contentToHash, Hash.Algorithm.SHA256);
                    if(r.generateFingerprint && r.hash != null) {
                        r.fingerprint = HashUtil.generateHash(r.hash.getHash(), Hash.Algorithm.SHA1);
                    }
                } catch (NoSuchAlgorithmException e1) {
                    r.statusCode = UNKNOWN_HASH_ALGORITHM;
                }
                break;
            }
            case OPERATION_VERIFY_HASH:{
                VerifyHashRequest r = (VerifyHashRequest)DLC.getData(VerifyHashRequest.class,e);
                try {
                    r.isAMatch = HashUtil.verifyHash(r.content, r.hashToVerify);
                } catch (NoSuchAlgorithmException e1) {
                    r.statusCode = UNKNOWN_HASH_ALGORITHM;
                }
                break;
            }
            default: deadLetter(e); // Operation not supported
        }
    }

    private void activateIdentity(DID activeDID) {
        List<DID> dids = loadIdentities(1, MAX_IDENTITIES);
        for(DID did : dids) {
            if(did.getPublicKey().getFingerprint().equals(activeDID.getPublicKey().getFingerprint())) {
                activeDID.setStatus(DID.Status.ACTIVE);
                saveIdentity(activeDID, false, false);
            } else if(did.getStatus()==DID.Status.ACTIVE) {
                did.setStatus(DID.Status.INACTIVE);
                saveIdentity(did, false, false);
            }
        }
    }

    /**
     * Saves and returns Identity DID generating passphrase hash if none exists.
     * @param did DID
     */
    private DID saveIdentity(DID did, boolean autoCreate, boolean isNode) {
        LOG.info("Saving Identity DID...");
        if(did.getPassphraseHash() == null) {
            LOG.info("Hashing passphrase...");
            try {
                did.setPassphraseHash(HashUtil.generatePasswordHash(did.getPassphrase()));
                // ensure passphrase is cleared
                did.setPassphrase(null);
            } catch (NoSuchAlgorithmException ex) {
                LOG.warning("Hashing Algorithm not supported while saving DID\n" + ex.getLocalizedMessage());
                return did;
            }
        }
        try {
            if(isNode) {
                nodeDB.save(
                        DID.class.getName(),
                        did.getPublicKey().getFingerprint(),
                        did.toJSON().getBytes(),
                        autoCreate);
                LOG.info("Node Identity DID saved.");
            } else {
                identitiesDB.save(
                        DID.class.getName(),
                        did.getPublicKey().getFingerprint(),
                        did.toJSON().getBytes(),
                        autoCreate);
                LOG.info("Identity DID saved.");
            }
        } catch (FileNotFoundException e) {
            LOG.warning(e.getLocalizedMessage());
        }
        return did;
    }

    /**
     * Authenticates passphrase
     * @param r AuthenticateDIDRequest
     */
    private void authenticateIdentity(AuthenticateDIDRequest r, boolean isNode) {
        DID loadedDID = loadIdentity(r.did.getPublicKey().getFingerprint(), isNode);
        if(loadedDID==null) {
            r.did.setAuthenticated(false);
            r.statusCode = AuthenticateDIDRequest.DID_USERNAME_UNKNOWN;
            return;
        }
        if(loadedDID.getPassphraseHash()==null) {
            if(r.autogenerate) {
                r.did.setVerified(true);
                r.did.setAuthenticated(true);
                loadedDID = saveIdentity(r.did, true, isNode);
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
                authN = HashUtil.verifyPasswordHash(r.did.getPassphrase(), loadedDID.getPassphraseHash());
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
        DID didLoaded = loadIdentity(r.did.getPublicKey().getFingerprint(), isNode);
        if(didLoaded != null && r.did.getPublicKey().getFingerprint() != null && r.did.getPublicKey().getFingerprint().equals(didLoaded.getPublicKey().getFingerprint())) {
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
            saveIdentity(r.did, true, isNode);
        } else {
            authenticateIdentity(r, isNode);
        }
        if(isNode) {
            nodeDID = r.did;
        }
    }

    private boolean isNewIdentity(String alias, boolean isNode) {
        DID loadedDID = loadIdentity(alias, isNode);
        return loadedDID == null || loadedDID.getUsername() == null || loadedDID.getUsername().isEmpty();
    }

    private DID loadIdentity(String fingerprint, boolean isNode) {
        DID loadedDID = new DID();
        byte[] content;
        try {
            content = isNode ? nodeDB.load(DID.class.getName(), fingerprint) : identitiesDB.load(DID.class.getName(), fingerprint);
        } catch (FileNotFoundException e) {
            return null;
        }
        String jsonBody = new String(content);
        LOG.info("JSON loaded: "+jsonBody);
        loadedDID.fromJSON(jsonBody);
        LOG.info("Identity DID Loaded from map.");
        return loadedDID;
    }

    private List<DID> loadIdentities(int start, int numberIdentities) {
        List<byte[]> bList = identitiesDB.loadRange(DID.class.getName(), start, numberIdentities);
        DID did;
        List<DID> dList = new ArrayList<>();
        for(byte[] b : bList) {
            did = new DID();
            did.fromMap((Map<String, Object>) JSONParser.parse(new String(b)));
            dList.add(did);
        }
        return dList;
    }

    /**
     * Saves and returns Contact DID.
     * @param did DID
     */
    private DID saveContact(DID did, boolean autoCreate) {
        LOG.info("Saving Contact DID...");
        try {
            contactsDB.save(
                    DID.class.getName(),
                    did.getPublicKey().getFingerprint(),
                    did.toJSON().getBytes(),
                    autoCreate);
        } catch (FileNotFoundException e) {
            LOG.warning(e.getLocalizedMessage());
        }
        LOG.info("Contact DID saved.");
        return did;
    }

    private DID loadContact(String fingerprint) {
        DID loadedDID = new DID();
        byte[] content;
        try {
            content = contactsDB.load(DID.class.getName(), fingerprint);
        } catch (FileNotFoundException e) {
            return null;
        }
        String jsonBody = new String(content);
        LOG.info("JSON loaded: "+jsonBody);
        loadedDID.fromMap((Map<String, Object>) JSONParser.parse(jsonBody));
        LOG.info("Contact DID Loaded from map.");
        return loadedDID;
    }

    private List<DID> loadContactRange(int begin, int numberEntries) {
        List<DID> loadedDID = new ArrayList<>();
        DID toLoad;
        List<byte[]> content = contactsDB.loadRange(DID.class.getName(), begin, numberEntries);
        for(byte[] c : content) {
            toLoad = new DID();
            String jsonBody = new String(c);
            LOG.info("JSON loaded: " + jsonBody);
            toLoad.fromJSON(jsonBody);
            loadedDID.add(toLoad);
            LOG.info("Contact DID Loaded from map.");
        }
        return loadedDID;
    }

    @Override
    public boolean start(Properties properties) {
        super.start(properties);
        LOG.info("Starting....");
        updateStatus(ServiceStatus.STARTING);
        // TODO: Support external drives (InfoVault)
        try {
            nodeDB = InfoVaultService.factory("node", getServiceDirectory().getAbsolutePath(), LocalFSInfoVaultDB.class.getName(), properties);
            identitiesDB = InfoVaultService.factory("identities", getServiceDirectory().getAbsolutePath(), LocalFSInfoVaultDB.class.getName(), properties);
            contactsDB = InfoVaultService.factory("contacts", getServiceDirectory().getAbsolutePath(), LocalFSInfoVaultDB.class.getName(), properties);
        } catch (ClassNotFoundException e) {
            LOG.warning(e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            return false;
        } catch (IllegalAccessException e) {
            LOG.warning(e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            return false;
        } catch (InstantiationException e) {
            LOG.warning(e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            return false;
        } catch (InvocationTargetException e) {
            LOG.warning(e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            return false;
        } catch (NoSuchMethodException e) {
            LOG.warning(e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            return false;
        }
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
