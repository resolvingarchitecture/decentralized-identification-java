package ra.did;

import ra.common.identity.DID;
import ra.common.service.ServiceMessage;

import java.util.Map;

public class VouchRequest extends ServiceMessage {

    public static final int SIGNER_REQUIRED = 1;
    public static final int SIGNEE_REQUIRED = 2;
    public static final int ATTRIBUTES_REQUIRED = 3;

    public DID signer;
    public DID signee;
    public Map<String, Object> attributesToSign;

    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> m = super.toMap();
        if(signer!=null) m.put("signer",signer.toMap());
        if(signee!=null) m.put("signee",signee.toMap());
        if(attributesToSign!=null) m.put("attributesToSign", attributesToSign);
        return m;
    }

    @Override
    public void fromMap(Map<String, Object> m) {
        super.fromMap(m);
        if(m.get("signer")!=null) {
            signer = new DID();
            signer.fromMap((Map<String, Object>)m.get("signer"));
        }
        if(m.get("signee")!=null) {
            signee = new DID();
            signee.fromMap((Map<String, Object>)m.get("signee"));
        }
        if(m.get("attributesToSign")!=null) {
            attributesToSign = (Map<String, Object>)m.get("attributesToSign");
        }
    }

}
