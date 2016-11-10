package org.wso2.carbon.security.userstore.jdbc.connector.virtual;

import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.store.CredentialStore;
import org.wso2.carbon.identity.mgt.store.IdentityStore;

import javax.security.auth.callback.Callback;
import java.util.List;
import java.util.ArrayList;



/**
 * VirtualStoreConnector
 *
 */
public class VirtualStoreConnector {

    private IdentityStore identityStore = null;
    private CredentialStore credentialStore = null;

    private Attribute connectorUserAttribute = null;

    private List<Attribute> attributes = new ArrayList<>();

    public void init(IdentityStore identityStore, CredentialStore credentialStore) {
        this.identityStore = identityStore;
        this.credentialStore = credentialStore;
    }

    public void addAttribute(List<Attribute> attributes) throws IdentityStoreException {
        this.attributes = attributes;
    }

    public void addCredential(Callback[] callbacks) throws CredentialStoreException {
        //We have both attributes and callbacks here to do the single sql insert.
        //Update the attribute after add attribute list
    }

    public Attribute getConnectorUserAttribute() {
        return connectorUserAttribute;
    }
}
