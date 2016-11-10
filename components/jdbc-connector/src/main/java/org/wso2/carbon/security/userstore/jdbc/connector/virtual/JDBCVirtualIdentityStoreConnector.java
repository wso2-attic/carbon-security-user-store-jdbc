package org.wso2.carbon.security.userstore.jdbc.connector.virtual;

import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.security.userstore.jdbc.connector.JDBCIdentityStoreConnector;
import org.wso2.carbon.security.userstore.jdbc.util.ConnectorContextThreadLocal;

import java.util.List;

public class JDBCVirtualIdentityStoreConnector extends JDBCIdentityStoreConnector {

    @Override
    public Attribute addUser(List<Attribute> attributes) throws IdentityStoreException {
        VirtualStoreConnector virtualStoreConnector = ConnectorContextThreadLocal.getVirtualStoreConnector();
        virtualStoreConnector.addAttribute(attributes);
        return new VirtualAttribute();
    }

}
