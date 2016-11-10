package org.wso2.carbon.security.userstore.jdbc.connector.virtual;

import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.security.userstore.jdbc.util.ConnectorContextThreadLocal;

public class VirtualAttribute extends Attribute {

    @Override
    public String getAttributeValue() {
        VirtualStoreConnector virtualStoreConnector = ConnectorContextThreadLocal.getVirtualStoreConnector();
        return virtualStoreConnector.getConnectorUserAttribute().getAttributeValue();
    }
}
