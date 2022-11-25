/*
 * Copyright 2022 NuNimbus Foundation and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.nunimbus.protocol.saml.mappers;

import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.SAMLAttributeStatementMapper;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.Collection;
import java.util.ArrayList;
import java.util.List;

/**
 * Maps user properties, attributes, and/or text to an AttributeStatement.
 *
 * @author Andrew Summers</a>
 * @version $Revision: 1 $
 */
public class CombineUserAttributesPropertiesTextMapper extends AbstractSAMLProtocolMapper implements SAMLAttributeStatementMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.USER_ATTRIBUTE);
        property.setLabel(ProtocolMapperUtils.USER_MODEL_ATTRIBUTE_LABEL);
        property.setHelpText("Combine any text with user properties (email, federationLink, firstName, id, lastName, "
        		+ "serviceAccountClientLink, or username) and/or custom user attributes. Properties or attributes must "
        		+ "be surrounded with backticks (`). To escape a backtick, use a backslash (\\). For example: "
        		+ "`username`-last:\\``lastName`\\`_`customAttribName`");
        configProperties.add(property);
        AttributeStatementHelper.setConfigProperties(configProperties);

        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.AGGREGATE_ATTRS);
        property.setLabel(ProtocolMapperUtils.AGGREGATE_ATTRS_LABEL);
        property.setHelpText(ProtocolMapperUtils.AGGREGATE_ATTRS_HELP_TEXT);
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "saml-combine-user-attributes-properties-text-mapper";


    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Combine User Attributes, Properties, and Text";
    }

    @Override
    public String getDisplayCategory() {
        return AttributeStatementHelper.ATTRIBUTE_STATEMENT_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Combine any text with user properties (email, federationLink, firstName, id, lastName, "
        		+ "serviceAccountClientLink, or username) and/or custom user attributes. Properties or attributes must "
        		+ "be surrounded with backticks (`). To escape a backtick, use a backslash (\\). Note that if a "
        		+ "property or attribute does not exist, the attribute name will be used. For example: "
        		+ "`username`-last:\\``lastName`\\`_`customAttribName`";
    }

    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        UserModel user = userSession.getUser();
        String value = mappingModel.getConfig().get(ProtocolMapperUtils.USER_ATTRIBUTE);
        boolean aggregateAttrs = Boolean.valueOf(mappingModel.getConfig().get(ProtocolMapperUtils.AGGREGATE_ATTRS));
        Collection<String> attributeValues = KeycloakModelUtils.resolveAttribute(user, value, aggregateAttrs);

        char[] chars = value.toCharArray();

        ArrayList<String> valueSplit = new ArrayList<String>();
        valueSplit.add("");

        boolean isAttr = false;
        
        for (int i = 0; i < value.length(); i++) {
        	int last = valueSplit.size() - 1;

        	if (chars[i] == '`') {
        		if (i > 0 && chars[i - 1] == '\\') {
        			String lastStr = valueSplit.get(last);
        			char[] lastStrChars = lastStr.toCharArray();
        			lastStrChars[lastStr.length() - 1] = chars[i];        			
        			valueSplit.set(last, new String(lastStrChars));
        		}
        		else if (isAttr) {
        			String attrName = valueSplit.get(last);

        			switch(attrName) {
        			  case "email":
        				  valueSplit.set(last, user.getEmail());
        				  break;
        			  case "federationLink":
        				  valueSplit.set(last, user.getFederationLink());
        				  break;
        			  case "firstName":
        				  valueSplit.set(last, user.getFirstName());
        				  break;
        			  case "id":
        				  valueSplit.set(last, user.getId());
        				  break;
        			  case "lastName":
        				  valueSplit.set(last, user.getLastName());
        				  break;
        			  case "serviceAccountClientLink":
        				  valueSplit.set(last, user.getServiceAccountClientLink());
        				  break;
        			  case "username":
        				  valueSplit.set(last, user.getUsername());
        				  break;
        			  default:
        				  if (user.getAttributes().get(attrName) != null) {
        					  valueSplit.set(last, user.getAttributes().get(attrName).get(0));
        				  }
        				  else {
        					  valueSplit.set(last, attrName);
        				  }
        				  break;
        			}

        			valueSplit.add("");
        			isAttr = false;
        		}
        		else if (! isAttr) {
        			valueSplit.add("");
        			isAttr = true;
        		}
        	}
        	else {
        		valueSplit.set(last, valueSplit.get(last) + chars[i]);
        	}
        }

        value = ""; 

        for (int i = 0; i < valueSplit.size(); i++) {
        	value = value + valueSplit.get(i);
        }
        
        attributeValues.add(value);

        if (attributeValues.isEmpty()) return;
        AttributeStatementHelper.addAttributes(attributeStatement, mappingModel, attributeValues);
    }

    public static ProtocolMapperModel createAttributeMapper(String name, String userAttribute,
                                                            String samlAttributeName, String nameFormat, String friendlyName) {
        String mapperId = PROVIDER_ID;
        return AttributeStatementHelper.createAttributeMapper(name, userAttribute, samlAttributeName, nameFormat, friendlyName,
                mapperId);
    }
}