/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.identity.application.authenticator.samlsso;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.DefaultSAML2SSOManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.xml.sax.SAXException;

/**
 * Created by kanapriya on 1/16/18.
 */
public class SAML2FederatedLogoutRequestHandler extends HttpServlet {
    private static Log log = LogFactory.getLog(SAML2FederatedLogoutRequestHandler.class);

    private static boolean bootStrapped = false;

    public SAML2FederatedLogoutRequestHandler() {}

    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException
    {
        log.error("--------------------- Inside doGet ----------------------- ");
    }


    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException
    {
        log.error("-------------------------- Inside doPost ---------------------- ");
        initiateLogRequest(req, resp);
    }

    protected void initiateLogRequest(HttpServletRequest request, HttpServletResponse response) {

        try {

            log.error("Here **************1");

            doBootstrap();
            XMLObject samlObject = null;
            Map<String, String[]> values = request.getParameterMap();

            for (Map.Entry<String, String[]> entry : values.entrySet())
            {
                log.error("*****" + entry.getKey() + "/" + entry.getValue());
            }

            Enumeration<String> attrs = request.getAttributeNames();

            if (request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ) == null) {
                return;
            }

            log.error("Here **************2");


            samlObject = unmarshall(new String(Base64.decode(request.getParameter(
                    SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ))));

            log.error("Here **************3");

            String sessionIndex = null;
            if (samlObject instanceof LogoutRequest) {
                // if log out request

                log.error("Here **************4");

                LogoutRequest samlLogoutRequest = (LogoutRequest) samlObject;
                List<SessionIndex> sessionIndexes = samlLogoutRequest.getSessionIndexes();
                if (sessionIndexes != null && sessionIndexes.size() > 0) {
                    sessionIndex = sessionIndexes.get(0).getSessionIndex();
                }
            }

            log.error("Recieved sessionIndex **************" + sessionIndex);

            //here onwards modify
            String contextId = DefaultSAML2SSOManager.sessionIndexMap.get(sessionIndex);
            log.error("Recieved ContextId **************" + contextId);

            AuthenticationContext context = FrameworkUtils.getAuthenticationContextFromCache(contextId);
            FrameworkUtils.getLogoutRequestHandler().handle(request, response, context);

        } catch (Throwable e) {
            e.printStackTrace();
        }
    }




    public static void doBootstrap()
    {
        if (!bootStrapped) {
            Thread thread = Thread.currentThread();
            ClassLoader loader = thread.getContextClassLoader();
            thread.setContextClassLoader(new DefaultSAML2SSOManager().getClass().getClassLoader());
            try {
                DefaultBootstrap.bootstrap();
                bootStrapped = true;
            } catch (ConfigurationException e) {
                log.error("Error in bootstrapping the OpenSAML2 library", e);
            } finally {
                thread.setContextClassLoader(loader);
            }
        }
    }

    private XMLObject unmarshall(String samlString) throws SAMLSSOException
    {
        try
        {
            DocumentBuilderFactory documentBuilderFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            ByteArrayInputStream is = new ByteArrayInputStream(samlString.getBytes());
            Document document = docBuilder.parse(is);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            XMLObject response = unmarshaller.unmarshall(element);


            NodeList responseList = response.getDOM().getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "Response");
            if (responseList.getLength() > 0) {
                log.error("Invalid schema for the SAML2 response. Multiple Response elements found.");
                throw new SAMLSSOException("Error occurred while processing SAML2 response.");
            }


            NodeList assertionList = response.getDOM().getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
            if (assertionList.getLength() > 1) {
                log.error("Invalid schema for the SAML2 response. Multiple Assertion elements found.");
                throw new SAMLSSOException("Error occurred while processing SAML2 response.");
            }

            return response;
        } catch (ParserConfigurationException|UnmarshallingException|SAXException|IOException e) {
            throw new SAMLSSOException("Error in unmarshalling SAML Request from the encoded String", e);
        }
    }
}
