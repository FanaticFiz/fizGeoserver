/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.geoserver.security.oauth2.GeoServerOAuthRemoteTokenServices;
import org.springframework.security.crypto.codec.Base64;

/**
 * Remote Token Services for Google token details.
 *
 * @author Alessio Fabiani, GeoSolutions S.A.S.
 */
public class GoogleTokenServices extends GeoServerOAuthRemoteTokenServices {

    public GoogleTokenServices() {
        super(new GoogleAccessTokenConverter());
    }

    protected Map<String, Object> checkToken(String accessToken) {
        Claims claims = Jwts.parser()
                .setSigningKey(clientSecret.getBytes())
                .parseClaimsJws(accessToken)
                .getBody();

        LOGGER.warn("Fiz claims: {}", claims);
        return claims;
    }

    protected void transformNonStandardValuesToStandardValues(Map<String, Object> map) {
        LOGGER.debug("Original map = " + map);
//        map.put("client_id", map.get("issued_to")); // Google sends 'client_id' as 'issued_to'
//        map.put("user_name", map.get("user_id")); // Google sends 'user_name' as 'user_id'
        LOGGER.debug("Transformed = " + map);
    }

    protected String getAuthorizationHeader(String accessToken) {
        String creds = String.format("%s:%s", clientId, clientSecret);
        return "Basic " + new String(Base64.encode(creds.getBytes(StandardCharsets.UTF_8)));
    }
}
