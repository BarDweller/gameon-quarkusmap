/*******************************************************************************
 * Copyright (c) 2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.gameontext.map.auth;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Level;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.net.ssl.SSLContext;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.faulttolerance.Retry;
import org.gameontext.map.Log;
import org.gameontext.signed.SignedRequestSecretProvider;
import org.gameontext.signed.TimestampedKey;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;

/**
 * A wrapped/encapsulation of outbound REST requests to the player service.
 *
 * @see ApplicationScoped
 */
@ApplicationScoped
public class PlayerClient implements SignedRequestSecretProvider {

    private static final Duration cacheKeyDuration = Duration.ofHours(1);

    /** The Key to Sign JWT's with (once it's loaded) */
    private PrivateKey signingKey = null;

    /** Cache of player API keys */
    private ConcurrentMap<String,TimestampedKey> playerSecrets = new ConcurrentHashMap<>();


    @ConfigProperty( name = "PLAYER_SERVICE_URL", defaultValue = "x")
    String playerLocation;

    @ConfigProperty( name = "JWT_PRIVATE_KEY", defaultValue = "x")
    String pemKey;

    @ConfigProperty( name = "MAP_KEY", defaultValue = "x")   
    String registrationSecret;

    @ConfigProperty( name = "SYSTEM_ID", defaultValue = "x")
    String SYSTEM_ID;

    @ConfigProperty( name = "SWEEP_ID", defaultValue = "x")
    String sweepId;

    @ConfigProperty( name = "SWEEP_SECRET", defaultValue = "x")
    String sweepSecret;

    String systemSecret;

    /**
     */
    @PostConstruct
    protected void init() {
    }

    public boolean isHealthy() {
        String secret = systemSecret;
        if ( secret == null ) {
            secret = systemSecret = getSecretForId(SYSTEM_ID);
        }
        return secret != null;
    }

    /**
     * Obtain the key we'll use to sign the jwts we use to talk to Player endpoints.
     *
     * @throws IOException
     *             if there are any issues with the keystore processing.
     */
    private synchronized void getKeyStoreInfo() {
        try {

            String stripped = pemKey.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

            Decoder decoder = Base64.getDecoder();
            byte[] decoded = decoder.decode(stripped);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            signingKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException |
                InvalidKeySpecException e) {
            throw new IllegalStateException("Unable to process private key", e);
        }
    }

    /**
     * Obtain a JWT for the player id that can be used to invoke player REST services.
     *
     * We can create this, because we have access to the private certificate
     * required to sign such a JWT.
     *
     * @param playerId The id to build the JWT for
     * @return The JWT as a string.
     * @throws IOException
     */
    private String buildClientJwtForId(String playerId) throws IOException{
        // grab the key if needed
        if (signingKey == null)
            getKeyStoreInfo();

        JwtClaimsBuilder onwardsClaims = Jwt.claims();

        // Set the subject using the "id" field from our claims map.
        onwardsClaims.subject(playerId);

        // We'll use this claim to know this is a user token
        onwardsClaims.audience("client");       
        
        // we set creation time to 24hrs ago, to avoid timezone issues
        // client JWT has 24 hrs validity from now.
        Instant timePoint = Instant.now();
        onwardsClaims.issuedAt(timePoint.minus(cacheKeyDuration));
        onwardsClaims.expiresAt(timePoint.plus(cacheKeyDuration));        

        // finally build the new jwt, using the claims we just built, signing it
        // with our signing key, and adding a key hint as kid to the encryption
        // header, which is optional, but can be used by the receivers of the
        // jwt to know which key they should verifiy it with.
        String newJwt = onwardsClaims.jws().header("kid","playerssl").sign(signingKey);            

        return newJwt;
    }

    /**
     * Obtain the apiKey for the given id, using a local cache to avoid hitting couchdb too much.
     */
    @Override
    public String getSecretForId(String id) {
        //first.. handle our built-in key
        if (SYSTEM_ID.equals(id)) {
            return registrationSecret;
        } else if (sweepId.equals(id)) {
            return sweepSecret;
        }

        String playerSecret = null;

        TimestampedKey timedKey =  playerSecrets.get(id);
        if ( timedKey != null ) {
            playerSecret = timedKey.getKey();
            if ( !timedKey.hasExpired() ) {
                // CACHED VALUE! the id has been seen, and hasn't expired. Shortcut!
                Log.log(Level.FINER,"Map using cached key for {0}",id);
                return playerSecret;
            }
        }

        TimestampedKey newKey = new TimestampedKey(cacheKeyDuration);
        Log.log(Level.FINER,"Map asking player service for key for id {0}",id);

        try {
            playerSecret = getPlayerSecret(id);
            newKey.setKey(playerSecret);
        } catch (WebApplicationException e) {
            if ( playerSecret != null ) {
                // we have a stale value, return it
                return playerSecret;
            }

            // no dice at all, rethrow
            throw e;
        }

        // replace expired timedKey with newKey always.
        playerSecrets.put(id, newKey);

        // return fetched playerSecret
        return playerSecret;
    }

    /**
     * Obtain sharedSecret for player id.
     *
     * @param playerId
     *            The player id
     * @return The apiKey for the player
     */
    private String getPlayerSecret(String playerId) throws WebApplicationException {
        try{
            String jwt = buildClientJwtForId(playerId);    
            return getPlayerSecretInternal(jwt, playerId, playerLocation);
        }catch (HttpResponseException hre) {
            Log.log(Level.FINEST, this, "Error communicating with player service: {0} {1}", hre.getStatusCode(), hre.getMessage());
            throw new WebApplicationException("Error communicating with Player service", Response.Status.INTERNAL_SERVER_ERROR);
        }catch (ClientProtocolException cpe){
            Log.log(Level.FINEST, this, "Error communicating with player service: {0}", cpe.getMessage());
            throw new WebApplicationException("Error communicating with Player service", Response.Status.INTERNAL_SERVER_ERROR);            
        }catch(IOException io){
            Log.log(Level.FINEST, this, "Unexpected exception getting token for playerService: {0}", io);
            throw new WebApplicationException("Token Error communicating with Player service", Response.Status.INTERNAL_SERVER_ERROR);
        }catch ( NoSuchAlgorithmException e ) {
            Log.log(Level.FINEST, this, "Unexpected exception getting secret from playerService: {0}", e);
            throw new WebApplicationException("Error communicating with Player service", Response.Status.INTERNAL_SERVER_ERROR);
        } 
    }

    @Retry(maxRetries = 5, 
           retryOn = {HttpResponseException.class, IOException.class}, 
           abortOn = {ClientProtocolException.class, NoSuchAlgorithmException.class})
    private String getPlayerSecretInternal(String jwt, String playerId, String playerLocation) throws  NoSuchAlgorithmException, ClientProtocolException, HttpResponseException, IOException{
        
            HttpClient client = null;
            if("development".equals(System.getenv("MAP_PLAYER_MODE"))){
                System.out.println("Using development mode player connection. (DefaultSSL,NoHostNameValidation)");
                HttpClientBuilder b = HttpClientBuilder.create();

                //use the default ssl context, we have a trust store configured for player cert.
                SSLContext sslContext = SSLContext.getDefault();

                //use a very trusting truststore.. (not needed..)
                //SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

                b.setSSLContext( sslContext);

                //disable hostname validation, because we'll need to access the cert via a different hostname.
                b.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);

                client = b.build();
            }else{
                client = HttpClientBuilder.create().build();
            }

            HttpGet hg = new HttpGet(playerLocation+"/"+playerId);
            hg.addHeader("gameon-jwt", jwt);

            Log.log(Level.FINEST, this, "Building web target: {0}", hg.getURI().toString());

            // Make GET request using the specified target, get result as a
            // string containing JSON
            HttpResponse r = client.execute(hg);
            String result = new BasicResponseHandler().handleResponse(r);

            // Parse the JSON response, and retrieve the apiKey field value.
            ObjectMapper om = new ObjectMapper();
            JsonNode jn = om.readValue(result,JsonNode.class);

            Log.log(Level.FINER, this, "Got player record for {0} from player service", playerId);

            JsonNode creds = jn.get("credentials").get("sharedSecret");
            return creds.textValue();


    }
}
