package com.web3auth.tss_client_android.client;

import android.util.Base64;

import androidx.core.util.Pair;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.web3auth.tss_client_android.client.util.ByteUtils;
import com.web3auth.tss_client_android.client.util.Secp256k1;
import com.web3auth.tss_client_android.client.util.Triple;
import com.web3auth.tss_client_android.dkls.ChaChaRng;
import com.web3auth.tss_client_android.dkls.Counterparties;
import com.web3auth.tss_client_android.dkls.DKLSComm;
import com.web3auth.tss_client_android.dkls.DKLSError;
import com.web3auth.tss_client_android.dkls.Precompute;
import com.web3auth.tss_client_android.dkls.SignatureFragments;
import com.web3auth.tss_client_android.dkls.ThresholdSigner;
import com.web3auth.tss_client_android.dkls.Utilities;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import io.socket.client.Socket;

public class TSSClient {
    private final String session;
    private final int parties;
    private boolean consumed = false;
    private final ThresholdSigner signer;
    private final ChaChaRng rng;
    private final DKLSComm comm;
    private final int index;
    private final String pubKey;

    /**
     * Constructor
     *
     * @param session            The session to be used
     * @param index              The party index of this client, indexing starts at zero, may not be greater than (parties.count-1)
     * @param parties            The total count of all parties
     * @param endpoints          Server endpoints for web requests, must be equal to parties.count, contains nil at endpoints.index == index
     * @param tssSocketEndpoints Server endpoints for socket communication, contains nil at endpoints.index == index
     * @param share              The share for the client, base64 encoded bytes
     * @param pubKey             The public key, base64 encoded bytes
     * @throws TSSClientError Parties and tss sockets length are not equal, data provided in parameters is not correct, or not of the correct format.
     */
    public TSSClient(String session, int index, int[] parties, String[] endpoints,
                     String[] tssSocketEndpoints, String share, String pubKey) throws TSSClientError {
        if (parties.length != tssSocketEndpoints.length) {
            throw new TSSClientError("Parties and socket length must be equal");
        }

        if (parties.length != endpoints.length) {
            throw new TSSClientError("Parties and endpoint length must be equal");
        }

        this.index = index;
        this.session = session;
        this.parties = parties.length;
        this.pubKey = pubKey;

        for (int i = 0; i < endpoints.length; i++) {
            if (i != this.index) {
                TSSConnectionInfo.getShared().addInfo(session, i, endpoints[i], tssSocketEndpoints[i]);
            }
        }

        try {
            comm = new DKLSComm(session, (int) this.index, parties.length);

            rng = new ChaChaRng();

            signer = new ThresholdSigner(session, (int) this.index, parties.length, parties.length, share, pubKey);
        } catch (DKLSError error) {
            throw new TSSClientError(error.getMessage());
        }
    }

    /**
     * Returns the session ID from the session
     *
     * @param session The session.
     * @return String
     * @throws TSSClientError Session format is invalid
     */
    public static String sid(String session) throws TSSClientError {
        String[] sessionParts = session.split(Delimiters.Delimiter4);
        if (sessionParts.length >= 2) {
            return sessionParts[1];
        } else {
            throw new TSSClientError("Invalid session format");
        }
    }

    private boolean setup() {
        return signer.setup(rng, comm);
    }

    /**
     * Performs the DKLS protocol to calculate a precompute for this client, each other party also calculates their own precompute
     *
     * @param serverCoeffs The coefficients for the servers, ordered according to endpoint index
     * @param signatures   The signatures for the servers, ordered according to endpoint index
     * @return Precompute
     * @throws TSSClientError Sockets are not connected, one or more servers returns invalid response, one or more parties fail in precompute calculation.
     * @see Precompute
     */
    public Precompute precompute(Map<String, String> serverCoeffs, List<String> signatures) throws TSSClientError {
        boolean local_servers = System.getProperty("LOCAL_SERVERS") != null;
        EventQueue.shared().updateFocus(new Date());
        for (int i = 0; i < parties; i++) {
            if (i != index) {
                Socket tssSocket = TSSConnectionInfo.getShared().lookupEndpoint(session, i).second.getSocket();
                if (tssSocket == null || tssSocket.id() == null) {
                    throw new TSSClientError("socket not connected yet, party: " + i + ", session: " + session);
                }
            }
        }

        for (int i = 0; i < parties; i++) {
            if (i != index) {
                try {
                    Pair<TSSEndpoint, TSSSocket> tssConnection = TSSConnectionInfo.getShared().lookupEndpoint(session, i);
                    String socketID = tssConnection.second.getSocket().id();
                    String tssUrl = tssConnection.first.getUrl();
                    String urlStr = tssUrl + "/precompute";
                    URL url = new URL(urlStr);
                    System.out.println("x-web3-session-id: " + TSSClient.sid(session));
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Access-Control-Allow-Origin", "*");
                    connection.setRequestProperty("Access-Control-Allow-Methods", "GET, POST");
                    connection.setRequestProperty("Access-Control-Allow-Headers", "Content-Type");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setRequestProperty("x-web3-session-id", TSSClient.sid(session));


                    List<String> endpointStrings = new ArrayList<>();
                    List<TSSEndpoint> endpoints = TSSConnectionInfo.getShared().allEndpoints(session);
                    for (TSSEndpoint endpoint : endpoints) {
                        endpointStrings.add(local_servers ? endpoint.getUrl().replace("10.0.2.2", "localhost") : endpoint.getUrl());
                    }
                    endpointStrings.add((int) index, "websocket:" + socketID);

                    LinkedHashMap<String, Object> msg = new LinkedHashMap<>();
                    List<Integer> partiesList = new ArrayList<>();
                    for (int j = 0; j < parties; j++) {
                        partiesList.add(j);
                    }
                    msg.put("endpoints", endpointStrings);
                    msg.put("session", session);
                    msg.put("parties", partiesList);
                    msg.put("player_index", (long) i);
                    msg.put("threshold", parties);
                    msg.put("pubkey", pubKey);
                    msg.put("notifyWebsocketId", socketID);
                    msg.put("sendWebsocket", socketID);
                    msg.put("server_coeffs", serverCoeffs);
                    msg.put("signatures", signatures);

                    Gson gson = new Gson();
                    byte[] jsonData = gson.toJson(msg).getBytes(StandardCharsets.UTF_8);
                    connection.setDoOutput(true);
                    try (DataOutputStream out = new DataOutputStream(connection.getOutputStream())) {
                        out.write(jsonData);
                        out.flush();
                    }

                    if (connection.getResponseCode() != 200) {
                        throw new TSSClientError("Failed precompute route for " + urlStr);
                    }
                    connection.disconnect();
                } catch (Exception e) {
                    throw new TSSClientError(e.toString());
                }
            }
        }

        if (!setup()) {
            throw new TSSClientError("Failed to setup client");
        }

        try {
            String partyArray = IntStream.range(0, parties).mapToObj(String::valueOf).collect(Collectors.joining(","));
            Counterparties counterparties = new Counterparties(partyArray);
            Precompute result = signer.precompute(counterparties, rng, comm);
            consumed = false;
            EventQueue.shared().addEvent(new Event("precompute_complete", session, index, new Date(), EventType.PRECOMPUTE_COMPLETE));
            return result;
        } catch (DKLSError error) {
            EventQueue.shared().addEvent(new Event("precompute_failed", session, index, new Date(), EventType.PRECOMPUTE_ERROR));
            throw new TSSClientError(error.getMessage());
        }
    }

    /**
     * Retrieves the signature fragments for each server, calculates its own fragment with the precompute, then performs local signing and verification
     *
     * @param message         The message or message hash.
     * @param hashOnly        Whether message is the hash of the message.
     * @param originalMessage The original message the hash was taken from, if not nil will be compared against message hash.
     * @param precompute      The previously calculated Precompute for this client
     * @param signatures      The signatures for the servers
     * @return (BigInteger, BigInteger, Byte)
     * @throws TSSClientError Not all servers have finished with their precompute calculation. Client has already signed a message. Message and its' hash do not match or original message is not provided. Servers provided invalid response or are unreachable. Signature verification failed.
     * @see Triple
     */
    public Triple<BigInteger, BigInteger, Byte> sign(String message, boolean hashOnly, String originalMessage,
                                                     Precompute precompute, List<String> signatures) throws TSSClientError {
        try {
            if (!isReady()) {
                throw new TSSClientError("Client is not ready");
            }

            if (consumed) {
                throw new TSSClientError("This instance has already signed a message and cannot be reused");
            }

            Integer precomputesComplete = EventQueue.shared().countEvents(session).getOrDefault(EventType.PRECOMPUTE_COMPLETE, 0);
            if (precomputesComplete == null || precomputesComplete != parties) {
                throw new TSSClientError("Insufficient Precomputes");
            }

            if (!hashOnly) {
                if (originalMessage != null) {
                    String hashedMessage = TSSHelpers.hashMessage(originalMessage);
                    if (!hashedMessage.equals(message)) {
                        throw new TSSClientError("hash of original message does not match message");
                    }
                } else {
                    throw new TSSClientError("Original message has to be provided");
                }
            }

            List<String> fragments = new ArrayList<>();
            for (int i = 0; i < precomputesComplete; i++) {
                if (i != index) {
                    TSSEndpoint tssConnection = TSSConnectionInfo.getShared().lookupEndpoint(session, (int) i).first;
                    String urlStr = tssConnection.getUrl() + "/sign";
                    URL url = new URL(urlStr);
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Access-Control-Allow-Origin", "*");
                    connection.setRequestProperty("Access-Control-Allow-Methods", "GET, POST");
                    connection.setRequestProperty("Access-Control-Allow-Headers", "Content-Type");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setRequestProperty("x-web3-session-id", TSSClient.sid(session));

                    LinkedHashMap<String, Object> msg = new LinkedHashMap<>();
                    msg.put("session", session);
                    msg.put("sender", index);
                    msg.put("recipient", i);
                    msg.put("msg", message);
                    msg.put("hash_only", hashOnly);
                    msg.put("original_message", originalMessage != null ? originalMessage : "");
                    msg.put("hash_algo", "keccak256");
                    msg.put("signatures", signatures);


                    Gson gson = new Gson();
                    byte[] data = gson.toJson(msg).getBytes(StandardCharsets.UTF_8);
                    connection.setDoOutput(true);
                    try (DataOutputStream out = new DataOutputStream(connection.getOutputStream())) {
                        out.write(data);
                        out.flush();
                    }

                    if (connection.getResponseCode() != 200) {
                        throw new TSSClientError("Failed send route for " + urlStr);
                    }

                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                        String response = reader.lines().collect(Collectors.joining());
                        Map<String, String> responseMap = new ObjectMapper().readValue(response, new TypeReference<>() {
                        });
                        String signatureFragment = responseMap.entrySet().iterator().next().getValue();
                        fragments.add(signatureFragment);
                    }

                    connection.disconnect();
                }
            }

            String signatureFragment = signWithPrecompute(message, hashOnly, precompute);
            fragments.add(signatureFragment);

            String input = String.join(",", fragments);
            SignatureFragments sigFrags = new SignatureFragments(input);

            String signature = verifyWithPrecompute(message, hashOnly, precompute, sigFrags, pubKey);

            String precompute_r = precompute.getR();
            byte[] decoded_r = android.util.Base64.decode(precompute_r, Base64.NO_WRAP);
            byte[] decoded = android.util.Base64.decode(signature, Base64.NO_WRAP);
            String sighex = ByteUtils.convertByteToHexadecimal(decoded);
            BigInteger r = new BigInteger(sighex.substring(0, 64), 16);
            BigInteger s = new BigInteger(sighex.substring(64), 16);
            byte recoveryParam = (byte) (decoded_r[decoded_r.length - 1] % 2);

            // boolean _sLessThanHalf = true;
            // if (_sLessThanHalf) {
            BigInteger halfOfSecp256k1n = Secp256k1.HALF_CURVE_ORDER;
            if (s.compareTo(halfOfSecp256k1n) > 0) {
                s = Secp256k1.CURVE.getN().subtract(s);
                recoveryParam = (byte) ((recoveryParam + 1) % 2);
            }
            // }

            consumed = true;
            return new Triple<>(s, r, recoveryParam);
        } catch (Exception | DKLSError e) {
            throw new TSSClientError(e.getMessage());
        }
    }

    /**
     * Locally signs a message, returning a signature fragment.
     *
     * @param message    The message or message hash to sign
     * @param hashOnly   If the message is just the hash
     * @param precompute The calculated precompute.
     * @return `String`
     * @throws TSSClientError Incorrect parameters provided.
     * @see Precompute
     */
    private String signWithPrecompute(String message, boolean hashOnly, Precompute precompute) throws TSSClientError {
        try {
            return Utilities.localSign(message, hashOnly, precompute);
        } catch (DKLSError error) {
            throw new TSSClientError(error.getMessage());
        }
    }

    /**
     * Verifies a locally signed message, returning the full signature
     *
     * @param message    The message of message hash.
     * @param hashOnly   If the message is just a hash.
     * @param precompute The calculated precompute.
     * @param fragments  The signature fragments.
     * @param pubKey     The public key used to sign the message.
     * @return `String`
     * @see SignatureFragments
     * @see Precompute
     */
    private String verifyWithPrecompute(String message, boolean hashOnly, Precompute precompute, SignatureFragments fragments, String pubKey) throws DKLSError {
        return Utilities.localVerify(message, hashOnly, precompute, fragments, pubKey);
    }

    /**
     * Checks notifications to determine if all parties have finished calculating a precompute before signing can be attempted
     *
     * @return boolean
     * @throws TSSClientError If a failure notification exists for any party or exceeds the timeout (5 seconds)
     */
    public boolean isReady() throws TSSClientError {
        return isReady(5000);
    }

    /**
     * Checks notifications to determine if all parties have finished calculating a precompute before signing can be attempted
     *
     * @param timeout The maximum number of seconds to wait, in seconds.
     * @return boolean
     * @throws TSSClientError If a failure notification exists for any party or exceeds the timeout
     */
    public boolean isReady(Integer timeout) throws TSSClientError {
        Date now = new Date();
        int offset = timeout != null ? timeout : 5000;
        boolean result = false;
        try {
            while (new Date().getTime() < now.getTime() + offset) {
                Map<EventType, Integer> counts = EventQueue.shared().countEvents(session);
                Integer precomputeErrorCount = counts.getOrDefault(EventType.PRECOMPUTE_ERROR, 0);
                if (precomputeErrorCount != null && precomputeErrorCount > 0) {
                    throw new TSSClientError("Error occurred during precompute");
                }

                Integer socketDataError = counts.getOrDefault(EventType.SOCKET_DATA_ERROR, 0);
                if (socketDataError != null && socketDataError > 0) {
                    throw new TSSClientError("Servers responded with invalid data");
                }

                Integer precomputeCompleteCount = counts.getOrDefault(EventType.PRECOMPUTE_COMPLETE, 0);
                if (precomputeCompleteCount != null && precomputeCompleteCount.equals(parties)) {
                    result = true;
                    break;
                }
            }
        } catch (Exception e) {
            throw new TSSClientError(e.getMessage());
        }
        return result;
    }

    /**
     * Checks if socket connections have been established and are ready to be used, for all parties, before precompute can be attempted
     *
     * @return boolean
     * @throws TSSClientError If the timeout is exceeded (5 seconds)
     */
    public boolean checkConnected() throws TSSClientError {
        return checkConnected(5000);
    }

    /**
     * Checks if socket connections have been established and are ready to be used, for all parties, before precompute can be attempted
     *
     * @param timeout The maximum number of seconds to wait, in seconds.
     * @return boolean
     * @throws TSSClientError If the timeout is exceeded
     */
    public boolean checkConnected(Integer timeout) throws TSSClientError {
        Date now = new Date();
        int offset = timeout != null ? timeout : 5000;
        boolean result = false;
        int connections = 0;
        List<Integer> connectedParties = new ArrayList<>();

        while (new Date().getTime() < now.getTime() + offset) {
            for (int party_index = 0; party_index < parties; party_index++) {
                if (party_index != index) {
                    if (!connectedParties.contains(party_index)) {
                        try {
                            Socket socketConnection = TSSConnectionInfo.getShared().lookupEndpoint(session, party_index).second.getSocket();
                            if (socketConnection == null) {
                                continue;
                            }
                            if (socketConnection.connected() &&
                                    socketConnection.id() != null) {
                                connections++;
                                connectedParties.add(party_index);
                            }
                        } catch (Exception ex) {
                            throw new TSSClientError(ex.toString());
                        }
                    }
                }
            }

            if (connections == parties - 1) {
                result = true;
                break;
            }
        }
        return result;
    }

    /**
     * Performs cleanup after signing, removing all messages, events and connections for this signer
     *
     * @param signatures The signatures for the servers
     * @throws TSSClientError If a server fails or is unreachable.
     */
    public void cleanup(String[] signatures) throws TSSClientError {
        MessageQueue.shared().removeMessages(this.session);
        EventQueue.shared().removeEvents(this.session);
        consumed = false;

        for (int i = 0; i < this.parties; i++) {
            if (i != this.index) {
                try {
                    Pair<TSSEndpoint, TSSSocket> tssConnection = TSSConnectionInfo.getShared().lookupEndpoint(this.session, i);
                    String url = tssConnection.first.getUrl();
                    URL endpoint = new URL(url + "/cleanup");
                    HttpURLConnection connection = (HttpURLConnection) endpoint.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Access-Control-Allow-Origin", "*");
                    connection.setRequestProperty("Access-Control-Allow-Methods", "GET, POST");
                    connection.setRequestProperty("Access-Control-Allow-Headers", "Content-Type");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setRequestProperty("x-web3-session-id", TSSClient.sid(session));

                    LinkedHashMap<String, Object> msg = new LinkedHashMap<>();
                    msg.put("session", session);
                    msg.put("signatures", signatures);

                    Gson gson = new Gson();
                    byte[] data = gson.toJson(msg).getBytes(StandardCharsets.UTF_8);
                    connection.setDoOutput(true);
                    OutputStream out = connection.getOutputStream();
                    out.write(data);

                    int responseCode = connection.getResponseCode();
                    if (responseCode != 200) {
                        throw new TSSClientError("Failed to cleanup for " + url);
                    }

                    connection.disconnect();
                } catch (Exception e) {
                    throw new TSSClientError(e.toString());
                }
            }
        }
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        TSSConnectionInfo.getShared().removeAll(session);
        MessageQueue.shared().removeMessages(session);
        EventQueue.shared().removeEvents(session);
    }
}
