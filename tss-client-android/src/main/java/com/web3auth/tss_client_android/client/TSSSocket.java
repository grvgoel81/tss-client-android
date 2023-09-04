package com.web3auth.tss_client_android.client;

import org.json.JSONObject;

import java.net.URI;
import java.util.Date;

import io.socket.client.IO;
import io.socket.client.Socket;
import io.socket.emitter.Emitter;
import io.socket.engineio.client.transports.WebSocket;

public class TSSSocket {
    private final String session;
    private final int party;
    private Socket socket;

    public TSSSocket(String session, int party, String socketURL) {
        this.session = session;
        this.party = party;

        try {
            IO.Options options;
            boolean local_servers = System.getProperty("LOCAL_SERVERS") != null;
            String query = session.split(Delimiters.Delimiter4)[1];
            if (local_servers) {
                options = IO.Options.builder()
                        .setQuery(query)
                        .setTransports(new String[]{WebSocket.NAME})
                        .setReconnectionDelayMax(10000)
                        .setReconnectionAttempts(3)
                        .setForceNew(true)
                        .build();
            } else {
                options = IO.Options.builder()
                        .setPath("/tss/socket.io")
                        .setQuery(query)
                        .setTransports(new String[]{WebSocket.NAME})
                        .setSecure(true)
                        .setReconnectionDelayMax(10000)
                        .setReconnectionAttempts(3)
                        .setForceNew(true)
                        .build();
            }
            socket = IO.socket(URI.create(socketURL), options);
        } catch (Exception e) {
            e.printStackTrace();
        }

        setupSocketEventHandlers();
    }

    public String getSession() {
        return session;
    }

    public int getParty() {
        return party;
    }

    public Socket getSocket() {
        return socket;
    }

    private void setupSocketEventHandlers() {
        socket.on(Socket.EVENT_CONNECT_ERROR, (Emitter.Listener) args -> System.out.println("socket error, party: " + party));

        socket.on(Socket.EVENT_CONNECT, args -> System.out.println("connected, party: " + party));

        socket.on(Socket.EVENT_DISCONNECT, args -> System.out.println("disconnected, party: " + party));

        socket.on("precompute_complete", args -> {
            JSONObject jsonData = (JSONObject) args[0];
            String session = jsonData.optString("session");
            int party = jsonData.optInt("party", -1);
            if (session.isEmpty() || party == -1 ) {
                EventQueue.shared().addEvent(new Event(
                        "Server failed to respond with valid json",
                        this.session,
                        party,
                        new Date(),
                        EventType.SOCKET_DATA_ERROR
                ));
                return;
            }
            if (!session.equals(this.session)) {
                System.out.println("ignoring message for a different session...");
                return;
            }
            EventQueue.shared().addEvent(new Event(
                    String.valueOf(party),
                    session,
                    party,
                    new Date(),
                    EventType.PRECOMPUTE_COMPLETE
            ));

        });

        socket.on("precompute_failed", args -> {
            JSONObject jsonData = (JSONObject) args[0];
            String session = jsonData.optString("session");
            int party = jsonData.optInt("party", -1);
            if (session.isEmpty() || party == -1) {
                EventQueue.shared().addEvent(new Event(
                        "Server failed to respond with valid json",
                        this.session,
                        party,
                        new Date(),
                        EventType.SOCKET_DATA_ERROR
                ));
                return;
            }
            if (!session.equals(this.session)) {
                System.out.println("ignoring message for a different session...");
                return;
            }
            EventQueue.shared().addEvent(new Event(
                    String.valueOf(party),
                    session,
                    party,
                    new Date(),
                    EventType.PRECOMPUTE_ERROR
            ));
        });

        socket.on("send", args -> {
            JSONObject data = (JSONObject) args[0];
            String session = data.optString("session");
            int sender = data.optInt("sender", -1);
            int recipient = data.optInt("recipient", -1);
            String msg_type = data.optString("msg_type");
            String msg_data = data.optString("msg_data");
            if (session.isEmpty() || sender == -1 || recipient == -1 || msg_type.isEmpty()) {
                EventQueue.shared().addEvent(new Event(
                        "Server failed to respond with valid json",
                        this.session,
                        recipient,
                        new Date(),
                        EventType.SOCKET_DATA_ERROR
                ));
                return;
            }

            if (!session.equals(this.session)) {
                System.out.println("ignoring message for a different session...");
                return;
            }
            MessageQueue.shared().addMessage(new Message(
                    session,
                    sender,
                    recipient,
                    msg_type,
                    msg_data
            ));

        });
        socket.connect();
    }

    public void disconnect() {
        socket.disconnect();
    }

}

