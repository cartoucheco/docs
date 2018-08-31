/**
 * A tool to demonstrate sending associate requests to the Cartouche API.
 *
 * Usage:
 *    associate --keyfile=path/to/key.json [--url=url] domain.luxe address
 *
 * Example:
 *    associate --keyfile=../../key.json nic.luxe 0x314159265dd8dbb310642f98f50c066173c1259b
 *
 * This code is licensed CC-0; adapt and use it as you wish without restriction.
 */

package co.cartouche.associate;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import com.google.gson.Gson;
import org.apache.commons.cli.*;
import org.apache.commons.io.IOUtils;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.crypto.Sign;
import org.web3j.ens.NameHash;
import org.web3j.utils.Numeric;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;

public class Associate {
    /**
     * Encodes a secp256k1 signature as a hex string in the format expected by the Cartouche API.
     */
    static String encodeSignature(Sign.SignatureData sig) {
        StringBuilder sighex = new StringBuilder();
        byte[] r = sig.getR();
        byte[] s = sig.getS();
        sighex.append(Numeric.toHexString(r, 0, r.length, true));
        sighex.append(Numeric.toHexString(s, 0, s.length, false));
        sighex.append(String.format("%02x", sig.getV()));
        return sighex.toString();
    }

    /*
     * Generates a valid secp256k1 signature for an associate request.
     */
    static String signAssociateRequest(Credentials wallet, String name, Address owner, int nonce) {
        byte[] associateData = new byte[96];
        byte[] node = NameHash.nameHashAsBytes(name);
        System.arraycopy(node, 0, associateData, 0, 32);
        byte[] addressData = owner.toUint160().getValue().toByteArray();
        System.arraycopy(addressData, 0, associateData, 32 + (32 - addressData.length), addressData.length);
        byte[] nonceData = BigInteger.valueOf(nonce).toByteArray();
        System.arraycopy(nonceData, 0, associateData, 64 + (32 - nonceData.length), nonceData.length);
        Sign.SignatureData sig = Sign.signMessage(associateData, wallet.getEcKeyPair(), true);
        return encodeSignature(sig);
    }

    /*
     * Makes an HTTP post request, encodinng the request data as JSON and decoding the responnse data likewise.
     */
    static <I, O> O jsonRequest(String url, I request, Class<O> classOfO) throws UnsupportedEncodingException, MalformedURLException, IOException {
        Gson gson = new Gson();
        URLConnection connection = new URL(url).openConnection();
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json");
        try(OutputStream out = connection.getOutputStream()) {
            Writer writer = new OutputStreamWriter(out, "utf-8");
            writer.write(gson.toJson(request));
            writer.close();
        }
        InputStream response = connection.getInputStream();
        return gson.fromJson(IOUtils.toString(response, "utf-8"), classOfO);
    }

    static class NonceRequest {
        String name;
    }

    static class NonceResponse {
        int result;
    }

    /*
     * Fetches the current nonce for a domain from the Cartouche API.
     */
    static int getNonce(String name, String url) throws UnsupportedEncodingException, MalformedURLException, IOException {
        NonceRequest request = new NonceRequest();
        request.name = name;
        return jsonRequest(url + "nonce", request, NonceResponse.class).result;
    }

    static class AssociateRequest {
        String domain;
        String owner;
        int nonce;
        String signature;
    }

    static class AssociateResponse {
        String result;
    }

    /*
     * Associates a domain with an Ethereum account using the Cartouche API.
     */
    static void associate(Credentials wallet, String name, String owner, String url) throws UnsupportedEncodingException, MalformedURLException, IOException {
        int nonce = getNonce(name, url);

        AssociateRequest request = new AssociateRequest();
        request.domain = name;
        request.owner = owner;
        request.nonce = nonce;
        request.signature = signAssociateRequest(wallet, name, new Address(owner), nonce);

        AssociateResponse response = jsonRequest(url + "associate", request, AssociateResponse.class);
        System.out.println(response.result);
    }

    class WalletFile {
        String address;
        String key;
    }

    /*
     * Loads a secp256k1 keypair from a JSON file.
     */
    static Credentials loadCredentials(String path) throws IOException {
        Gson gson = new Gson();
        WalletFile wallet = gson.fromJson(IOUtils.toString(new FileInputStream(path), "utf-8"), WalletFile.class);
        return Credentials.create(wallet.key);
    }

    public static void main(String[] args) throws IOException, ParseException {
        Options options = new Options();
        Option keyfile = new Option("k", "keyfile", true, "path to JSON key file");
        keyfile.setRequired(true);
        options.addOption(keyfile);
        options.addOption(new Option("u", "url", true, "url to Cartouche API"));

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);
        args = cmd.getArgs();

        Credentials wallet = loadCredentials(cmd.getOptionValue("keyfile"));
        String name = args[0];
        String owner = args[1];
        String url = cmd.getOptionValue("url");
        if(url == null) {
            url = "https://api-test.cartouche.co/v2/";
        }
        associate(wallet, name, owner, url);
    }
}
