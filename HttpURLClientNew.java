// http client

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.*;

public class HttpURLClientNew {

	private String serverAddress;
	private final String USER_AGENT = "Mozilla/5.0";
	private IvParameterSpec ivParameterSpec;
	private SecretKey aesSessionKey;

	public static void main(String[] args) throws Exception {
		// Check arguments
		if (args.length != 1) {
			System.out.println("Usage: java HttpURLClientNew <IP_ADDR>");
			return;
		}

		HttpURLClientNew http = new HttpURLClientNew();
		http.serverAddress = args[0];

		http.negotiateKey();

		System.out.println("Testing 1 - Send Http GET request");
		http.sendGet();

		System.out.println("\nTesting 2 - Send Http POST request");
		http.sendPost();
	}

	private byte[] receiveByteData(DataInputStream dataInputStream) throws IOException {
		byte[] data = new byte[0];
		int length = dataInputStream.readInt();
		if (length > 0) {
			data = new byte[length];
			dataInputStream.readFully(data);
		} else {
			System.out.println("Unable to read data from server");
			System.exit(1);
		}
		return data;
	}

	private X509Certificate validateCertificate(byte[] certAndSig, PublicKey publicKey) {
		try {
			// Split certificate and signature
			byte[] signature = new byte[256];
			System.arraycopy(certAndSig, certAndSig.length - 256, signature, 0, signature.length);
			byte[] certificateBytes = new byte[certAndSig.length - signature.length];
			System.arraycopy(certAndSig, 0, certificateBytes, 0, certificateBytes.length);

			// Create certificate
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));

			// Check validity
			certificate.checkValidity();

			// Check digital signature
			Signature dsa = Signature.getInstance("SHA256withRSA");
			dsa.initVerify(publicKey);
			boolean validSignature = dsa.verify(signature);
			if (!validSignature) {
				System.out.println("Invalid signature from received certificate");
				System.exit(0);
			}

			return certificate;
		} catch (CertificateExpiredException e) {
			System.out.println("Certificate expired");
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			System.out.println("Certificate not yet valid");
			e.printStackTrace();
		} catch (CertificateException e) {
			System.out.println("Unable to create certificate from received bytes");
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.exit(0);
		return null;
	}

	// Negotiate key with client
	private void negotiateKey() {
		try {
			// Read CA cert from cert file
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			byte[] file = Files.readAllBytes(Paths.get("ca.cert"));
			X509Certificate caCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(file));

			// Connect to CA server
			int serverCAPort = 8080;
			System.out.println("Connecting to CA at " + serverAddress + ":" + serverCAPort + "...");
			Socket client = new Socket(serverAddress, serverCAPort);
			System.out.println("Connected to CA at " + client.getRemoteSocketAddress());

			// Data streams to send and receive data
			DataInputStream dataInputStream = new DataInputStream(client.getInputStream());
			DataOutputStream dataOutputStream = new DataOutputStream(client.getOutputStream());

			// Send client hello
			System.out.println("Sending client HELLO");
			dataOutputStream.writeUTF("HELLO");
			dataOutputStream.flush();

			// Receive signed web server cert from CA
			System.out.println("Receiving web server certificate");
			byte[] webServerCertandSig = receiveByteData(dataInputStream);

			// Send response
			System.out.println("Sending response");
			dataOutputStream.writeUTF("OK");
			dataOutputStream.flush();

			// Validate received cert
			System.out.println("Validating web server certificate");
			X509Certificate webServerCertificate = validateCertificate(webServerCertandSig, caCertificate.getPublicKey());
			System.out.println("Certificate valid");

			// Get web server public key
			System.out.println("Reading public key from web server certificate");
			PublicKey webServerPublicKey = webServerCertificate.getPublicKey();

			// Generate 128 bit / 16 bytes IV
			byte[] iV = new byte[16];
			System.out.println("Generating " + (iV.length * 8) + " bit IV");
			SecureRandom secureRandom = new SecureRandom();
			secureRandom.nextBytes(iV);

			// Cast IV to IvParameterSpec
			ivParameterSpec = new IvParameterSpec(iV);

			// Generate AES session key
			System.out.println("Generating AES session key");
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			aesSessionKey = keyGenerator.generateKey();

			// Append AES session key bytes to IV
			byte[] aesSessionKeyBytes = aesSessionKey.getEncoded();
			byte[] iVAndAES = new byte[iV.length + aesSessionKeyBytes.length];
			System.arraycopy(iV, 0, iVAndAES, 0, iV.length);
			System.arraycopy(aesSessionKeyBytes, 0, iVAndAES, iV.length, aesSessionKeyBytes.length);

			// Encrypt IV and AES session key with web server public key
			System.out.println("Encrypting AES session key with web server public key");
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, webServerPublicKey);
			byte[] encryptedIvAndSessionKey = cipher.doFinal(iVAndAES);

			// Send encrypted IV and session key
			System.out.println("Sending IV and AES session key");
			dataOutputStream.writeInt(encryptedIvAndSessionKey.length);
			dataOutputStream.flush();
			dataOutputStream.write(encryptedIvAndSessionKey);
			dataOutputStream.flush();

			// Get response from server
			System.out.println("Waiting for response from server");
			if (!dataInputStream.readUTF().equals("OK")) {
				System.out.println("No response from client\nTerminating");
				System.exit(0);
			}
			System.out.println("Server OK");

			// Get Server END to end connection
			if (dataInputStream.readUTF().equals("END")) {
				System.out.println("Received Server END\nClosing connection");

				// Close socket
				client.close();
			} else {
				System.out.println("Unknown data received. Expected Server END");
				client.close();
				System.exit(0);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	// HTTP GET request
	private void sendGet() throws Exception {
		String url = "http://" + serverAddress + "/encrypted-get.jsp";

		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("GET");

		//add request header
		con.setRequestProperty("User-Agent", USER_AGENT);

		int responseCode = con.getResponseCode();
		System.out.println("\nSending 'GET' request to URL : " + url);
		System.out.println("Response Code : " + responseCode);

		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		// Response string
		System.out.println("Received response:");
		String responseString = response.toString();

		// Print response
		System.out.println(responseString);

		// Decrypt response with session key
		System.out.println("Decrypting response with AES session key");
		byte[] encryptedContentBytes = Base64.decode(responseString);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, aesSessionKey, ivParameterSpec);
		byte[] decryptedContentBytes = cipher.doFinal(encryptedContentBytes);

		// Print content
		String content = new String(decryptedContentBytes, "UTF-8");
		System.out.println(content);

		// Write to file then open content in browser
		File htmlFile = new File("get.html");
		FileOutputStream fileOutputStream = new FileOutputStream(htmlFile);
		fileOutputStream.write(decryptedContentBytes);
		Desktop.getDesktop().browse(htmlFile.toURI());
	}

	// HTTP POST request
	private void sendPost() throws Exception {
		String url = "http://" + serverAddress + "/encrypted-post.jsp";
		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		//add request header
		con.setRequestMethod("POST");
		con.setRequestProperty("User-Agent", USER_AGENT);
		con.setRequestProperty("Accept-Language", "en-US,en;q=0.5");

		// Encrypt parameters
		String name = JOptionPane.showInputDialog(null,
				"Enter your name",
				"Name",
				JOptionPane.INFORMATION_MESSAGE);
		String email = JOptionPane.showInputDialog(null,
				"Enter your Email",
				"Email",
				JOptionPane.INFORMATION_MESSAGE);
		String parameters = "name=" + name + "&email=" + email;
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, aesSessionKey, ivParameterSpec);
		byte[] encryptedParameters = cipher.doFinal(parameters.getBytes());
		String encryptedParametersBase64 = Base64.encode(encryptedParameters);

		// Create post parameters
		String urlParameters = "data=" + URLEncoder.encode(encryptedParametersBase64, "UTF-8");

		// Send post request
		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(urlParameters);
		wr.flush();
		wr.close();

		int responseCode = con.getResponseCode();
		System.out.println("\nSending 'POST' request to URL : " + url);
		System.out.println("Post parameters : " + urlParameters);
		System.out.println("Response Code : " + responseCode);

		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		// Response string
		System.out.println("Received response:");
		String responseString = response.toString();

		// Print response
		System.out.println(responseString);

		// Decrypt response with session key
		System.out.println("Decrypting response with AES session key");
		byte[] encryptedContentBytes = Base64.decode(responseString);
		cipher.init(Cipher.DECRYPT_MODE, aesSessionKey, ivParameterSpec);
		byte[] decryptedContentBytes = cipher.doFinal(encryptedContentBytes);

		// Print content
		String content = new String(decryptedContentBytes, "UTF-8");
		System.out.println(content);

		// Write to file then open content in browser
		File htmlFile = new File("post.html");
		FileOutputStream fileOutputStream = new FileOutputStream(htmlFile);
		fileOutputStream.write(decryptedContentBytes);
		Desktop.getDesktop().browse(htmlFile.toURI());
	}

}
