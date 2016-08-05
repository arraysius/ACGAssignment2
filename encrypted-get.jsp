<%@ page import="com.sun.org.apache.xml.internal.security.utils.Base64" %>
<%@ page import="javax.crypto.Cipher" %>
<%@ page import="javax.crypto.SecretKey" %>
<%@ page import="javax.crypto.spec.IvParameterSpec" %>
<%@ page import="javax.crypto.spec.SecretKeySpec" %>
<%@ page import="java.io.File" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="java.nio.file.Path" %>
<%@ page import="java.nio.file.Paths" %>
<%@ page import="java.security.MessageDigest" %>
<%
	try {
		// Get client IP address
		String clientIP = request.getRemoteAddr();

		// Password to generate AES key
		// Entered in bytes for obfuscation
		byte[] passwordByte = {0x61, 0x63, 0x67, 0x53, 0x54, 0x32, 0x35, 0x30, 0x34};

		// Generate local key
		// MD5 produces 16 byte data for AES key generation
		// Hash password to get 128 bit / 16 byte data
		MessageDigest messageDigest = MessageDigest.getInstance("MD5");
		byte[] passwordDigest = messageDigest.digest(passwordByte);
		SecretKey localKey = new SecretKeySpec(passwordDigest, "AES");

		// Create cipher
		Cipher cipher;

		// Read encrypted AES session key
		Path sessionKeyLocation = Paths.get(File.separator + "home" + File.separator + "acg" + File.separator + "sessionKeys" + File.separator + clientIP + ".aes");
		byte[] encryptedSessionKey = Files.readAllBytes(sessionKeyLocation);

		// Decrypt to get IV and AES session key
		cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, localKey);
		byte[] iVAndSessionKey = cipher.doFinal(encryptedSessionKey);
		byte[] iV = new byte[16];
		System.arraycopy(iVAndSessionKey, 0, iV, 0, iV.length);
		byte[] sessionKeyBytes = new byte[iVAndSessionKey.length - iV.length];
		System.arraycopy(iVAndSessionKey, iV.length, sessionKeyBytes, 0, sessionKeyBytes.length);

		// Create IvParameterSpec
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iV);

		// Create session key
		SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

		// Page content
		String content = "<html>\n" +
				"<head>\n" +
				"<title>Encrypted GET</title>\n" +
				"</head>\n" +
				"<body>\n" +
				"<p>Welcome!</p>\n" +
				"</body>\n" +
				"</html>";

		// Encrypt content
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivParameterSpec);
		byte[] encryptedContentBytes = cipher.doFinal(content.getBytes());

		// Base64 encode encrypted content
		String encryptedContentBase64 = Base64.encode(encryptedContentBytes);
		out.print(encryptedContentBase64);
	} catch (Exception e) {
		out.print("<html>");
		out.print("<head>");
		out.print("<title>Encrypted GET</title>");
		out.print("</head>");
		out.print("<body>");
		out.print("<p>Error handling request</p>");
		out.print("</body>");
		out.print("</html>");
		e.printStackTrace();
	}
%>
