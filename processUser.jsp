<%@ page import="java.sql.*, java.util.*" %>
<%@ page import ="org.mindrot.jbcrypt.*" %>
<html>
<head>
<title>processUser</title>
</head>
<body>
<%
Class.forName("com.mysql.jdbc.Driver");
String connURL = "jdbc:mysql://localhost/test?user=root&password=password";
Connection conn = DriverManager.getConnection(connURL);

String username = request.getParameter("username");
String password = request.getParameter("password");

PreparedStatement pstmt = conn.prepareStatement("SELECT username, hashedPassword FROM login WHERE username = ?");
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();

while (rs.next()) {
	String dbpassword = rs.getString("hashedPassword");
	if (BCrypt.checkpw(password, dbpassword)) {
    out.println("Welcome + " + username + "!<br>Your IP address is " + request.getRemoteAddr());
	} else {
		out.println("Login Failed");
	}
}
%>
</body>
</html>
