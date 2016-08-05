<html>
<head>
<title>Welcome</title>
</head>
<body>
<%
String name = test_input(request.getParameter("name"));
String email = test_input(request.getParameter("email"));

	out.println("Welcome " + name + "<br />");
	out.println("Your email address is: " + email);
%>
<%!
	public static String test_input(String data) {
	data = data.trim();
	data = data.replaceAll("\\\\", "");
	data = StringEscapeUtils.escapeHtml4(data);
	  return data;
}
%>
</body>
</html>
