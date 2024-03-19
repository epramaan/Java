<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>

<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>OTV Success</title>
</head>
<body>
    <h3>Message: <span style="color: red;"><%= request.getAttribute("otvResp") %></span></h3>
    
	<form method="get" action="Logout">
		<input type="submit" value="Logout ">
	</form>
</body>
</html>