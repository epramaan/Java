<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>One Time PushBack</title>
<style>
    /*set border to the form*/
      
    form {
        border: 3px solid #f1f1f1;
        width: 50%;
    }
    /*assign full width inputs*/
      
    input[type=text],
    input[type=password] {
        width: 100%;
        padding: 12px 20px;
        margin: 8px 0;
        display: inline-block;
        border: 1px solid #ccc;
        box-sizing: border-box;
    }
    /*set a style for the buttons*/
      
    button {
        background-color: #4CAF50;
        color: white;
        padding: 14px 20px;
        margin: 8px 0;
        border: none;
        cursor: pointer;
        width: 100%;
    }
    /* set a hover effect for the button*/
      
    button:hover {
        opacity: 0.8;
    }

    /*set padding to the container*/
      
    .container {
        padding: 16px;
    }

    }
</style>
</head>
<body>
	<h1>Push Back</h1>
	
    <form action="oneTimePushback" method="get">
        <div class="container">
        <%
    String msgForUser = (String) request.getAttribute("msgForUser");
    if (msgForUser != null) {
%>
        <h2><%= msgForUser %></h2>
<%
    }
%>
        
            <label><b>Username</b></label>
            <input type="text" placeholder="Enter Username" name="username" required>
            <input type="password" placeholder="Enter Password" name="password" required>
  
             <!--  <label><b>Password</b></label>
           <input type="password" placeholder="Enter Password" name="userpass" value="U001pwd" required>-->
           <h1><%= request.getAttribute("ePramaanId") %></h1>
  			<input type="hidden" name="SSO_Id" value="<%= request.getAttribute("ePramaanId") %>">
            <button type="submit">Push Back</button>
        </div>
    </form>
  
</body>
</html>