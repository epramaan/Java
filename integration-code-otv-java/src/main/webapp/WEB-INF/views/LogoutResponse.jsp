<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.google.gson.JsonObject" %>
<%@ page import="java.util.Map" %>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Logout Status</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f7fa;
            margin: 0;
            padding: 0;
            display: grid;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            padding: 20px;
            width: 100%;
            max-width: 600px;
        }
        h2 {
            text-align: center;
            color: #000000;
            margin-bottom: 20px;
        }
        .status {
            font-size: 18px;
            color: #333;
            text-align: center;
        }
        .success {
            color: green;
            font-size: 20px;
            text-align: center;
        }
        .failure {
            color: red;
            font-size: 20px;
            text-align: center;
        }
        .login-btn {
            padding: 10px 20px;
            background-color: #4caf50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-align: center;
        }
        .login-btn:hover {
            background-color: #45a049;
        }

        /* Center the login button in a flexbox container */
        .button-container {
            display: flex;
            justify-content: center;
            margin-top: 20px;
        }

        /* Added styling for JSON */
        .json-container {
            margin-top: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 8px;
            border: 1px solid #ddd;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Courier New', Courier, monospace;
            font-size: 14px;
            margin-bottom: 20px;
        }

        pre {
            margin: 0;
            padding: 10px;
            background-color: #f1f1f1;
            border-radius: 5px;
            white-space: pre-wrap;       /* Ensures long lines wrap */
            word-wrap: break-word;       /* Breaks long words */
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Logout Status</h2>

        <!-- Check logoutStatus value -->
        <%
            String logoutStatus = (String) request.getAttribute("logoutStatus");
            JsonObject jsonObject = (JsonObject) request.getAttribute("jsonObject");

            if ("true".equalsIgnoreCase(logoutStatus)) {
        %>
            <!-- Logout successful message -->
            <div class="success">
                <p>Logout Successful</p>
            </div>
        <%
            } else {
        %>
            <!-- Logout failure message -->
            <div class="failure">
                <p>Logout Failed</p>
            </div>
        <%
            }
        %>

        <!-- Center the Login Button -->
        <div class="button-container">
            <form action="<%= request.getContextPath() %>/" method="GET">
                <button type="submit" class="login-btn">Login</button>
            </form>
        </div>

        <!-- Display the full JSON object inside a scrollable container -->
        <div class="json-container">
            <h3>Response JSON:</h3>
            <pre><%= jsonObject.toString() %></pre>
        </div>
    </div>
</body>
</html>
