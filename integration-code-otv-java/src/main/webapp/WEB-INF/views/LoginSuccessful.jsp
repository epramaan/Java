<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.Map"%>
<%@ page import="java.util.Map.Entry"%>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>JWT Token Details</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f7fa;
            margin: 0;
            padding: 0;
            align-items: center;
            height: 100vh;
        }

        .container {
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            padding: 20px;
            width: 100%;
            max-width: 800px;
            margin: auto;
        }

        h2 {
            text-align: center;
            color: #4caf50;
            margin-bottom: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
            word-break: break-word;
        }

        th {
            background-color: #4caf50;
            color: white;
        }

        tr:nth-child(even) {
            background-color: #f9f9f9;
        }

        tr:hover {
            background-color: #f1f1f1;
        }

        .no-data {
            text-align: center;
            font-style: italic;
            color: #888;
        }

        .logout-btn {
            display: block;
            margin-top: 20px;
            padding: 10px 20px;
            background-color: #f44336;
            color: white;
            border: none;
            border-radius: 5px;
            text-align: center;
            cursor: pointer;
        }

        .logout-btn:hover {
            background-color: #d32f2f;
        }
    </style>
</head>
<body>
    <div style="display:flex; justify-content:right; margin-right:2rem;">
        <!-- Logout button -->
        <%
        // Retrieve session attributes directly
        String sessionId = (String) session.getAttribute("sessionId");
        String sub = (String) session.getAttribute("sub");
        %>
        <form action="<%= request.getContextPath() %>/Epramaan/CreateRequestForLogoutOnEpramaan" method="POST">
            <input type="hidden" name="sessionId" value="<%= sessionId %>" />
            <input type="hidden" name="sub" value="<%= sub %>" />
            <button type="submit" class="logout-btn">Logout</button>
        </form>
    </div>
    <div class="container">
        <h2>JWT Token Details</h2>
        <h3>${message}</h3><!-- OTV Response -->
        <table>
            <tr>
                <th>Key</th>
                <th>Value</th>
            </tr>
            <%
            // Retrieve the map from session
            Map<String, Object> jwtMap = (Map<String, Object>) session.getAttribute("jwtMap");
            if (jwtMap != null && !jwtMap.isEmpty()) {
                // Iterate through the map and display the keys and values
                for (Map.Entry<String, Object> entry : jwtMap.entrySet()) {
            %>
            <tr>
                <td><%= entry.getKey() %></td>
                <td><%= entry.getValue() %></td>
            </tr>
            <%
                }
            } else {
            %>
            <tr>
                <td colspan="2" class="no-data">No data available</td>
            </tr>
            <%
            }
            %>
        </table>
    </div>
</body>
</html>
